/**
 * Password reset (design §6.6).
 *
 * request → if `email` is a verified address on this account and the
 *           `password_reset` action limit allows, store SHA-256 of a fresh
 *           secret in `tokens` (purpose 'password_reset', RESET_TTL) and email
 *           the link to that address only.
 * reset   → check the secret (known, unused, unexpired, address still on the
 *           account), set the new hash (creating the password credential for
 *           passkey-only users), use up every outstanding reset token, revoke
 *           all sessions, clear password backoff, alert every verified address.
 *
 * Token format: `pr1.<userId>.<secret>`, so the Worker can route straight to
 * the User DO. Only the secret's hash is stored; userId is just routing.
 */

import { config } from '../../config';
import { sha256Base64url, timingSafeEqual } from '../../crypto/hash';
import { randomToken } from '../../crypto/ids';
import { createMailer } from '../../email/mailer';
import { passwordChanged, passwordReset } from '../../email/templates';
import { normalizeEmail } from '../../identifiers';
import { checkActionLimit } from '../../ratelimit';
import { SECRET_PATTERN, USER_ID_PATTERN } from '../../session/refresh-token';
import { type UserContext, readProfile } from './context';
import { readDisabledAt } from './admin';
import { setPassword } from './password';

export const RESET_PURPOSE = 'password_reset';
const RESET_PREFIX = 'pr1';
const RESET_ACTION = 'password_reset';

export interface ResetTokenParts {
  userId: string;
  secret: string;
}

export function formatResetToken({ userId, secret }: ResetTokenParts): string {
  return `${RESET_PREFIX}.${userId}.${secret}`;
}

/** The parts of a well-formed v1 reset token, else null. */
export function parseResetToken(value: string | null | undefined): ResetTokenParts | null {
  if (!value || value.length > 128) return null;
  const parts = value.split('.');
  if (parts.length !== 3) return null;
  const [prefix, userId, secret] = parts as [string, string, string];
  if (prefix !== RESET_PREFIX || !USER_ID_PATTERN.test(userId) || !SECRET_PATTERN.test(secret)) return null;
  return { userId, secret };
}

export type RequestResetResult =
  | { sent: true }
  | { sent: false; reason: 'unknown_email' | 'rate_limited' | 'send_failed' };

export type ResetPasswordResult =
  | { ok: true }
  | { ok: false; reason: 'invalid' | 'expired' | 'used' };

type TokenRow = {
  token_hash: string;
  email: string | null;
  expires_at: number;
  used_at: number | null;
};

/** Issue and email a reset link if `email` is verified here and the limit allows. Never throws on mail errors. */
export async function requestPasswordReset(ctx: UserContext, email: string): Promise<RequestResetResult> {
  const { sql, now } = ctx;
  const norm = normalizeEmail(email);
  const secret = randomToken();
  const secretHash = await sha256Base64url(secret);

  // No awaits until the writes are done: check-and-record is atomic.
  const outcome = ctx.storage.transactionSync(() => {
    const profile = readProfile(sql);
    if (!profile || !hasEmail(sql, norm)) return { kind: 'unknown' as const };
    // A disabled account can't sign in, so a reset link is useless; don't mail one.
    if (readDisabledAt(sql) !== null) return { kind: 'unknown' as const };
    const times = sql.exec<{ at: number }>(
      'SELECT at FROM action_limits WHERE action = ?', RESET_ACTION,
    ).toArray().map((r) => r.at);
    if (!checkActionLimit(RESET_ACTION, times, now).allowed) {
      ctx.audit('password_reset.limited', { email: norm });
      return { kind: 'limited' as const };
    }
    sql.exec('INSERT INTO action_limits (action, at) VALUES (?, ?)', RESET_ACTION, now);
    sql.exec(
      'INSERT INTO tokens (token_hash, purpose, email, expires_at, used_at) VALUES (?, ?, ?, ?, NULL)',
      secretHash, RESET_PURPOSE, norm, now + config.RESET_TTL,
    );
    ctx.audit('password_reset.requested', { email: norm });
    return { kind: 'ok' as const, userId: profile.user_id };
  });

  if (outcome.kind === 'unknown') return { sent: false, reason: 'unknown_email' };
  if (outcome.kind === 'limited') return { sent: false, reason: 'rate_limited' };

  const token = formatResetToken({ userId: outcome.userId, secret });
  const url = `${ctx.env.ISSUER}/password/reset?token=${encodeURIComponent(token)}`;
  try {
    await createMailer(ctx.env).send({ to: norm, ...passwordReset(url, Math.round(config.RESET_TTL / 60_000)) });
    return { sent: true };
  } catch (err) {
    console.error('password reset email failed', err);
    return { sent: false, reason: 'send_failed' };
  }
}

/** Whether `secret` is a usable reset token right now. No side effects. */
export async function checkResetToken(ctx: UserContext, secret: string): Promise<ResetPasswordResult> {
  const presented = await sha256Base64url(secret);
  return judgeToken(ctx, presented);
}

/**
 * Consume a reset token and set the password (`hash` already from
 * hashPassword). Everything from the token check to the session revocation
 * runs without an await, so two concurrent resets can't both use one token.
 */
export async function resetPassword(ctx: UserContext, secret: string, hash: string): Promise<ResetPasswordResult> {
  const presented = await sha256Base64url(secret);
  const { sql, now } = ctx;
  const verdict = judgeToken(ctx, presented);
  if (!verdict.ok) {
    ctx.audit('password_reset.rejected', { reason: verdict.reason });
    return verdict;
  }

  const revoked = ctx.storage.transactionSync(() => {
    sql.exec('UPDATE tokens SET used_at = ? WHERE token_hash = ?', now, presented);
    // Any other outstanding links stop working too.
    sql.exec(
      'UPDATE tokens SET used_at = ? WHERE purpose = ? AND used_at IS NULL', now, RESET_PURPOSE,
    );
    return sql.exec('UPDATE sessions SET revoked_at = ? WHERE revoked_at IS NULL', now).rowsWritten;
  });
  // Sets/creates the credential and clears password backoff (own transaction, still no await).
  setPassword(ctx, hash);
  ctx.audit('password_reset.completed', { sessionsRevoked: revoked });

  const recipients = sql.exec<{ email: string }>('SELECT email FROM emails ORDER BY email').toArray();
  const mailer = createMailer(ctx.env);
  const content = passwordChanged();
  await Promise.all(recipients.map(async ({ email }) => {
    try {
      await mailer.send({ to: email, ...content });
    } catch (err) {
      console.error('password changed alert failed', err);
    }
  }));
  return { ok: true };
}

function judgeToken(ctx: UserContext, presented: string): ResetPasswordResult {
  const { sql, now } = ctx;
  const row = sql.exec<TokenRow>(
    'SELECT token_hash, email, expires_at, used_at FROM tokens WHERE token_hash = ? AND purpose = ?',
    presented, RESET_PURPOSE,
  ).toArray()[0];
  // Constant-time compare of the stored hash, so the check doesn't hinge on the index lookup alone.
  if (!row || !timingSafeEqual(presented, row.token_hash)) return { ok: false, reason: 'invalid' };
  if (row.used_at !== null) return { ok: false, reason: 'used' };
  if (row.expires_at <= now) return { ok: false, reason: 'expired' };
  // The address the link went to must still be on the account.
  if (!row.email || !hasEmail(sql, row.email) || !readProfile(sql)) return { ok: false, reason: 'invalid' };
  return { ok: true };
}

function hasEmail(sql: SqlStorage, norm: string): boolean {
  return sql.exec('SELECT 1 FROM emails WHERE email = ?', norm).toArray().length > 0;
}
