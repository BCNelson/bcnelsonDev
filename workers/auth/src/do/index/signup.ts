/**
 * Signup with email verification before the account exists (design §6.1).
 *
 * start    → reserve the handle as `pending` (SIGNUP_TTL), store a hashed code
 *            (CODE_TTL, CODE_MAX_ATTEMPTS) and email it. An address that already
 *            has an account gets a notice instead and a signup that can never
 *            verify; the caller sees the same `{ signupId }` either way.
 * verify   → check the code, mark the signup verified.
 * complete → create the User DO, then flip the handle to `active` and insert
 *            the email in one transaction. Any conflict fails generically.
 *
 * The signupId is a bearer secret for the pending signup. Starting again with
 * the same username + email (resend) issues a fresh code *and* a fresh
 * signupId, so whoever restarts a signup can't complete one someone else
 * verified.
 */

import { config } from '../../config';
import { sha256Base64url, timingSafeEqual } from '../../crypto/hash';
import { newId, randomCode, randomToken } from '../../crypto/ids';
import { createMailer } from '../../email/mailer';
import { alreadyRegistered, signupCode } from '../../email/templates';
import { validateEmail, validateUsername } from '../../identifiers';
import { actionLimit } from '../../ratelimit';
import { isLive, type IndexContext } from './context';
import { upsertDirectoryEntry } from './directory';
import { checkSends, recordSends, type SendLimit } from './send-limits';

export type StartSignupResult =
  | { ok: true; signupId: string }
  | {
    ok: false;
    reason: 'invalid_username' | 'invalid_email' | 'username_taken' | 'rate_limited';
    retryAfterMs?: number;
  };

export type VerifySignupResult =
  | { ok: true }
  | { ok: false; reason: 'invalid' | 'expired' | 'too_many_attempts' };

/** A verified, unexpired signup; what a credential needs before the account exists. */
export interface VerifiedSignup {
  signupId: string;
  userId: string;
  username: string;
  email: string;
}

export interface CompleteSignupOptions {
  /**
   * Social signup (do/index/identities.ts): also register this provider
   * identity for the new account, in the same transaction as the handle and
   * email. A taken identity is a `conflict`.
   */
  identity?: { provider: string; subject: string };
}

export type CompleteSignupResult =
  | { ok: true; userId: string; username: string; email: string }
  | { ok: false; reason: 'invalid' | 'not_verified' | 'conflict' };

type SignupRow = {
  signup_id: string;
  username: string;
  username_norm: string;
  email: string;
  email_norm: string;
  code_hash: string;
  attempts: number;
  verified_at: number | null;
  expires_at: number;
  user_id: string | null;
  code_expires_at: number | null;
};

const CODE_PATTERN = new RegExp(`^[0-9]{${config.CODE_LENGTH}}$`);

/** Start (or restart, for a resend) a signup and email the code or the notice. */
export async function startSignup(
  ctx: IndexContext,
  input: { username: string; email: string; ip?: string },
): Promise<StartSignupResult> {
  const username = validateUsername(input.username);
  if (!username.ok) return { ok: false, reason: 'invalid_username' };
  const email = validateEmail(input.email);
  if (!email.ok) return { ok: false, reason: 'invalid_email' };

  const { sql, now } = ctx;
  const code = randomCode(config.CODE_LENGTH);
  // Registered addresses get a hash of a random token: no code can ever match it.
  const [codeHash, deadHash] = await Promise.all([sha256Base64url(code), sha256Base64url(randomToken())]);
  const [perEmail, emailWindow] = actionLimit('verification_send');
  const limits: SendLimit[] = [{ key: `email:${email.norm}`, max: perEmail, windowMs: emailWindow }];
  if (input.ip) {
    limits.push({ key: `ip:${input.ip}`, max: config.SIGNUP_SENDS_PER_IP[0], windowMs: config.SIGNUP_SENDS_PER_IP[1] });
  }

  // No awaits from here until the writes are done: read-decide-write is atomic.
  const outcome = ctx.storage.transactionSync(() => {
    const handle = sql.exec<{ status: string; expires_at: number | null }>(
      'SELECT status, expires_at FROM handles WHERE username_norm = ?', username.norm,
    ).toArray()[0];
    const pending = sql.exec<SignupRow>(
      'SELECT * FROM pending_signups WHERE username_norm = ? AND expires_at > ?', username.norm, now,
    ).toArray()[0];
    const resend = pending !== undefined && pending.email_norm === email.norm;
    if (handle && isLive(handle.status, handle.expires_at, now) && !(handle.status === 'pending' && resend)) {
      return { kind: 'taken' as const };
    }

    const limit = checkSends(sql, limits, now);
    if (!limit.allowed) return { kind: 'limited' as const, retryAfterMs: limit.retryAfterMs };
    const sendsExpire = recordSends(sql, limits, now);

    const registered = sql.exec<{ status: string; expires_at: number | null }>(
      'SELECT status, expires_at FROM emails WHERE email_norm = ?', email.norm,
    ).toArray().some((r) => isLive(r.status, r.expires_at, now));
    const hash = registered ? deadHash : codeHash;
    const signupId = newId('sig');
    const codeExpiresAt = now + config.CODE_TTL;

    if (resend) {
      // The reservation keeps its original expiry so restarts can't hold a name forever.
      sql.exec(
        `UPDATE pending_signups SET signup_id = ?, code_hash = ?, attempts = 0, verified_at = NULL,
           code_expires_at = ? WHERE signup_id = ?`,
        signupId, hash, codeExpiresAt, pending.signup_id,
      );
      return { kind: 'ok' as const, signupId, registered, sweepAt: Math.min(pending.expires_at, sendsExpire) };
    }

    const expiresAt = now + config.SIGNUP_TTL;
    sql.exec('DELETE FROM pending_signups WHERE username_norm = ?', username.norm);
    sql.exec(
      `INSERT OR REPLACE INTO handles (username_norm, user_id, status, expires_at)
       VALUES (?, NULL, 'pending', ?)`,
      username.norm, expiresAt,
    );
    sql.exec(
      `INSERT INTO pending_signups (signup_id, username, username_norm, email, email_norm,
         code_hash, attempts, verified_at, expires_at, user_id, code_expires_at)
       VALUES (?, ?, ?, ?, ?, ?, 0, NULL, ?, ?, ?)`,
      signupId, username.display, username.norm, email.display, email.norm,
      hash, expiresAt, newId('usr'), codeExpiresAt,
    );
    return { kind: 'ok' as const, signupId, registered, sweepAt: Math.min(expiresAt, sendsExpire) };
  });

  if (outcome.kind === 'taken') return { ok: false, reason: 'username_taken' };
  if (outcome.kind === 'limited') return { ok: false, reason: 'rate_limited', retryAfterMs: outcome.retryAfterMs };

  await ctx.scheduleSweep(outcome.sweepAt);
  const content = outcome.registered
    ? alreadyRegistered(`${ctx.env.ISSUER}/login`, `${ctx.env.ISSUER}/password/forgot`)
    : signupCode(code, Math.round(config.CODE_TTL / 60_000));
  try {
    await createMailer(ctx.env).send({ to: email.display, ...content });
  } catch (err) {
    // Same response either way; the user can ask for a resend.
    console.error('signup email failed', err);
  }
  return { ok: true, signupId: outcome.signupId };
}

/** Check a code. Every wrong guess counts; CODE_MAX_ATTEMPTS ends the code. */
export async function verifySignup(
  ctx: IndexContext,
  signupId: string,
  code: string,
): Promise<VerifySignupResult> {
  const presented = await sha256Base64url(code);
  const { sql, now } = ctx;
  const row = signupRow(sql, signupId);
  if (!row) return { ok: false, reason: 'invalid' };
  if (row.expires_at <= now) return { ok: false, reason: 'expired' };
  if (row.verified_at !== null) return { ok: true };
  if (row.attempts >= config.CODE_MAX_ATTEMPTS) return { ok: false, reason: 'too_many_attempts' };
  if ((row.code_expires_at ?? row.expires_at) <= now) return { ok: false, reason: 'expired' };
  // Compare even when the format is wrong so timing doesn't depend on it.
  const match = timingSafeEqual(presented, row.code_hash) && CODE_PATTERN.test(code);
  if (match) {
    sql.exec('UPDATE pending_signups SET verified_at = ? WHERE signup_id = ?', now, signupId);
    return { ok: true };
  }
  sql.exec('UPDATE pending_signups SET attempts = attempts + 1 WHERE signup_id = ?', signupId);
  return row.attempts + 1 >= config.CODE_MAX_ATTEMPTS
    ? { ok: false, reason: 'too_many_attempts' }
    : { ok: false, reason: 'invalid' };
}

/** The signup if it is verified and unexpired, else null. Credential modules use it before completion. */
export function getVerifiedSignup(ctx: IndexContext, signupId: string): VerifiedSignup | null {
  const row = signupRow(ctx.sql, signupId);
  if (!row || row.verified_at === null || row.expires_at <= ctx.now || !row.user_id) return null;
  return { signupId: row.signup_id, userId: row.user_id, username: row.username, email: row.email };
}

/**
 * Create the account for a verified signup: initialise the User DO, then
 * activate the handle and claim the email in one transaction. A User DO
 * left behind by a lost race is unreachable (nothing in the index points
 * at it) and harmless.
 */
export async function completeSignup(
  ctx: IndexContext,
  signupId: string,
  options: CompleteSignupOptions = {},
): Promise<CompleteSignupResult> {
  const { sql, now } = ctx;
  const { identity } = options;
  const row = signupRow(sql, signupId);
  if (!row || row.expires_at <= now || !row.user_id) return { ok: false, reason: 'invalid' };
  if (row.verified_at === null) return { ok: false, reason: 'not_verified' };
  if (!canClaim(sql, row, now) || (identity && identityTaken(sql, identity))) return { ok: false, reason: 'conflict' };

  const userId = row.user_id;
  const user = ctx.env.USER.get(ctx.env.USER.idFromName(userId));
  try {
    await user.initProfile({ userId, username: row.username, email: row.email });
  } catch (err) {
    // A retry after a crash between the two steps: the profile is this signup's own.
    if (!/already exists/i.test(String((err as Error)?.message ?? err))) throw err;
  }

  const claimed = ctx.storage.transactionSync(() => {
    const current = signupRow(sql, signupId);
    if (!current || !canClaim(sql, current, Date.now())) return false;
    if (identity && identityTaken(sql, identity)) return false;
    sql.exec(
      "UPDATE handles SET status = 'active', user_id = ?, expires_at = NULL WHERE username_norm = ?",
      userId, row.username_norm,
    );
    sql.exec(
      `INSERT OR REPLACE INTO emails (email_norm, user_id, status, expires_at)
       VALUES (?, ?, 'active', NULL)`,
      row.email_norm, userId,
    );
    if (identity) {
      sql.exec(
        'INSERT INTO identities (provider, provider_subject, user_id) VALUES (?, ?, ?)',
        identity.provider, identity.subject, userId,
      );
    }
    sql.exec('DELETE FROM pending_signups WHERE signup_id = ?', signupId);
    // Admin directory row; later changes are pushed by the User DO (user/admin.ts syncDirectory).
    const at = Date.now();
    upsertDirectoryEntry(sql, {
      userId, username: row.username, primaryEmail: row.email_norm, roles: [], createdAt: at, disabledAt: null,
    }, at);
    return true;
  });
  if (!claimed) return { ok: false, reason: 'conflict' };
  return { ok: true, userId, username: row.username, email: row.email_norm };
}

/** True when this provider identity already belongs to an account. */
function identityTaken(sql: SqlStorage, identity: { provider: string; subject: string }): boolean {
  return sql.exec(
    'SELECT 1 FROM identities WHERE provider = ? AND provider_subject = ?', identity.provider, identity.subject,
  ).toArray().length > 0;
}

function signupRow(sql: SqlStorage, signupId: string): SignupRow | null {
  return sql.exec<SignupRow>('SELECT * FROM pending_signups WHERE signup_id = ?', signupId).toArray()[0] ?? null;
}

/** The handle is still this signup's pending reservation and the email is unclaimed. */
function canClaim(sql: SqlStorage, row: SignupRow, now: number): boolean {
  const handle = sql.exec<{ status: string; user_id: string | null; expires_at: number | null }>(
    'SELECT status, user_id, expires_at FROM handles WHERE username_norm = ?', row.username_norm,
  ).toArray()[0];
  if (!handle || handle.status !== 'pending' || handle.user_id !== null) return false;
  if ((handle.expires_at ?? 0) <= now) return false;
  const email = sql.exec<{ status: string; expires_at: number | null }>(
    'SELECT status, expires_at FROM emails WHERE email_norm = ?', row.email_norm,
  ).toArray()[0];
  return !email || !isLive(email.status, email.expires_at, now);
}
