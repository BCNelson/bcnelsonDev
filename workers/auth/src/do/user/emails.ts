/**
 * Email addresses on an account (design §5, §6.5). `emails` holds verified
 * addresses only (normalized); `pending_emails` holds codes for addresses
 * being added.
 *
 * add     → per-user limits (ACTION_LIMITS.email_add for new addresses,
 *           verification_send for every code), MAX_PENDING_EMAILS, then a
 *           hashed code (CODE_TTL, CODE_MAX_ATTEMPTS) mailed to the address.
 *           Whether the address belongs to someone else is never checked here.
 * verify  → code, then MAX_EMAILS_PER_ACCOUNT (verified only), then
 *           UserIndex.claimEmail; only then is it inserted. Alerts: primary +
 *           the new address.
 * primary → alerts every verified address.
 * remove  → never the last one; removing the primary needs a new primary.
 *           The index row becomes `held` for EMAIL_HOLD. Alerts: primary +
 *           the removed address.
 *
 * Reauth (design §6.5) is enforced by the routes.
 */

import { config } from '../../config';
import { sha256Base64url, timingSafeEqual } from '../../crypto/hash';
import { randomCode } from '../../crypto/ids';
import { createMailer } from '../../email/mailer';
import { addEmailCode, emailAdded, emailRemoved, primaryChanged, type EmailContent } from '../../email/templates';
import { normalizeEmail, validateEmail } from '../../identifiers';
import { checkActionLimit, actionLimit, type LimitedAction } from '../../ratelimit';
import { syncDirectorySafe } from './admin';
import { type UserContext, readPrimaryEmail, readProfile } from './context';

export interface EmailInfo {
  email: string;
  verifiedAt: number;
  primary: boolean;
}

export interface PendingEmailInfo {
  email: string;
  expiresAt: number;
}

export type StartAddEmailResult =
  | { ok: true; email: string; expiresAt: number }
  | {
    ok: false;
    reason: 'invalid_email' | 'already_added' | 'too_many_pending' | 'too_many_emails' | 'rate_limited';
    retryAfterMs?: number;
  };

export type VerifyAddEmailResult =
  | { ok: true; email: string }
  | { ok: false; reason: 'invalid' | 'expired' | 'too_many_attempts' | 'too_many_emails' | 'unavailable' };

export type SetPrimaryEmailResult =
  | { ok: true; changed: boolean }
  | { ok: false; reason: 'not_found' };

export type RemoveEmailResult =
  | { ok: true; primaryChanged: boolean }
  | { ok: false; reason: 'not_found' | 'last_email' | 'primary_required' | 'invalid_new_primary' };

type PendingRow = { email: string; code_hash: string; attempts: number; expires_at: number };

const CODE_PATTERN = new RegExp(`^[0-9]{${config.CODE_LENGTH}}$`);

// --- reads -----------------------------------------------------------------

/** Verified addresses, primary first. */
export function listEmails(sql: SqlStorage): EmailInfo[] {
  return sql.exec<{ email: string; verified_at: number; is_primary: number }>(
    'SELECT email, verified_at, is_primary FROM emails ORDER BY is_primary DESC, verified_at, email',
  ).toArray().map((r) => ({ email: r.email, verifiedAt: r.verified_at, primary: r.is_primary === 1 }));
}

/** Unexpired pending addresses. */
export function listPendingEmails(sql: SqlStorage, now: number): PendingEmailInfo[] {
  return sql.exec<{ email: string; expires_at: number }>(
    'SELECT email, expires_at FROM pending_emails WHERE expires_at > ? ORDER BY expires_at', now,
  ).toArray().map((r) => ({ email: r.email, expiresAt: r.expires_at }));
}

function hasEmail(sql: SqlStorage, norm: string): boolean {
  return sql.exec('SELECT 1 FROM emails WHERE email = ?', norm).toArray().length > 0;
}

function countEmails(sql: SqlStorage): number {
  return Number(sql.exec<{ n: number }>('SELECT COUNT(*) AS n FROM emails').one().n);
}

// --- add + verify ------------------------------------------------------------

export async function startAddEmail(ctx: UserContext, input: string): Promise<StartAddEmailResult> {
  const email = validateEmail(input);
  if (!email.ok) return { ok: false, reason: 'invalid_email' };
  const norm = email.norm;
  const code = randomCode(config.CODE_LENGTH);
  const codeHash = await sha256Base64url(code);
  const { sql, now } = ctx;
  const expiresAt = now + config.CODE_TTL;

  // No awaits until the writes are done: read-decide-write is atomic.
  const outcome = ctx.storage.transactionSync((): StartAddEmailResult => {
    sql.exec('DELETE FROM pending_emails WHERE expires_at <= ?', now);
    if (hasEmail(sql, norm)) return { ok: false, reason: 'already_added' };
    if (countEmails(sql) >= config.MAX_EMAILS_PER_ACCOUNT) return { ok: false, reason: 'too_many_emails' };
    const resend = sql.exec('SELECT 1 FROM pending_emails WHERE email = ?', norm).toArray().length > 0;
    if (!resend) {
      const pending = Number(sql.exec<{ n: number }>('SELECT COUNT(*) AS n FROM pending_emails').one().n);
      if (pending >= config.MAX_PENDING_EMAILS) return { ok: false, reason: 'too_many_pending' };
    }
    const actions: LimitedAction[] = resend ? ['verification_send'] : ['email_add', 'verification_send'];
    let retryAfterMs = 0;
    for (const action of actions) {
      const decision = checkActionLimit(action, actionTimes(sql, action, now), now);
      if (!decision.allowed) retryAfterMs = Math.max(retryAfterMs, decision.retryAfterMs);
    }
    if (retryAfterMs > 0) return { ok: false, reason: 'rate_limited', retryAfterMs };
    for (const action of actions) recordAction(sql, action, now);
    sql.exec(
      `INSERT OR REPLACE INTO pending_emails (email, code_hash, attempts, expires_at)
       VALUES (?, ?, 0, ?)`,
      norm, codeHash, expiresAt,
    );
    ctx.audit('email.add_started', { email: norm, resend });
    return { ok: true, email: norm, expiresAt };
  });
  if (!outcome.ok) return outcome;

  try {
    await createMailer(ctx.env).send({ to: norm, ...addEmailCode(code, Math.round(config.CODE_TTL / 60_000)) });
  } catch (err) {
    // Same answer either way; the user can ask for a new code.
    console.error('add-email code send failed', err);
  }
  return outcome;
}

export async function verifyAddEmail(ctx: UserContext, input: string, code: string): Promise<VerifyAddEmailResult> {
  const norm = normalizeEmail(input);
  const presented = await sha256Base64url(code);
  const { sql, now } = ctx;
  const row = sql.exec<PendingRow>('SELECT * FROM pending_emails WHERE email = ?', norm).toArray()[0];
  if (!row) return { ok: false, reason: 'invalid' };
  if (row.expires_at <= now) return { ok: false, reason: 'expired' };
  if (row.attempts >= config.CODE_MAX_ATTEMPTS) return { ok: false, reason: 'too_many_attempts' };
  const match = timingSafeEqual(presented, row.code_hash) && CODE_PATTERN.test(code);
  if (!match) {
    sql.exec('UPDATE pending_emails SET attempts = attempts + 1 WHERE email = ?', norm);
    ctx.audit('email.verify_failed', { email: norm });
    return row.attempts + 1 >= config.CODE_MAX_ATTEMPTS
      ? { ok: false, reason: 'too_many_attempts' }
      : { ok: false, reason: 'invalid' };
  }
  if (hasEmail(sql, norm)) {
    sql.exec('DELETE FROM pending_emails WHERE email = ?', norm);
    return { ok: true, email: norm };
  }
  if (countEmails(sql) >= config.MAX_EMAILS_PER_ACCOUNT) return { ok: false, reason: 'too_many_emails' };

  // The code is single use from here on, whatever the index says.
  sql.exec('DELETE FROM pending_emails WHERE email = ?', norm);
  const userId = requireUserId(ctx);
  const index = indexStub(ctx);
  const claim = await index.claimEmail(userId, norm);
  if (!claim.ok) {
    ctx.audit('email.claim_failed', { email: norm });
    return { ok: false, reason: 'unavailable' };
  }

  // Re-check the cap: a concurrent verification may have landed while we awaited.
  const added = ctx.storage.transactionSync(() => {
    if (hasEmail(sql, norm)) return true;
    if (countEmails(sql) >= config.MAX_EMAILS_PER_ACCOUNT) return false;
    sql.exec('INSERT INTO emails (email, verified_at, is_primary) VALUES (?, ?, 0)', norm, Date.now());
    ctx.audit('email.added', { email: norm });
    return true;
  });
  if (!added) {
    await index.releaseEmail(userId, norm);
    return { ok: false, reason: 'too_many_emails' };
  }
  await sendAlert(ctx, [readPrimaryEmail(sql), norm], emailAdded(norm), 'email_added');
  return { ok: true, email: norm };
}

// --- primary + remove --------------------------------------------------------

export async function setPrimaryEmail(ctx: UserContext, input: string): Promise<SetPrimaryEmailResult> {
  const norm = normalizeEmail(input);
  const { sql } = ctx;
  const outcome = ctx.storage.transactionSync((): SetPrimaryEmailResult => {
    if (!hasEmail(sql, norm)) return { ok: false, reason: 'not_found' };
    const previous = readPrimaryEmail(sql);
    if (previous === norm) return { ok: true, changed: false };
    sql.exec('UPDATE emails SET is_primary = CASE WHEN email = ? THEN 1 ELSE 0 END', norm);
    ctx.audit('email.primary_changed', { from: previous, to: norm });
    return { ok: true, changed: true };
  });
  if (outcome.ok && outcome.changed) {
    await syncDirectorySafe(ctx);
    await sendAlert(ctx, listEmails(sql).map((e) => e.email), primaryChanged(norm), 'primary_changed');
  }
  return outcome;
}

export async function removeEmail(ctx: UserContext, input: string, newPrimary?: string): Promise<RemoveEmailResult> {
  const norm = normalizeEmail(input);
  const nextNorm = newPrimary ? normalizeEmail(newPrimary) : undefined;
  const { sql } = ctx;
  const outcome = ctx.storage.transactionSync((): RemoveEmailResult => {
    if (!hasEmail(sql, norm)) return { ok: false, reason: 'not_found' };
    if (countEmails(sql) <= 1) return { ok: false, reason: 'last_email' };
    const wasPrimary = readPrimaryEmail(sql) === norm;
    if (wasPrimary) {
      if (!nextNorm) return { ok: false, reason: 'primary_required' };
      if (nextNorm === norm || !hasEmail(sql, nextNorm)) return { ok: false, reason: 'invalid_new_primary' };
    }
    sql.exec('DELETE FROM emails WHERE email = ?', norm);
    if (wasPrimary) sql.exec('UPDATE emails SET is_primary = 1 WHERE email = ?', nextNorm!);
    ctx.audit('email.removed', { email: norm, newPrimary: wasPrimary ? nextNorm : null });
    return { ok: true, primaryChanged: wasPrimary };
  });
  if (!outcome.ok) return outcome;

  try {
    await indexStub(ctx).holdEmail(requireUserId(ctx), norm);
  } catch (err) {
    // The account no longer lists it; a stale active row only maps logins by it to this account.
    console.error('email hold failed', err);
  }
  const primary = readPrimaryEmail(sql);
  if (outcome.primaryChanged) {
    await syncDirectorySafe(ctx);
    await sendAlert(ctx, listEmails(sql).map((e) => e.email), primaryChanged(primary!), 'primary_changed');
  }
  await sendAlert(ctx, [primary, norm], emailRemoved(norm), 'email_removed');
  return outcome;
}

// --- shared helpers ------------------------------------------------------------

/**
 * Send one alert to each distinct address (failures are logged, never thrown)
 * and audit `alert.<event>` with the recipients.
 */
export async function sendAlert(
  ctx: Pick<UserContext, 'env' | 'audit'>,
  recipients: readonly (string | null | undefined)[],
  content: EmailContent,
  event: string,
): Promise<void> {
  const to = [...new Set(recipients.filter((r): r is string => Boolean(r)))];
  if (to.length === 0) return;
  const mailer = createMailer(ctx.env);
  const results = await Promise.allSettled(to.map((address) => mailer.send({ to: address, ...content })));
  results.forEach((r) => {
    if (r.status === 'rejected') console.error(`alert ${event} failed`, r.reason);
  });
  ctx.audit(`alert.${event}`, { to });
}

function actionTimes(sql: SqlStorage, action: LimitedAction, now: number): number[] {
  const [, windowMs] = actionLimit(action);
  return sql.exec<{ at: number }>(
    'SELECT at FROM action_limits WHERE action = ? AND at > ?', action, now - windowMs,
  ).toArray().map((r) => r.at);
}

function recordAction(sql: SqlStorage, action: LimitedAction, now: number): void {
  sql.exec('INSERT INTO action_limits (action, at) VALUES (?, ?)', action, now);
}

function requireUserId(ctx: UserContext): string {
  const profile = readProfile(ctx.sql);
  if (!profile) throw new Error('User profile does not exist');
  return profile.user_id;
}

function indexStub(ctx: UserContext) {
  return ctx.env.USER_INDEX.get(ctx.env.USER_INDEX.idFromName('index'));
}
