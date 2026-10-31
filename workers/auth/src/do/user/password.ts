/**
 * Password credential (design §6.2, §7): one `credentials` row of type
 * `password` with `{ hash }`, and per-user backoff in `login_attempts`.
 */

import { hashPassword, verifyDummy, verifyPassword } from '../../crypto/password';
import { newId } from '../../crypto/ids';
import { createMailer } from '../../email/mailer';
import { loginFailureAlert } from '../../email/templates';
import {
  type AttemptState,
  EMPTY_ATTEMPTS,
  checkBackoff,
  recordFailure,
  recordSuccess,
} from '../../ratelimit';
import type { PasswordLoginContext, PasswordLoginResult } from '../../types';
import { type UserContext, readPrimaryEmail } from './context';

/** login_attempts.method for passwords. */
export const PASSWORD_METHOD = 'password';
/** Upper bound on a stored hash string; real ones are ~100 chars. */
const MAX_HASH_LENGTH = 512;

interface PasswordCredential {
  id: string;
  data: string;
  hash: string;
}

/** The password credential, or null when the user has none (passkey-only). */
export function readPasswordCredential(sql: SqlStorage): PasswordCredential | null {
  const row = sql.exec<{ id: string; data: string }>(
    "SELECT id, data FROM credentials WHERE type = 'password' ORDER BY created_at LIMIT 1",
  ).toArray()[0];
  if (!row) return null;
  try {
    const { hash } = JSON.parse(row.data) as { hash?: unknown };
    return typeof hash === 'string' ? { ...row, hash } : null;
  } catch {
    return null;
  }
}

/** Set or replace the password hash (already hashed by the caller). Clears password backoff. */
export function setPassword(ctx: UserContext, hash: string): void {
  if (typeof hash !== 'string' || hash === '' || hash.length > MAX_HASH_LENGTH) {
    throw new Error('setPassword: invalid hash');
  }
  const { sql, now } = ctx;
  ctx.storage.transactionSync(() => {
    const data = JSON.stringify({ hash });
    const existing = readPasswordCredential(sql);
    if (existing) {
      sql.exec('UPDATE credentials SET data = ? WHERE id = ?', data, existing.id);
    } else {
      sql.exec(
        "INSERT INTO credentials (id, type, data, created_at) VALUES (?, 'password', ?, ?)",
        newId('cred'), data, now,
      );
    }
    sql.exec('DELETE FROM login_attempts WHERE method = ?', PASSWORD_METHOD);
    ctx.audit(existing ? 'password.changed' : 'password.set');
  });
}

/**
 * Verify a password and start a session (design §6.2). Backoff is checked
 * first; then the attempt is counted as a failure *before* verifying, so
 * concurrent guesses can't all slip past the check, and success resets it.
 */
export async function loginWithPassword(
  ctx: UserContext,
  password: string,
  login: PasswordLoginContext,
): Promise<PasswordLoginResult> {
  const { sql, now } = ctx;
  const decision = checkBackoff(readAttempts(sql), now);
  if (!decision.allowed) return { ok: false, reason: 'locked', retryAfterMs: decision.retryAfterMs };
  if (decision.needsTurnstile && !login.turnstileOk) return { ok: false, reason: 'turnstile_required' };

  const credential = readPasswordCredential(sql);
  const failure = recordFailure(readAttempts(sql), now);
  writeAttempts(sql, failure.state);

  let result = { ok: false, needsRehash: false };
  if (credential) result = await verifyPassword(password, credential.hash);
  else await verifyDummy(password);

  if (!result.ok) {
    ctx.audit('login.password_failed', { failures: failure.state.failures, ip: login.ip ?? null });
    if (failure.shouldAlert) await sendFailureAlert(ctx, failure.state.failures);
    return { ok: false, reason: 'invalid' };
  }

  writeAttempts(sql, recordSuccess());
  sql.exec('UPDATE credentials SET last_used_at = ? WHERE id = ?', now, credential!.id);
  let rehashed = false;
  if (result.needsRehash) {
    const data = JSON.stringify({ hash: await hashPassword(password) });
    // Only replace the hash we verified; a concurrent setPassword wins.
    rehashed = sql.exec(
      'UPDATE credentials SET data = ? WHERE id = ? AND data = ?', data, credential!.id, credential!.data,
    ).rowsWritten > 0;
  }
  ctx.audit('login.password', { ip: login.ip ?? null, rehashed });
  const session = await ctx.createSession({ amr: ['pwd'], userAgent: login.userAgent, ip: login.ip });
  return { ok: true, session };
}

function readAttempts(sql: SqlStorage): AttemptState {
  const row = sql.exec<{ failures: number; last_failure_at: number | null; locked_until: number | null }>(
    'SELECT failures, last_failure_at, locked_until FROM login_attempts WHERE method = ?', PASSWORD_METHOD,
  ).toArray()[0];
  if (!row) return { ...EMPTY_ATTEMPTS };
  return { failures: row.failures, lastFailureAt: row.last_failure_at, lockedUntil: row.locked_until };
}

function writeAttempts(sql: SqlStorage, state: AttemptState): void {
  if (state.failures === 0) {
    sql.exec('DELETE FROM login_attempts WHERE method = ?', PASSWORD_METHOD);
    return;
  }
  sql.exec(
    `INSERT OR REPLACE INTO login_attempts (method, failures, last_failure_at, locked_until)
     VALUES (?, ?, ?, ?)`,
    PASSWORD_METHOD, state.failures, state.lastFailureAt, state.lockedUntil,
  );
}

async function sendFailureAlert(ctx: UserContext, failures: number): Promise<void> {
  const to = readPrimaryEmail(ctx.sql);
  if (!to) return;
  try {
    await createMailer(ctx.env).send({ to, ...loginFailureAlert(failures) });
    ctx.audit('alert.login_failures', { failures });
  } catch (err) {
    console.error('login failure alert failed', err);
  }
}
