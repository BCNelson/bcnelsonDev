/**
 * WebAuthn challenges (design §4.1, §6.3), kept in the UserIndex because the
 * user often isn't known yet (discoverable login, signup). Each challenge is
 * single use and lives for WEBAUTHN_CHALLENGE_TTL; the alarm sweeps leftovers.
 *
 * Purposes in use (routes/passkey.ts): `login`, `register:signup`
 * (data: { signupId, userId }), `register:user` (data: { userId, sessionId }).
 */

import { config } from '../../config';
import type { IndexContext } from './context';

/** Longest challenge/purpose accepted (ours are 43-char base64url). */
const MAX_CHALLENGE_LENGTH = 256;
const MAX_PURPOSE_LENGTH = 64;

/** Small string map a ceremony carries with its challenge. */
export type ChallengeData = Record<string, string>;

export interface ChallengeRecord {
  purpose: string;
  /** What putChallenge stored, or null. */
  data: ChallengeData | null;
  expiresAt: number;
}

type ChallengeRow = { challenge: string; purpose: string; expires_at: number; data: string | null };

/** Store a fresh challenge for `purpose`. Throws on an over-long or duplicate challenge. */
export async function putChallenge(
  ctx: IndexContext,
  purpose: string,
  challenge: string,
  data?: ChallengeData,
): Promise<{ expiresAt: number }> {
  if (!challenge || challenge.length > MAX_CHALLENGE_LENGTH) throw new Error('putChallenge: invalid challenge');
  if (!purpose || purpose.length > MAX_PURPOSE_LENGTH) throw new Error('putChallenge: invalid purpose');
  const expiresAt = ctx.now + config.WEBAUTHN_CHALLENGE_TTL;
  ctx.sql.exec(
    'INSERT INTO challenges (challenge, purpose, expires_at, data) VALUES (?, ?, ?, ?)',
    challenge, purpose, expiresAt, data === undefined ? null : JSON.stringify(data),
  );
  await ctx.scheduleSweep(expiresAt);
  return { expiresAt };
}

/**
 * Take a challenge (delete it) if it exists for `purpose`. Returns null when
 * unknown, for another purpose (left in place), already used, or expired.
 */
export function consumeChallenge(ctx: IndexContext, challenge: string, purpose: string): ChallengeRecord | null {
  if (!challenge || challenge.length > MAX_CHALLENGE_LENGTH) return null;
  const { sql, now } = ctx;
  return ctx.storage.transactionSync(() => {
    const row = sql.exec<ChallengeRow>(
      'SELECT challenge, purpose, expires_at, data FROM challenges WHERE challenge = ?', challenge,
    ).toArray()[0];
    if (!row || row.purpose !== purpose) return null;
    sql.exec('DELETE FROM challenges WHERE challenge = ?', challenge);
    if (row.expires_at <= now) return null;
    let data: ChallengeData | null = null;
    try {
      const parsed: unknown = row.data === null ? null : JSON.parse(row.data);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) data = parsed as ChallengeData;
    } catch {
      data = null;
    }
    return { purpose: row.purpose, data, expiresAt: row.expires_at };
  });
}

/**
 * True when `userId` owns an active handle, i.e. a finished account. Passkey
 * login checks this before addressing a User DO by an untrusted userHandle,
 * so random handles can't spin up empty DOs.
 */
export function isActiveUser(ctx: IndexContext, userId: string): boolean {
  return ctx.sql.exec<{ n: number }>(
    "SELECT COUNT(*) AS n FROM handles WHERE user_id = ? AND status = 'active'", userId,
  ).one().n > 0;
}
