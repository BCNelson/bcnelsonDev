/**
 * Pure session logic for the User DO: refresh-rotation decisions (design
 * §3.2) and claim building. No storage access, so it is unit-testable.
 */

import { config } from '../config';
import { timingSafeEqual } from '../crypto/hash';
import type { UserClaims } from '../types';

/** The `sessions` columns the refresh decision needs. Times are epoch ms. */
export type SessionSecrets = {
  secret_hash: string;
  prev_secret_hash: string | null;
  prev_valid_until: number | null;
  expires_at: number;
  revoked_at: number | null;
};

export type RefreshDecision =
  /** Presented the current secret: rotate. */
  | { action: 'rotate' }
  /** Presented the previous secret within REFRESH_GRACE (concurrent tab): rotate. */
  | { action: 'grace' }
  /** Presented the previous secret after the grace window: theft, revoke the session. */
  | { action: 'reuse' }
  | { action: 'reject'; reason: 'invalid' | 'expired' | 'revoked' };

/** Decide what a refresh with `presentedHash` (SHA-256 of the secret) should do. */
export function decideRefresh(
  row: SessionSecrets | null,
  presentedHash: string,
  now: number,
): RefreshDecision {
  if (!row) return { action: 'reject', reason: 'invalid' };
  if (row.revoked_at !== null) return { action: 'reject', reason: 'revoked' };
  if (row.expires_at <= now) return { action: 'reject', reason: 'expired' };
  // Compare against both hashes unconditionally so timing doesn't reveal which matched.
  const current = timingSafeEqual(presentedHash, row.secret_hash);
  const prev = row.prev_secret_hash !== null && timingSafeEqual(presentedHash, row.prev_secret_hash);
  if (current) return { action: 'rotate' };
  if (prev) {
    return row.prev_valid_until !== null && now <= row.prev_valid_until
      ? { action: 'grace' }
      : { action: 'reuse' };
  }
  return { action: 'reject', reason: 'invalid' };
}

/**
 * Column values after rotating to `newHash`. The hash that was current
 * stays valid for REFRESH_GRACE so a concurrent tab still holding it (or
 * holding the one just issued) keeps working; expiry slides.
 */
export function rotatedSecrets(
  row: Pick<SessionSecrets, 'secret_hash'>,
  newHash: string,
  now: number,
): {
  secret_hash: string;
  prev_secret_hash: string;
  prev_valid_until: number;
  expires_at: number;
  last_seen_at: number;
} {
  return {
    secret_hash: newHash,
    prev_secret_hash: row.secret_hash,
    prev_valid_until: now + config.REFRESH_GRACE,
    expires_at: now + config.REFRESH_TOKEN_TTL,
    last_seen_at: now,
  };
}

export type ProfileRow = {
  user_id: string;
  username: string;
  name: string | null;
  picture: string | null;
  roles: string;
};

export type SessionClaimsRow = {
  id: string;
  auth_time: number;
  amr: string;
};

/** UserClaims from the profile, primary email and session rows. */
export function buildClaims(
  profile: ProfileRow,
  primaryEmail: string,
  session: SessionClaimsRow,
): UserClaims {
  const claims: UserClaims = {
    sub: profile.user_id,
    sid: session.id,
    auth_time: Math.floor(session.auth_time / 1000),
    amr: parseStringArray(session.amr),
    preferred_username: profile.username,
    email: primaryEmail,
  };
  if (profile.name) claims.name = profile.name;
  if (profile.picture) claims.picture = profile.picture;
  const roles = parseStringArray(profile.roles);
  if (roles.length > 0) claims.roles = roles;
  return claims;
}

/** Parse a JSON string array column, tolerating bad data. */
export function parseStringArray(json: string | null): string[] {
  if (!json) return [];
  try {
    const value: unknown = JSON.parse(json);
    return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];
  } catch {
    return [];
  }
}
