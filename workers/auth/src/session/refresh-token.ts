/**
 * Refresh token format (design §3.2): `rt1.<userId>.<sessionId>.<secret>`.
 */

const PREFIX = 'rt1';
/** `usr_` / `ses_` + ULID (Crockford base32, either case). */
export const USER_ID_PATTERN = /^usr_[0-9A-HJKMNP-TV-Z]{26}$/i;
export const SESSION_ID_PATTERN = /^ses_[0-9A-HJKMNP-TV-Z]{26}$/i;
/** 32 random bytes, base64url without padding. */
export const SECRET_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export interface RefreshTokenParts {
  userId: string;
  sessionId: string;
  secret: string;
}

export function formatRefreshToken({ userId, sessionId, secret }: RefreshTokenParts): string {
  if (!USER_ID_PATTERN.test(userId)) throw new Error('invalid userId');
  if (!SESSION_ID_PATTERN.test(sessionId)) throw new Error('invalid sessionId');
  if (!SECRET_PATTERN.test(secret)) throw new Error('invalid secret');
  return `${PREFIX}.${userId}.${sessionId}.${secret}`;
}

/** Returns the parts, or null for anything that isn't exactly a v1 token. */
export function parseRefreshToken(value: string | null | undefined): RefreshTokenParts | null {
  if (!value || value.length > 128) return null;
  const parts = value.split('.');
  if (parts.length !== 4) return null;
  const [prefix, userId, sessionId, secret] = parts as [string, string, string, string];
  if (prefix !== PREFIX) return null;
  if (!USER_ID_PATTERN.test(userId) || !SESSION_ID_PATTERN.test(sessionId) || !SECRET_PATTERN.test(secret)) {
    return null;
  }
  return { userId, sessionId, secret };
}
