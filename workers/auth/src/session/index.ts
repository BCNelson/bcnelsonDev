/**
 * Session cookies (design §3.1) and issuing a session: sign the JWT, set both cookies.
 */

import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import type { CookieOptions } from 'hono/utils/cookie';
import { config } from '../config';
import type { AppContext } from '../http';
import { signAccessToken, type SignedToken } from '../tokens';
import type { UserClaims } from '../types';
import { formatRefreshToken, parseRefreshToken, type RefreshTokenParts } from './refresh-token';

export * from './refresh-token';

/** True when the auth origin is https, so Secure and __Host- cookies work. */
export function isSecureRequest(c: AppContext): boolean {
  return new URL(c.req.url).protocol === 'https:';
}

function refreshCookieName(secure: boolean): string {
  return secure ? config.REFRESH_COOKIE : config.REFRESH_COOKIE_INSECURE;
}

function accessCookieOptions(c: AppContext): CookieOptions {
  return { domain: c.env.COOKIE_DOMAIN, path: '/', httpOnly: true, secure: isSecureRequest(c), sameSite: 'Lax' };
}

/** Host-only; __Host- rules (Secure, Path=/, no Domain) on https. */
function refreshCookieOptions(c: AppContext): CookieOptions {
  return { path: '/', httpOnly: true, secure: isSecureRequest(c), sameSite: 'Lax' };
}

export function setAccessCookie(c: AppContext, token: SignedToken): void {
  const maxAge = Math.max(0, token.expiresAt - Math.floor(Date.now() / 1000));
  setCookie(c, config.ACCESS_COOKIE, token.token, { ...accessCookieOptions(c), maxAge });
}

export function setRefreshCookie(c: AppContext, value: string): void {
  const maxAge = Math.floor(config.REFRESH_TOKEN_TTL / 1000);
  setCookie(c, refreshCookieName(isSecureRequest(c)), value, { ...refreshCookieOptions(c), maxAge });
}

/** Raw refresh cookie value for this request's scheme. */
export function readRefreshCookie(c: AppContext): string | undefined {
  return getCookie(c, refreshCookieName(isSecureRequest(c)));
}

/** Parsed refresh cookie, or null when missing/malformed. */
export function readRefreshToken(c: AppContext): RefreshTokenParts | null {
  return parseRefreshToken(readRefreshCookie(c));
}

/** Clears both cookies (bcn_at with the shared domain). */
export function clearSessionCookies(c: AppContext): void {
  deleteCookie(c, config.ACCESS_COOKIE, accessCookieOptions(c));
  deleteCookie(c, refreshCookieName(isSecureRequest(c)), refreshCookieOptions(c));
}

export interface IssuedSession {
  sessionId: string;
  /** Absent → keep the existing refresh cookie (grace-window refresh). */
  secret?: string;
  claims: UserClaims;
}

/** Signs an access token and sets both cookies. Returns the signed token. */
export async function issueSession(c: AppContext, userId: string, session: IssuedSession): Promise<SignedToken> {
  if (session.claims.sub !== userId || session.claims.sid !== session.sessionId) {
    throw new Error('session claims do not match userId/sessionId');
  }
  const token = await signAccessToken(c.env, session.claims);
  setAccessCookie(c, token);
  if (session.secret !== undefined) {
    setRefreshCookie(c, formatRefreshToken({ userId, sessionId: session.sessionId, secret: session.secret }));
  }
  return token;
}
