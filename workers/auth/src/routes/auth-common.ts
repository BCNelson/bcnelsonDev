/**
 * Shared pieces for interactive login routes (password, signup, and later
 * passkey/social): error responses, DO stubs, IP limiting, and
 * `completeLogin`, the one place a fresh session becomes cookies.
 */

import type { MiddlewareHandler } from 'hono';
import { getCookie } from 'hono/cookie';
import type { ClientErrorStatusCode } from 'hono/utils/http-status';
import { config } from '../config';
import type { Env } from '../env';
import { clientIp, validateReturnTo, type AppContext, type AppEnv } from '../http';
import { isFormPost, type RequestBody } from '../http/body';
import { normalizeEmail } from '../identifiers';
import { checkIp } from '../ratelimit';
import { issueSession, readRefreshToken } from '../session';
import { verifyAccessToken, type AccessTokenPayload } from '../tokens';
import type { CreatedSession } from '../types';

/** JSON error body every auth POST uses: `{ ok: false, error, message, retryAfterMs? }`. */
export function apiError(
  c: AppContext,
  status: ClientErrorStatusCode,
  error: string,
  message: string,
  retryAfterMs?: number,
): Response {
  if (retryAfterMs !== undefined) {
    c.header('Retry-After', String(Math.max(1, Math.ceil(retryAfterMs / 1000))));
    return c.json({ ok: false, error, message, retryAfterMs }, status);
  }
  return c.json({ ok: false, error, message }, status);
}

export const RATE_LIMITED = 'Too many requests. Please wait a minute and try again.';
export const BAD_REQUEST = 'The request was missing something. Please reload the page and try again.';

export function indexStub(env: Env) {
  return env.USER_INDEX.get(env.USER_INDEX.idFromName('index'));
}

export function userStub(env: Env, userId: string) {
  return env.USER.get(env.USER.idFromName(userId));
}

/** IP and User-Agent recorded on sessions. */
export function requestInfo(c: AppContext): { ip?: string; userAgent?: string } {
  return { ip: clientIp(c.req.raw), userAgent: c.req.header('User-Agent') };
}

/** RL_IP check (design §7); a 429 response when over the limit, else null. */
export async function limitIp(c: AppContext): Promise<Response | null> {
  const ok = await checkIp(c.env, clientIp(c.req.raw) ?? 'unknown');
  return ok ? null : apiError(c, 429, 'rate_limited', RATE_LIMITED);
}

/** Middleware form of limitIp for POSTs (other methods pass through). */
export const ipLimitPosts: MiddlewareHandler<AppEnv> = async (c, next) => {
  if (c.req.method === 'POST') {
    const limited = await limitIp(c);
    if (limited) return limited;
  }
  await next();
};

/** Validated return_to from the body, else the query string, else the default. */
export function returnToFrom(c: AppContext, body: RequestBody | null): string {
  return validateReturnTo(body?.fields.return_to ?? c.req.query('return_to'), c.env);
}

/** Parsed ADMIN_EMAILS, normalized. */
export function adminEmails(env: Pick<Env, 'ADMIN_EMAILS'>): Set<string> {
  return new Set((env.ADMIN_EMAILS ?? '').split(',').map(normalizeEmail).filter(Boolean));
}

/**
 * Finish any interactive login: apply the ADMIN_EMAILS bootstrap (design §8),
 * sign the access token, set both cookies, and answer `{ ok: true, redirect }`
 * (or a 303 to `returnTo` for a no-JS form post). `returnTo` must already be
 * validated.
 */
export async function completeLogin(
  c: AppContext,
  userId: string,
  session: CreatedSession,
  returnTo: string,
): Promise<Response> {
  let claims = session.claims;
  if (adminEmails(c.env).has(normalizeEmail(claims.email)) && !claims.roles?.includes('admin')) {
    const user = userStub(c.env, userId);
    await user.ensureRole('admin', 'admin_emails');
    claims = (await user.getClaims(session.sessionId)) ?? claims;
  }
  // A re-login (e.g. reauth from the profile page) supersedes this browser's
  // previous session of the same user; the secret check keeps it to our own.
  // OIDC client tokens bound to the old session move to the new one: the user
  // re-confirming who they are shouldn't sign third-party apps out.
  const previous = readRefreshToken(c);
  if (previous && previous.userId === userId && previous.sessionId !== session.sessionId) {
    await userStub(c.env, userId).supersedeSession(previous.sessionId, previous.secret, session.sessionId);
  }
  await issueSession(c, userId, { sessionId: session.sessionId, secret: session.secret, claims });
  if (isFormPost(c)) return c.redirect(returnTo, 303);
  return c.json({ ok: true, redirect: returnTo });
}

/** The verified bcn_at payload, or null when absent/invalid/expired. */
export async function currentAccessToken(c: AppContext): Promise<AccessTokenPayload | null> {
  const token = getCookie(c, config.ACCESS_COOKIE);
  if (!token) return null;
  try {
    return await verifyAccessToken(c.env, token);
  } catch {
    return null;
  }
}

/** Cache-Control: no-store on every response. */
export const noStore: MiddlewareHandler<AppEnv> = async (c, next) => {
  await next();
  c.header('Cache-Control', 'no-store');
};
