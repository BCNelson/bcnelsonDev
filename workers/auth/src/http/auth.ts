/**
 * Signed-in and re-authentication middleware for auth-Worker routes.
 *
 *   const r = new Hono<AuthEnv>();
 *   r.use('/thing/*', requireSession());                 // c.get('user') = verified bcn_at claims
 *   r.post('/thing/danger', requireReauth(), handler);   // auth_time within REAUTH_WINDOW
 *
 * Page requests (GET/HEAD outside /api/ that don't ask for JSON) are
 * redirected: no session → /refresh?return_to=<this URL> (which falls through
 * to /login), stale login → /login?reauth=1&return_to=<this URL>. Everything
 * else gets JSON in the apiError shape:
 *   401 { ok: false, error: 'unauthorized', message }
 *   403 { ok: false, error: 'reauth_required', message, reauthUrl }
 *
 * Every signed-in JSON endpoint uses these two shapes (unauthorizedResponse /
 * reauthRequiredResponse): requireSession / requireReauth here, requireAdmin
 * (http/admin.ts), the passkey and social-unlink routes. Client JS keys on
 * `error`, not the status: 'reauth_required' → go to `reauthUrl`,
 * 'unauthorized' → reload (the page load refreshes or goes to /login).
 */

import type { Context, MiddlewareHandler } from 'hono';
import { getCookie } from 'hono/cookie';
import { config } from '../config';
import type { Env } from '../env';
import { verifyAccessToken, type AccessTokenPayload } from '../tokens';
import type { UserClaims } from '../types';
import { validateReturnTo, type AppContext } from './index';

/**
 * Hono env for routes behind requireSession: `c.get('user')` is the verified
 * access token; with `verifyActive`, `c.get('claims')` holds the live claims
 * from the User DO.
 */
export type AuthEnv = { Bindings: Env; Variables: { user: AccessTokenPayload; claims?: UserClaims } };
export type AuthContext = Context<AuthEnv>;

/** Any route context of this Worker (base, signed-in or admin env). */
type AnyContext = Context<any>;

/** A verified bcn_at whose session the User DO still considers live. */
export interface LiveSession {
  token: AccessTokenPayload;
  /** Live claims (roles, auth_time, username) from User.getClaims. */
  claims: UserClaims;
}

export const UNAUTHORIZED_MESSAGE = 'Sign in to continue.';
export const REAUTH_MESSAGE = 'For your security, please sign in again to continue.';

export interface RequireSessionOptions {
  /**
   * Also ask the User DO whether the session is still active (not revoked or
   * expired, account not disabled). Costs one DO call; use it where the
   * handler talks to the DO anyway or acts on the account.
   */
  verifyActive?: boolean;
}

export interface RequireReauthOptions {
  /** Where to come back to after re-login. Default: this URL for pages, ISSUER/profile for APIs. */
  returnTo?: (c: AuthContext) => string;
}

/** True for a browser page load (redirect) rather than an API call (JSON). */
export function isPageRequest(c: AnyContext | AppContext | AuthContext): boolean {
  const method = c.req.method.toUpperCase();
  if (method !== 'GET' && method !== 'HEAD') return false;
  if (c.req.path.startsWith('/api/')) return false;
  return !(c.req.header('Accept') ?? '').includes('application/json');
}

/** True when the login behind `user` happened within REAUTH_WINDOW. */
export function hasRecentAuth(user: Pick<AccessTokenPayload, 'auth_time'>, now = Date.now()): boolean {
  const ageMs = now - user.auth_time * 1000;
  return ageMs >= -60_000 && ageMs <= config.REAUTH_WINDOW;
}

/** The re-login URL for `returnTo` (validated). */
export function reauthUrl(env: Env, returnTo: string): string {
  return `/login?reauth=1&return_to=${encodeURIComponent(validateReturnTo(returnTo, env))}`;
}

/** 401 `{ ok: false, error: 'unauthorized', message }` (no-store). */
export function unauthorizedResponse(c: AnyContext, message = UNAUTHORIZED_MESSAGE): Response {
  c.header('Cache-Control', 'no-store');
  return c.json({ ok: false, error: 'unauthorized', message }, 401);
}

/** 403 `{ ok: false, error: 'reauth_required', message, reauthUrl }` (no-store); `returnTo` is validated. */
export function reauthRequiredResponse(c: AnyContext, returnTo: string, message = REAUTH_MESSAGE): Response {
  c.header('Cache-Control', 'no-store');
  return c.json({ ok: false, error: 'reauth_required', message, reauthUrl: reauthUrl(c.env as Env, returnTo) }, 403);
}

/**
 * The caller's live session: a valid bcn_at whose session the User DO says
 * is active (not revoked or expired, account enabled), with the live claims.
 * Null when signed out. One DO call.
 */
export async function liveSession(c: AnyContext): Promise<LiveSession | null> {
  const token = await verifiedToken(c);
  if (!token) return null;
  const claims = await liveClaims(c.env as Env, token);
  return claims ? { token, claims } : null;
}

/** Requires a valid bcn_at; sets `c.get('user')` (and `c.get('claims')` with verifyActive). */
export function requireSession(options: RequireSessionOptions = {}): MiddlewareHandler<AuthEnv> {
  return async (c, next) => {
    const user = await verifiedToken(c);
    const claims = user && options.verifyActive ? await liveClaims(c.env, user) : null;
    if (!user || (options.verifyActive && !claims)) {
      if (isPageRequest(c)) {
        return c.redirect(`/refresh?return_to=${encodeURIComponent(validateReturnTo(c.req.url, c.env))}`, 302);
      }
      return unauthorizedResponse(c);
    }
    c.set('user', user);
    if (claims) c.set('claims', claims);
    await next();
  };
}

/** Requires a recent interactive login (design §6.5). Mount after requireSession. */
export function requireReauth(options: RequireReauthOptions = {}): MiddlewareHandler<AuthEnv> {
  return async (c, next) => {
    const user = c.get('user');
    if (!user) throw new Error('requireReauth needs requireSession first');
    // Prefer the live auth_time when requireSession({ verifyActive }) fetched it.
    if (hasRecentAuth(c.get('claims') ?? user)) {
      await next();
      return;
    }
    const page = isPageRequest(c);
    const returnTo = options.returnTo?.(c) ?? (page ? c.req.url : `${c.env.ISSUER}/profile`);
    if (page) return c.redirect(reauthUrl(c.env, returnTo), 302);
    return reauthRequiredResponse(c, returnTo);
  };
}

async function verifiedToken(c: AnyContext): Promise<AccessTokenPayload | null> {
  const token = getCookie(c, config.ACCESS_COOKIE);
  if (!token) return null;
  try {
    const payload = await verifyAccessToken(c.env as Env, token);
    return typeof payload.sub === 'string' && typeof payload.sid === 'string' ? payload : null;
  } catch {
    return null;
  }
}

async function liveClaims(env: Env, user: AccessTokenPayload): Promise<UserClaims | null> {
  const claims = await env.USER.get(env.USER.idFromName(user.sub)).getClaims(user.sid);
  return claims !== null && claims.sub === user.sub && claims.sid === user.sid ? claims : null;
}
