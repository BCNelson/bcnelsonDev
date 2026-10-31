/**
 * `requireAdmin` (design §8): admin-only routes. Built on http/auth.ts
 * `liveSession` (bcn_at verified, then re-checked against the User DO, so
 * revoked sessions, disabled accounts and removed roles take effect at once
 * rather than when the JWT expires), plus the `admin` role, and for
 * state-changing requests an `auth_time` within REAUTH_WINDOW. Errors use
 * the shared shapes (http/auth.ts unauthorizedResponse /
 * reauthRequiredResponse), plus 403 `forbidden` for non-admins.
 */

import type { MiddlewareHandler } from 'hono';
import type { Env } from '../env';
import type { UserClaims } from '../types';
import { checkIp } from '../ratelimit';
import { hasRecentAuth, liveSession, reauthRequiredResponse, unauthorizedResponse } from './auth';
import { clientIp } from './index';

/** Who is calling an admin route. Claims are the live ones from the User DO. */
export interface AdminPrincipal {
  userId: string;
  sessionId: string;
  claims: UserClaims;
}

export type AdminEnv = { Bindings: Env; Variables: { admin: AdminPrincipal } };

export type AdminCheck = 'ok' | 'forbidden' | 'reauth_required';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * Pure authorisation decision: `admin` role required; with `needReauth`, the
 * last interactive login (claims.auth_time, seconds) must be within REAUTH_WINDOW.
 */
export function checkAdmin(claims: Pick<UserClaims, 'roles' | 'auth_time'>, needReauth: boolean, now = Date.now()): AdminCheck {
  if (!claims.roles?.includes('admin')) return 'forbidden';
  if (needReauth && !hasRecentAuth(claims, now)) return 'reauth_required';
  return 'ok';
}

export interface RequireAdminOptions {
  /** 'page': redirect to /refresh when signed out, HTML 403 otherwise. 'api': JSON errors. */
  mode: 'page' | 'api';
  /** Require a recent login for every request. Default: only for non-GET/HEAD/OPTIONS. */
  reauth?: boolean;
}

export function requireAdmin(opts: RequireAdminOptions): MiddlewareHandler<AdminEnv> {
  return async (c, next) => {
    c.header('Cache-Control', 'no-store');
    const live = await liveSession(c);
    const here = new URL(c.req.url);
    const returnTo = `${c.env.ISSUER}${here.pathname}${here.search}`;
    if (!live) {
      if (opts.mode === 'page') return c.redirect(`/refresh?return_to=${encodeURIComponent(returnTo)}`, 302);
      return unauthorizedResponse(c, 'Please sign in again.');
    }
    const unsafe = !SAFE_METHODS.has(c.req.method.toUpperCase());
    // Every mutation is IP rate limited (design §7), like the other POST routes.
    if (unsafe && !(await checkIp(c.env, clientIp(c.req.raw) ?? 'unknown'))) {
      return c.json({ ok: false, error: 'rate_limited', message: 'Too many requests. Please wait a minute and try again.' }, 429);
    }
    const needReauth = opts.reauth ?? unsafe;
    const check = checkAdmin(live.claims, needReauth);
    if (check === 'forbidden') {
      if (opts.mode === 'page') return c.text('Forbidden: this page is for administrators.', 403);
      return c.json({ ok: false, error: 'forbidden', message: 'Administrators only.' }, 403);
    }
    if (check === 'reauth_required') {
      // API calls come from /admin or /admin/clients; send the admin back to the page.
      const page = here.pathname.startsWith('/api/admin/clients') ? '/admin/clients' : '/admin';
      return reauthRequiredResponse(c, `${c.env.ISSUER}${page}`, 'For your security, please sign in again to make changes.');
    }
    c.set('admin', { userId: live.token.sub, sessionId: live.token.sid, claims: live.claims });
    await next();
  };
}
