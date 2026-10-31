/**
 * Refresh and logout (design §6.4): GET /refresh, GET /session/token (CORS), POST /logout.
 */

import { Hono } from 'hono';
import { siteCors, validateReturnTo, type AppContext, type AppEnv } from '../http';
import { clearSessionCookies, issueSession, readRefreshToken, type RefreshTokenParts } from '../session';
import type { RefreshResult } from '../types';
import { ipLimitPosts } from './auth-common';

export const sessionRoutes = new Hono<AppEnv>();

sessionRoutes.use('/refresh', noStore);
sessionRoutes.use('/session/token', noStore, siteCors({ methods: ['GET'] }));
sessionRoutes.use('/logout', noStore, siteCors({ methods: ['POST'] }), ipLimitPosts);

/** Rotates the refresh token, sets fresh cookies, redirects back; or sends the user to /login. */
sessionRoutes.get('/refresh', async (c) => {
  const returnTo = validateReturnTo(c.req.query('return_to'), c.env);
  const parts = readRefreshToken(c);
  const result = parts ? await refresh(c, parts) : null;
  if (!parts || !result?.ok) {
    clearSessionCookies(c);
    return c.redirect(`/login?return_to=${encodeURIComponent(returnTo)}`, 302);
  }
  await issueSession(c, parts.userId, { sessionId: parts.sessionId, secret: result.secret, claims: result.claims });
  return c.redirect(returnTo, 302);
});

/** For SPAs: rotates the session and returns the access token as JSON. */
sessionRoutes.get('/session/token', async (c) => {
  const parts = readRefreshToken(c);
  const result = parts ? await refresh(c, parts) : null;
  if (!parts || !result?.ok) {
    clearSessionCookies(c);
    return c.json({ error: 'invalid_session', reason: result?.ok === false ? result.reason : 'invalid' }, 401);
  }
  const token = await issueSession(c, parts.userId, {
    sessionId: parts.sessionId,
    secret: result.secret,
    claims: result.claims,
  });
  // expires_at is epoch seconds, matching the JWT's exp.
  return c.json({ access_token: token.token, expires_at: token.expiresAt });
});

/** Revokes the current session and clears both cookies. Redirects when return_to is given. */
sessionRoutes.post('/logout', async (c) => {
  const parts = readRefreshToken(c);
  if (parts) await userStub(c, parts.userId).revokeSession(parts.sessionId, parts.secret);
  clearSessionCookies(c);
  const returnTo = c.req.query('return_to');
  if (returnTo !== undefined) return c.redirect(validateReturnTo(returnTo, c.env), 303);
  return c.body(null, 204);
});

function userStub(c: AppContext, userId: string) {
  return c.env.USER.get(c.env.USER.idFromName(userId));
}

/** Calls User.refreshSession and rejects results whose claims don't match the cookie. */
async function refresh(c: AppContext, parts: RefreshTokenParts): Promise<RefreshResult> {
  const result: RefreshResult = await userStub(c, parts.userId).refreshSession(parts.sessionId, parts.secret);
  if (result.ok && (result.claims.sub !== parts.userId || result.claims.sid !== parts.sessionId)) {
    return { ok: false, reason: 'invalid' };
  }
  return result;
}

async function noStore(c: AppContext, next: () => Promise<void>): Promise<void> {
  await next();
  c.header('Cache-Control', 'no-store');
}
