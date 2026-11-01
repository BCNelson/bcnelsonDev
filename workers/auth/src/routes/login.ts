/**
 * Password login (design §6.2): GET /login page, POST /login/password.
 *
 * POST /login/password  { identifier, password, turnstile?, return_to? }  (JSON or form)
 *   200 { ok: true, redirect }                    cookies set
 *   400 bad_request · 401 invalid_credentials · 403 turnstile_required
 *   429 rate_limited | locked (+ retryAfterMs, Retry-After)
 * Errors are `{ ok: false, error, message, retryAfterMs? }`. A no-JS form post
 * gets 303s instead: to return_to, or back to /login?error=<code>.
 */

import { Hono } from 'hono';
import type { ClientErrorStatusCode } from 'hono/utils/http-status';
import { verifyDummy } from '../crypto/password';
import { clientIp, validateReturnTo, type AppContext, type AppEnv } from '../http';
import { isFormPost, readBody } from '../http/body';
import { verifyTurnstile } from '../http/turnstile';
import { classifyIdentifier } from '../identifiers';
import { renderPage } from '../pages/layout';
import { LOGIN_JS, LOGIN_MESSAGES, loginPage } from '../pages/login';
import { PASSKEY_LOGIN_JS, WEBAUTHN_JS, passkeyLoginSlot } from '../pages/passkeys';
import { checkIdentifier } from '../ratelimit';
import { readRefreshToken } from '../session';
import { socialLoginSlot } from './oauth';
import {
  apiError,
  completeLogin,
  currentAccessToken,
  indexStub,
  limitIp,
  noStore,
  requestInfo,
  returnToFrom,
  userStub,
} from './auth-common';

export const loginRoutes = new Hono<AppEnv>();

loginRoutes.use('/login/password', noStore);

/** The root: the profile when signed in, otherwise sign-in (which then returns to the profile). */
loginRoutes.get('/', async (c) => {
  if (await currentAccessToken(c)) return c.redirect('/profile', 302);
  return c.redirect(`/login?return_to=${encodeURIComponent(`${c.env.ISSUER}/profile`)}`, 302);
});

/**
 * Signed in already → straight to return_to; refresh cookie only → /refresh first.
 * `?reauth=1` (http/auth requireReauth) always shows the form, identifier prefilled.
 */
loginRoutes.get('/login', async (c) => {
  const returnTo = validateReturnTo(c.req.query('return_to'), c.env);
  const reauth = c.req.query('reauth') === '1';
  const current = await currentAccessToken(c);
  if (current && !reauth) return c.redirect(returnTo, 302);
  if (!reauth && readRefreshToken(c)) return c.redirect(`/refresh?return_to=${encodeURIComponent(returnTo)}`, 302);
  return renderPage(c, {
    title: reauth ? "Confirm it's you" : 'Sign in',
    body: loginPage({
      returnTo,
      error: c.req.query('error'),
      notice: c.req.query('notice'),
      turnstileSiteKey: c.env.TURNSTILE_SITE_KEY,
      reauth: reauth ? { identifier: current?.preferred_username } : undefined,
      slots: { passkey: passkeyLoginSlot(), social: socialLoginSlot(c.env, returnTo) },
    }),
    scripts: [LOGIN_JS, WEBAUTHN_JS, PASSKEY_LOGIN_JS],
    turnstile: true,
  });
});

loginRoutes.post('/login/password', async (c) => {
  const body = await readBody(c);
  const returnTo = returnToFrom(c, body);
  const limited = await limitIp(c);
  if (limited) return isFormPost(c) ? failLogin(c, 429, 'rate_limited', returnTo) : limited;

  const identifier = body?.fields.identifier?.trim() ?? '';
  const password = body?.fields.password ?? '';
  if (!identifier || !password) return failLogin(c, 400, 'bad_request', returnTo);

  const { norm } = classifyIdentifier(identifier);
  if (!(await checkIdentifier(c.env, norm))) return failLogin(c, 429, 'rate_limited', returnTo);

  const userId = await indexStub(c.env).resolve(identifier);
  if (!userId) {
    // Same work and answer as a wrong password.
    await verifyDummy(password);
    return failLogin(c, 401, 'invalid_credentials', returnTo);
  }

  const token = body?.fields.turnstile || body?.fields['cf-turnstile-response'];
  const turnstile = await verifyTurnstile(c.env, token, clientIp(c.req.raw));
  const result = await userStub(c.env, userId).loginWithPassword(password, {
    amr: ['pwd'],
    ...requestInfo(c),
    turnstileOk: turnstile.ok,
  });
  if (result.ok) return completeLogin(c, userId, result.session, returnTo);
  switch (result.reason) {
    case 'turnstile_required':
      return failLogin(c, 403, 'turnstile_required', returnTo);
    case 'locked':
      return failLogin(c, 429, 'locked', returnTo, result.retryAfterMs);
    case 'disabled':
      return failLogin(c, 403, 'account_disabled', returnTo);
    default:
      return failLogin(c, 401, 'invalid_credentials', returnTo);
  }
});

function failLogin(
  c: AppContext,
  status: ClientErrorStatusCode,
  error: string,
  returnTo: string,
  retryAfterMs?: number,
): Response {
  if (isFormPost(c)) {
    const reauth = c.req.query('reauth') === '1' ? '&reauth=1' : '';
    return c.redirect(`/login?error=${error}${reauth}&return_to=${encodeURIComponent(returnTo)}`, 303);
  }
  let message = LOGIN_MESSAGES[error]!;
  if (error === 'locked' && retryAfterMs) {
    const minutes = Math.max(1, Math.ceil(retryAfterMs / 60_000));
    message = `Too many failed attempts. Try again in ${minutes} minute${minutes === 1 ? '' : 's'}.`;
  }
  return apiError(c, status, error, message, retryAfterMs);
}
