/**
 * Password reset (design §6.6). JSON or form bodies.
 *
 * GET  /password/forgot[?return_to]      page: email + Turnstile
 * POST /password/forgot  { email, turnstile, return_to? }
 *   200 { ok: true }  — always the same, whether or not the address has an
 *       account, the per-user limit allowed a send, or the mail went out
 *   400 bad_request | invalid_email · 403 turnstile_failed · 429 rate_limited
 * GET  /password/reset?token=pr1.<userId>.<secret>   page: new password
 * POST /password/reset   { token, password, confirm? }
 *   200 { ok: true, redirect: '/login?notice=password_updated' }  (no login)
 *   400 bad_request | invalid_token | weak_password | password_mismatch · 429 rate_limited
 * Errors are `{ ok: false, error, message }`. A no-JS form post gets 303s:
 * forgot → /password/forgot?sent=1 or ?error=<code>; reset → the redirect
 * above, or back to /password/reset?token=…&error=<code>.
 *
 * The token is never logged; it routes straight to the User DO by its userId.
 */

import { Hono } from 'hono';
import type { ClientErrorStatusCode } from 'hono/utils/http-status';
import { hashPassword, validatePasswordPolicy } from '../crypto/password';
import { parseResetToken } from '../do/user/reset';
import type { Env } from '../env';
import { clientIp, validateReturnTo, type AppContext, type AppEnv } from '../http';
import { isFormPost, readBody } from '../http/body';
import { verifyTurnstile } from '../http/turnstile';
import { validateEmail } from '../identifiers';
import { renderPage } from '../pages/layout';
import { FORGOT_JS, PASSWORD_PAGE_MESSAGES, RESET_JS, forgotPage, resetPage } from '../pages/password';
import { checkIdentifier, checkIp } from '../ratelimit';
import { clearSessionCookies } from '../session';
import { apiError, indexStub, noStore, returnToFrom, userStub } from './auth-common';

export const LOGIN_AFTER_RESET = '/login?notice=password_updated';

export const passwordRoutes = new Hono<AppEnv>();

passwordRoutes.use('/password/*', noStore);

passwordRoutes.get('/password/forgot', (c) => {
  const returnTo = validateReturnTo(c.req.query('return_to'), c.env);
  return renderPage(c, {
    title: 'Reset your password',
    body: forgotPage({
      returnTo,
      turnstileSiteKey: c.env.TURNSTILE_SITE_KEY,
      sent: c.req.query('sent') === '1',
      error: c.req.query('error'),
    }),
    scripts: [FORGOT_JS],
    turnstile: true,
  });
});

passwordRoutes.post('/password/forgot', async (c) => {
  const body = await readBody(c);
  const returnTo = returnToFrom(c, body);
  const fail = (status: ClientErrorStatusCode, error: string) => {
    if (isFormPost(c)) {
      return c.redirect(`/password/forgot?error=${error}&return_to=${encodeURIComponent(returnTo)}`, 303);
    }
    return apiError(c, status, error, PASSWORD_PAGE_MESSAGES[error]!);
  };

  const ip = clientIp(c.req.raw);
  if (!(await checkIp(c.env, ip ?? 'unknown'))) return fail(429, 'rate_limited');
  if (!body) return fail(400, 'bad_request');
  const email = validateEmail(body.fields.email ?? '');
  if (!email.ok) return fail(400, 'invalid_email');

  const token = body.fields.turnstile || body.fields['cf-turnstile-response'];
  const turnstile = await verifyTurnstile(c.env, token, ip);
  if (!turnstile.ok) return fail(403, 'turnstile_failed');
  if (!(await checkIdentifier(c.env, email.norm))) return fail(429, 'rate_limited');

  // Same answer, and (in production) the same latency, whatever happens next.
  const work = sendResetLink(c.env, email.norm);
  const waitUntil = executionWaitUntil(c);
  if (waitUntil) waitUntil(work);
  else await work;

  if (isFormPost(c)) return c.redirect(`/password/forgot?sent=1&return_to=${encodeURIComponent(returnTo)}`, 303);
  return c.json({ ok: true });
});

passwordRoutes.get('/password/reset', async (c) => {
  const raw = c.req.query('token') ?? '';
  const parts = parseResetToken(raw);
  const usable = parts ? (await userStub(c.env, parts.userId).checkResetToken(parts.secret)).ok : false;
  return renderPage(c, {
    title: 'Choose a new password',
    body: resetPage({ token: raw, invalid: !usable, error: c.req.query('error') }),
    scripts: usable ? [RESET_JS] : [],
    status: usable ? 200 : 400,
  });
});

passwordRoutes.post('/password/reset', async (c) => {
  const body = await readBody(c);
  const raw = body?.fields.token ?? '';
  const fail = (status: ClientErrorStatusCode, error: string) => {
    if (isFormPost(c)) {
      return c.redirect(`/password/reset?token=${encodeURIComponent(raw)}&error=${error}`, 303);
    }
    return apiError(c, status, error, PASSWORD_PAGE_MESSAGES[error]!);
  };

  if (!(await checkIp(c.env, clientIp(c.req.raw) ?? 'unknown'))) return fail(429, 'rate_limited');
  const password = body?.fields.password;
  if (!body || !raw || typeof password !== 'string' || password === '') return fail(400, 'bad_request');
  const confirm = body.fields.confirm;
  if (confirm !== undefined && confirm !== password) return fail(400, 'password_mismatch');

  const parts = parseResetToken(raw);
  if (!parts) return fail(400, 'invalid_token');
  if (validatePasswordPolicy(password)) return fail(400, 'weak_password');

  // Cheap check first so a bad link doesn't cost a password hash.
  const user = userStub(c.env, parts.userId);
  if (!(await user.checkResetToken(parts.secret)).ok) return fail(400, 'invalid_token');
  const hash = await hashPassword(password);
  const result = await user.resetPassword(parts.secret, hash);
  if (!result.ok) return fail(400, 'invalid_token');

  // Every session is revoked; drop this browser's cookies too, or a still-valid
  // access token would bounce /login straight back to return_to.
  clearSessionCookies(c);
  if (isFormPost(c)) return c.redirect(LOGIN_AFTER_RESET, 303);
  return c.json({ ok: true, redirect: LOGIN_AFTER_RESET });
});

/** Resolve the address and let its User DO decide whether to send. Never throws. */
async function sendResetLink(env: Env, emailNorm: string): Promise<void> {
  try {
    const userId = await indexStub(env).resolve(emailNorm);
    if (!userId) return;
    await userStub(env, userId).requestPasswordReset(emailNorm);
  } catch (err) {
    console.error('password reset request failed', err);
  }
}

/** ExecutionContext.waitUntil when running in a Worker; null in tests (app.request without ctx). */
function executionWaitUntil(c: AppContext): ((p: Promise<unknown>) => void) | null {
  try {
    const ctx = c.executionCtx;
    return (p) => ctx.waitUntil(p);
  } catch {
    return null;
  }
}
