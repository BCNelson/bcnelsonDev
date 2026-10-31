/**
 * Signup (design §6.1): GET /signup page and the three JSON steps. All take
 * JSON or form bodies and answer `{ ok: true, ... }` or
 * `{ ok: false, error, message, retryAfterMs? }`.
 *
 * POST /signup/start     { username, email, turnstile }  → { ok, signupId }
 *   400 invalid_username | invalid_email · 403 turnstile_failed
 *   409 username_taken · 429 rate_limited
 * POST /signup/verify    { signupId, code }               → { ok }
 *   400 invalid_code | code_expired | too_many_attempts
 * POST /signup/complete  { signupId, password, return_to? } → { ok, redirect }, cookies set
 *   400 not_verified | weak_password · 409 signup_failed
 *
 * /signup/complete accepts any credential in SIGNUP_CREDENTIALS; the first
 * whose `matches` accepts the body handles it. Password is built in; the
 * passkey variant adds a handler (see SignupCredential).
 */

import { Hono } from 'hono';
import { config } from '../config';
import { hashPassword, validatePasswordPolicy } from '../crypto/password';
import { clientIp, validateReturnTo, type AppContext, type AppEnv } from '../http';
import type { RequestBody } from '../http/body';
import { readBody } from '../http/body';
import { verifyTurnstile } from '../http/turnstile';
import { validateEmail, validateUsername, type UsernameError } from '../identifiers';
import type { VerifiedSignup } from '../do/index/signup';
import { renderPage } from '../pages/layout';
import { SIGNUP_JS, signupPage } from '../pages/signup';
import { PASSKEY_SIGNUP_JS, WEBAUTHN_JS, passkeySignupSlot } from '../pages/passkeys';
import { passkeySignupCredential } from './passkey';
import { socialLoginSlot } from './oauth';
import { checkIdentifier } from '../ratelimit';
import {
  BAD_REQUEST,
  RATE_LIMITED,
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

/** A first credential for a new account. */
export interface SignupCredential {
  /** True when this request body is for this credential type. */
  matches(body: RequestBody): boolean;
  /**
   * Validate (and e.g. hash, or verify a WebAuthn registration for
   * `signup.userId`) before the account exists. Return an error Response,
   * or `amr` for the session plus `attach`, run once the User DO exists.
   */
  prepare(
    c: AppContext,
    body: RequestBody,
    signup: VerifiedSignup,
  ): Promise<Response | { amr: string[]; attach(user: ReturnType<typeof userStub>): Promise<void> }>;
}

const passwordCredential: SignupCredential = {
  matches: (body) => typeof body.fields.password === 'string',
  async prepare(c, body) {
    const password = body.fields.password!;
    const problem = validatePasswordPolicy(password);
    if (problem) return apiError(c, 400, 'weak_password', PASSWORD_MESSAGES[problem] ?? PASSWORD_MESSAGES.too_short!);
    const hash = await hashPassword(password);
    return { amr: ['pwd'], attach: (user) => user.setPassword(hash) };
  },
};

/** Credential handlers for /signup/complete, tried in order. */
export const SIGNUP_CREDENTIALS: SignupCredential[] = [passwordCredential, passkeySignupCredential];

const SIGNUP_ID = /^sig_[0-9A-HJKMNP-TV-Z]{26}$/i;

const USERNAME_MESSAGES: Record<UsernameError, string> = {
  empty: 'Choose a username.',
  non_ascii: 'Usernames can only use letters, numbers, - and _.',
  invalid_format: 'Usernames are 3–30 characters: letters, numbers, - and _, starting with a letter or number.',
  reserved: "That username isn't available.",
};

const PASSWORD_MESSAGES: Record<string, string> = {
  too_short: `Use at least ${config.PASSWORD_MIN_LENGTH} characters.`,
  too_long: `Use at most ${config.PASSWORD_MAX_LENGTH} characters.`,
  invalid_unicode: 'That password contains characters we can’t store.',
};

const SIGNUP_FAILED = "We couldn't create your account. Please start again.";

export const signupRoutes = new Hono<AppEnv>();

signupRoutes.use('/signup/*', noStore);

signupRoutes.get('/signup', async (c) => {
  const returnTo = validateReturnTo(c.req.query('return_to'), c.env);
  if (await currentAccessToken(c)) return c.redirect(returnTo, 302);
  return renderPage(c, {
    title: 'Create an account',
    body: signupPage({
      returnTo,
      turnstileSiteKey: c.env.TURNSTILE_SITE_KEY,
      slots: { passkey: passkeySignupSlot(), social: socialLoginSlot(c.env, returnTo, 'Sign up') },
    }),
    scripts: [SIGNUP_JS, WEBAUTHN_JS, PASSKEY_SIGNUP_JS],
    turnstile: true,
  });
});

signupRoutes.post('/signup/start', async (c) => {
  const limited = await limitIp(c);
  if (limited) return limited;
  const body = await readBody(c);
  if (!body) return apiError(c, 400, 'bad_request', BAD_REQUEST);

  const username = validateUsername(body.fields.username ?? '');
  if (!username.ok) return apiError(c, 400, 'invalid_username', USERNAME_MESSAGES[username.reason]);
  const email = validateEmail(body.fields.email ?? '');
  if (!email.ok) return apiError(c, 400, 'invalid_email', 'Enter a valid email address.');

  const ip = clientIp(c.req.raw);
  const token = body.fields.turnstile || body.fields['cf-turnstile-response'];
  const turnstile = await verifyTurnstile(c.env, token, ip);
  if (!turnstile.ok) {
    return apiError(c, 403, 'turnstile_failed', 'Please complete the verification and try again.');
  }
  if (!(await checkIdentifier(c.env, email.norm))) return apiError(c, 429, 'rate_limited', RATE_LIMITED);

  const result = await indexStub(c.env).startSignup({ username: username.display, email: email.display, ip });
  if (result.ok) return c.json({ ok: true, signupId: result.signupId });
  switch (result.reason) {
    case 'username_taken':
      return apiError(c, 409, 'username_taken', 'That username is taken.');
    case 'rate_limited':
      return apiError(c, 429, 'rate_limited', 'Too many codes sent. Please try again later.', result.retryAfterMs);
    case 'invalid_email':
      return apiError(c, 400, 'invalid_email', 'Enter a valid email address.');
    default:
      return apiError(c, 400, 'invalid_username', USERNAME_MESSAGES.invalid_format);
  }
});

signupRoutes.post('/signup/verify', async (c) => {
  const limited = await limitIp(c);
  if (limited) return limited;
  const body = await readBody(c);
  const signupId = body?.fields.signupId ?? '';
  const code = (body?.fields.code ?? '').replace(/\s+/g, '');
  if (!SIGNUP_ID.test(signupId) || !code) return apiError(c, 400, 'bad_request', BAD_REQUEST);

  const result = await indexStub(c.env).verifySignup(signupId, code);
  if (result.ok) return c.json({ ok: true });
  switch (result.reason) {
    case 'expired':
      return apiError(c, 400, 'code_expired', 'That code has expired. Send a new one.');
    case 'too_many_attempts':
      return apiError(c, 400, 'too_many_attempts', 'Too many wrong codes. Send a new one.');
    default:
      return apiError(c, 400, 'invalid_code', "That code isn't right. Check the email and try again.");
  }
});

signupRoutes.post('/signup/complete', async (c) => {
  const limited = await limitIp(c);
  if (limited) return limited;
  const body = await readBody(c);
  const signupId = body?.fields.signupId ?? '';
  if (!body || !SIGNUP_ID.test(signupId)) return apiError(c, 400, 'bad_request', BAD_REQUEST);
  const credential = SIGNUP_CREDENTIALS.find((h) => h.matches(body));
  if (!credential) return apiError(c, 400, 'bad_request', BAD_REQUEST);

  const index = indexStub(c.env);
  const signup = await index.getVerifiedSignup(signupId);
  if (!signup) return apiError(c, 400, 'not_verified', 'Verify your email first, or start again.');

  const prepared = await credential.prepare(c, body, signup);
  if (prepared instanceof Response) return prepared;

  const created = await index.completeSignup(signupId);
  if (!created.ok) return apiError(c, 409, 'signup_failed', SIGNUP_FAILED);

  const user = userStub(c.env, created.userId);
  await prepared.attach(user);
  const session = await user.createSession({ amr: prepared.amr, ...requestInfo(c) });
  return completeLogin(c, created.userId, session, returnToFrom(c, body));
});
