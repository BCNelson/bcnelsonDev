/**
 * Social login + account linking (design §6.7), provider adapters in src/oauth/.
 *
 * GET  /oauth/:provider/start?return_to=&intent=login|link
 *   Signed state cookie (oauth/state.ts: state, PKCE verifier, intent,
 *   return_to; for link also userId + sessionId) → 302 to the provider.
 *   intent=link needs a recent login: no session → /refresh, stale → /login?reauth=1.
 * GET  /oauth/:provider/callback?code=&state=
 *   State checked in constant time against the cookie (which is cleared), code
 *   exchanged, then:
 *   - known identity, intent=login → sign in (amr oauth:<provider>) → 302 return_to
 *   - intent=link → same signed-in session as at start → identity attached → 302 return_to
 *   - unknown, verified provider email of an existing account → NOT linked:
 *     "sign in to link" page; a pending link (UserIndex, cookie handle) waits
 *     for that user at /oauth/social/link
 *   - unknown otherwise → social signup at /oauth/social/signup
 * GET  /oauth/social/link?return_to=        confirm page (signed in as the matched user, recent login)
 * POST /oauth/social/link        (form)     link it → 303 return_to
 * POST /oauth/social/link/cancel (form)     drop the offer → 303 return_to
 * GET  /oauth/social/signup?return_to=      choose a username (+ email code when unverified)
 * POST /oauth/social/signup/start    { username, email, turnstile } → { ok }           (unverified email)
 * POST /oauth/social/signup/verify   { code }                       → { ok }
 * POST /oauth/social/signup/complete { username?, return_to? }      → { ok, redirect }, cookies set
 * POST /oauth/social/unlink          { credentialId }               → { ok }  401/403 reauth, 409 last_method
 *
 * Pages answer errors with an error page; JSON endpoints use the apiError shape.
 * Providers with an empty client ID are 404 here and hidden on every page.
 * The OIDC provider shares the /oauth prefix (/oauth/token); everything here is
 * /oauth/<provider>/... or /oauth/social/....
 */

import { generateCodeVerifier, generateState } from 'arctic';
import { Hono } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import { config } from '../config';
import { timingSafeEqual } from '../crypto/hash';
import type { OAuthPendingData } from '../do/index/identities';
import type { Env } from '../env';
import { clientIp, validateReturnTo, type AppContext, type AppEnv } from '../http';
import { hasRecentAuth, liveSession, reauthRequiredResponse, reauthUrl, unauthorizedResponse } from '../http/auth';
import { readBody } from '../http/body';
import { verifyTurnstile } from '../http/turnstile';
import { validateEmail, validateUsername } from '../identifiers';
import { enabledProviders, getProvider, providerLabel, type OAuthProvider, type ProviderProfile } from '../oauth';
import { openState, sealState, type OAuthState } from '../oauth/state';
import { renderPage } from '../pages/layout';
import {
  OAUTH_MESSAGES,
  OAUTH_SIGNUP_JS,
  emailExistsPage,
  linkConfirmPage,
  oauthErrorPage,
  oauthSection,
  oauthSignupPage,
  socialButtons,
} from '../pages/oauth';
import { checkIdentifier, checkIp } from '../ratelimit';
import { isSecureRequest } from '../session';
import type { AccessTokenPayload } from '../tokens';
import {
  BAD_REQUEST,
  apiError,
  completeLogin,
  indexStub,
  limitIp,
  ipLimitPosts,
  noStore,
  requestInfo,
  returnToFrom,
  userStub,
} from './auth-common';
import { PROFILE_SLOTS } from './profile';

export const oauthRoutes = new Hono<AppEnv>();

oauthRoutes.use('/oauth/social/*', noStore);
oauthRoutes.use('/oauth/social/link/cancel', ipLimitPosts);

const CRED_ID = /^cred_[0-9A-HJKMNP-TV-Z]{26}$/;

// --- start -------------------------------------------------------------------

oauthRoutes.get('/oauth/:provider/start', async (c) => {
  const provider = getProvider(c.env, c.req.param('provider'));
  if (!provider) return notFound(c);
  const intent = c.req.query('intent') === 'link' ? 'link' : 'login';
  const rawReturnTo = c.req.query('return_to');
  const returnTo = validateReturnTo(rawReturnTo ?? (intent === 'link' ? profileUrl(c.env) : undefined), c.env);

  let link: { userId: string; sessionId: string } | undefined;
  if (intent === 'link') {
    const here = validateReturnTo(c.req.url, c.env);
    const auth = await signedIn(c);
    if (!auth) return c.redirect(`/refresh?return_to=${encodeURIComponent(here)}`, 302);
    if (!hasRecentAuth(auth.token)) return c.redirect(reauthUrl(c.env, here), 302);
    link = { userId: auth.userId, sessionId: auth.sessionId };
  }

  const state = generateState();
  const verifier = generateCodeVerifier();
  const url = await provider.authorizationUrl(c.env, state, verifier);
  const sealed = await sealState(c.env, {
    provider: provider.id,
    state,
    verifier,
    intent,
    returnTo,
    userId: link?.userId,
    sessionId: link?.sessionId,
    expiresAt: Date.now() + config.OAUTH_STATE_TTL,
  });
  setCookie(c, config.OAUTH_STATE_COOKIE, sealed, cookieOptions(c, config.OAUTH_STATE_TTL));
  c.header('Cache-Control', 'no-store');
  c.header('Referrer-Policy', 'no-referrer');
  return c.redirect(url.toString(), 302);
});

// --- callback ------------------------------------------------------------------

oauthRoutes.get('/oauth/:provider/callback', async (c) => {
  const provider = getProvider(c.env, c.req.param('provider'));
  if (!provider) return notFound(c);
  if (!(await checkIp(c.env, clientIp(c.req.raw) ?? 'unknown'))) return errorPage(c, 'rate_limited', 429);

  const cookie = getCookie(c, config.OAUTH_STATE_COOKIE);
  deleteCookie(c, config.OAUTH_STATE_COOKIE, cookieOptions(c));
  const st = await openState(c.env, cookie);
  const presented = c.req.query('state') ?? '';
  if (!st || st.provider !== provider.id || !timingSafeEqual(st.state, presented)) {
    return errorPage(c, 'state_invalid');
  }
  const code = c.req.query('code');
  if (c.req.query('error') || !code || code.length > config.MAX_FIELD_LENGTH) {
    return errorPage(c, 'provider_error', 400, st.returnTo);
  }

  let profile: ProviderProfile;
  try {
    profile = await provider.exchange(c.env, code, st.verifier);
  } catch (err) {
    console.error('oauth exchange failed', provider.id, String((err as Error)?.message ?? err).slice(0, 300));
    return errorPage(c, 'exchange_failed', 400, st.returnTo);
  }

  const index = indexStub(c.env);
  const owner = await index.findIdentity(provider.id, profile.subject);

  if (st.intent === 'link') return linkFromCallback(c, st, provider, profile, owner);
  if (owner) return loginExisting(c, owner, provider.id, profile.subject, st.returnTo);

  let emailVerified = Boolean(profile.email) && profile.emailVerified;
  const data: OAuthPendingData = { name: profile.name, picture: profile.picture, username: profile.username };
  if (emailVerified && profile.email) {
    const match = await index.emailMatch(profile.email);
    if (match.kind === 'active') {
      // Never auto-link: the account owner has to sign in and confirm.
      const pending = await index.putOAuthPending({
        kind: 'link', provider: provider.id, subject: profile.subject,
        email: profile.email, emailVerified: true, userId: match.userId, data,
      });
      setCookie(c, config.OAUTH_LINK_COOKIE, pending.handle, cookieOptions(c, config.OAUTH_LINK_TTL));
      const linkUrl = `${c.env.ISSUER}/oauth/social/link?return_to=${encodeURIComponent(st.returnTo)}`;
      return renderPage(c, {
        title: 'You already have an account',
        body: emailExistsPage({
          providerLabel: provider.label,
          email: profile.email,
          loginUrl: `/login?return_to=${encodeURIComponent(linkUrl)}`,
          cancelUrl: `/login?return_to=${encodeURIComponent(st.returnTo)}`,
        }),
      });
    }
    // A held address (recently removed from an account) can't be claimed now;
    // the code flow will refuse it the usual, non-revealing way.
    if (match.kind === 'held') emailVerified = false;
  }

  const pending = await index.putOAuthPending({
    kind: 'signup', provider: provider.id, subject: profile.subject,
    email: profile.email, emailVerified, data,
  });
  setCookie(c, config.OAUTH_SIGNUP_COOKIE, pending.handle, cookieOptions(c, config.OAUTH_SIGNUP_TTL));
  return c.redirect(`/oauth/social/signup?return_to=${encodeURIComponent(st.returnTo)}`, 302);
});

async function loginExisting(c: AppContext, userId: string, provider: string, subject: string, returnTo: string) {
  if (!(await indexStub(c.env).isActiveUser(userId))) return errorPage(c, 'exchange_failed', 400, returnTo);
  const result = await userStub(c.env, userId).loginWithOAuth(provider, subject, requestInfo(c));
  if (result.ok) return asRedirect(await completeLogin(c, userId, result.session, returnTo), returnTo);
  if (result.reason === 'disabled') return errorPage(c, 'account_disabled', 403, returnTo);
  return errorPage(c, 'exchange_failed', 400, returnTo);
}

async function linkFromCallback(
  c: AppContext,
  st: OAuthState,
  provider: OAuthProvider,
  profile: ProviderProfile,
  owner: string | null,
): Promise<Response> {
  const auth = await signedIn(c);
  if (!auth || auth.userId !== st.userId || auth.sessionId !== st.sessionId) {
    return errorPage(c, 'link_session_changed', 400, st.returnTo);
  }
  if (owner === auth.userId) return c.redirect(st.returnTo, 302);
  if (owner) return errorPage(c, 'identity_taken', 409, st.returnTo);
  const attached = await attachIdentity(c.env, auth.userId, provider.id, profile.subject, profile.email ?? null, credentialLabel(provider.label, profile.username, profile.email));
  if (!attached.ok) return errorPage(c, attached.reason, 409, st.returnTo);
  return c.redirect(st.returnTo, 302);
}

// --- pending link (email matched an existing account) -----------------------------

oauthRoutes.get('/oauth/social/link', async (c) => {
  const returnTo = validateReturnTo(c.req.query('return_to') ?? profileUrl(c.env), c.env);
  const handle = getCookie(c, config.OAUTH_LINK_COOKIE);
  const pending = handle ? await indexStub(c.env).getOAuthPending(handle, 'link') : null;
  if (!pending) return errorPage(c, 'link_expired', 400, returnTo);
  const here = validateReturnTo(c.req.url, c.env);
  const auth = await signedIn(c);
  if (!auth) return c.redirect(`/login?return_to=${encodeURIComponent(here)}`, 302);
  if (!hasRecentAuth(auth.token)) return c.redirect(reauthUrl(c.env, here), 302);
  if (auth.userId !== pending.userId) return errorPage(c, 'link_expired', 400, returnTo);
  return renderPage(c, {
    title: `Link ${providerLabel(pending.provider)}`,
    body: linkConfirmPage({
      providerLabel: providerLabel(pending.provider),
      email: pending.email,
      username: auth.username,
      returnTo,
    }),
  });
});

oauthRoutes.post('/oauth/social/link', async (c) => {
  const body = await readBody(c);
  const returnTo = returnToFrom(c, body);
  if (!(await checkIp(c.env, clientIp(c.req.raw) ?? 'unknown'))) return errorPage(c, 'rate_limited', 429, returnTo);
  const handle = getCookie(c, config.OAUTH_LINK_COOKIE) ?? '';
  const auth = await signedIn(c);
  const confirmUrl = `${c.env.ISSUER}/oauth/social/link?return_to=${encodeURIComponent(returnTo)}`;
  if (!auth || !hasRecentAuth(auth.token)) return c.redirect(reauthUrl(c.env, confirmUrl), 303);
  const index = indexStub(c.env);
  const pending = await index.consumeOAuthLink(handle, auth.userId);
  if (!pending) return errorPage(c, 'link_expired', 400, returnTo);
  deleteCookie(c, config.OAUTH_LINK_COOKIE, cookieOptions(c));
  const label = credentialLabel(providerLabel(pending.provider), pending.data.username, pending.email ?? undefined);
  const attached = await attachIdentity(c.env, auth.userId, pending.provider, pending.subject, pending.email, label);
  if (!attached.ok) return errorPage(c, attached.reason, 409, returnTo);
  return c.redirect(returnTo, 303);
});

oauthRoutes.post('/oauth/social/link/cancel', async (c) => {
  const body = await readBody(c);
  const returnTo = returnToFrom(c, body);
  const handle = getCookie(c, config.OAUTH_LINK_COOKIE);
  if (handle) await indexStub(c.env).deleteOAuthPending(handle);
  deleteCookie(c, config.OAUTH_LINK_COOKIE, cookieOptions(c));
  return c.redirect(returnTo, 303);
});

// --- social signup -------------------------------------------------------------

oauthRoutes.get('/oauth/social/signup', async (c) => {
  const returnTo = validateReturnTo(c.req.query('return_to'), c.env);
  const handle = getCookie(c, config.OAUTH_SIGNUP_COOKIE);
  const pending = handle ? await indexStub(c.env).getOAuthPending(handle, 'signup') : null;
  if (!pending) return errorPage(c, 'signup_expired', 400, returnTo);
  const suggestion = pending.username ?? pending.data.username ?? '';
  return renderPage(c, {
    title: 'Create your account',
    body: oauthSignupPage({
      providerLabel: providerLabel(pending.provider),
      email: pending.email,
      emailVerified: pending.emailVerified,
      usernameSuggestion: validateUsername(suggestion).ok ? suggestion : '',
      returnTo,
      turnstileSiteKey: c.env.TURNSTILE_SITE_KEY,
    }),
    scripts: [OAUTH_SIGNUP_JS],
    turnstile: !pending.emailVerified,
  });
});

oauthRoutes.post('/oauth/social/signup/start', async (c) => {
  const limited = await limitIp(c);
  if (limited) return limited;
  const body = await readBody(c);
  const handle = getCookie(c, config.OAUTH_SIGNUP_COOKIE);
  if (!body || !handle) return apiError(c, 400, 'bad_request', BAD_REQUEST);
  const username = validateUsername(body.fields.username ?? '');
  if (!username.ok) return apiError(c, 400, 'invalid_username', OAUTH_MESSAGES.invalid_username!);
  const email = validateEmail(body.fields.email ?? '');
  if (!email.ok) return apiError(c, 400, 'invalid_email', OAUTH_MESSAGES.invalid_email!);
  const ip = clientIp(c.req.raw);
  const turnstile = await verifyTurnstile(c.env, body.fields.turnstile || body.fields['cf-turnstile-response'], ip);
  if (!turnstile.ok) return apiError(c, 403, 'turnstile_failed', OAUTH_MESSAGES.turnstile_failed!);
  if (!(await checkIdentifier(c.env, email.norm))) return apiError(c, 429, 'rate_limited', OAUTH_MESSAGES.rate_limited!);
  const result = await indexStub(c.env).startOAuthSignup(handle, { username: username.display, email: email.display, ip });
  if (result.ok) return c.json({ ok: true, verified: result.verified });
  return startError(c, result.reason, result.retryAfterMs);
});

oauthRoutes.post('/oauth/social/signup/verify', async (c) => {
  const limited = await limitIp(c);
  if (limited) return limited;
  const body = await readBody(c);
  const handle = getCookie(c, config.OAUTH_SIGNUP_COOKIE);
  const code = (body?.fields.code ?? '').replace(/\s+/g, '');
  if (!handle || !code) return apiError(c, 400, 'bad_request', BAD_REQUEST);
  const result = await indexStub(c.env).verifyOAuthSignup(handle, code);
  if (result.ok) return c.json({ ok: true });
  switch (result.reason) {
    case 'not_found':
      return apiError(c, 400, 'signup_expired', OAUTH_MESSAGES.signup_expired!);
    case 'expired':
      return apiError(c, 400, 'code_expired', OAUTH_MESSAGES.code_expired!);
    case 'too_many_attempts':
      return apiError(c, 400, 'too_many_attempts', OAUTH_MESSAGES.too_many_attempts!);
    default:
      return apiError(c, 400, 'invalid_code', OAUTH_MESSAGES.invalid_code!);
  }
});

oauthRoutes.post('/oauth/social/signup/complete', async (c) => {
  const limited = await limitIp(c);
  if (limited) return limited;
  const body = await readBody(c);
  const handle = getCookie(c, config.OAUTH_SIGNUP_COOKIE);
  if (!body || !handle) return apiError(c, 400, 'bad_request', BAD_REQUEST);
  const index = indexStub(c.env);
  const pending = await index.getOAuthPending(handle, 'signup');
  if (!pending) return apiError(c, 400, 'signup_expired', OAUTH_MESSAGES.signup_expired!);

  if (pending.emailVerified) {
    // One step: reserve the username (already verified by the provider), then create.
    const username = validateUsername(body.fields.username ?? '');
    if (!username.ok) return apiError(c, 400, 'invalid_username', OAUTH_MESSAGES.invalid_username!);
    const started = await index.startOAuthSignup(handle, { username: username.display, ip: clientIp(c.req.raw) });
    if (!started.ok) return startError(c, started.reason, started.retryAfterMs);
  } else if (!pending.signupVerified) {
    return apiError(c, 400, 'not_verified', OAUTH_MESSAGES.not_verified!);
  }

  const created = await index.completeOAuthSignup(handle);
  if (!created.ok) {
    if (created.reason === 'not_verified') return apiError(c, 400, 'not_verified', OAUTH_MESSAGES.not_verified!);
    if (created.reason === 'not_found') return apiError(c, 400, 'signup_expired', OAUTH_MESSAGES.signup_expired!);
    return apiError(c, 409, 'signup_failed', OAUTH_MESSAGES.signup_failed!);
  }
  deleteCookie(c, config.OAUTH_SIGNUP_COOKIE, cookieOptions(c));

  const user = userStub(c.env, created.userId);
  const label = credentialLabel(providerLabel(created.provider), created.data.username, created.providerEmail ?? undefined);
  const added = await user.addOAuthCredential({
    provider: created.provider, subject: created.subject, email: created.providerEmail, label,
  });
  if (!added.ok) throw new Error(`social signup credential not stored: ${added.reason}`);
  if (created.data.name || created.data.picture) {
    // Best effort: a provider name/avatar our profile rules reject is just skipped.
    const update = await user.updateProfile({ name: created.data.name, picture: created.data.picture });
    if (!update.ok && created.data.name) await user.updateProfile({ name: created.data.name });
  }
  const session = await user.createSession({ amr: [`oauth:${created.provider}`], ...requestInfo(c) });
  return completeLogin(c, created.userId, session, returnToFrom(c, body));
});

// --- unlink (profile page) -------------------------------------------------------

oauthRoutes.post('/oauth/social/unlink', async (c) => {
  const limited = await limitIp(c);
  if (limited) return limited;
  const body = await readBody(c);
  const credentialId = body?.fields.credentialId ?? '';
  if (!CRED_ID.test(credentialId)) return apiError(c, 400, 'bad_request', BAD_REQUEST);
  const auth = await signedIn(c);
  if (!auth) return unauthorizedResponse(c);
  if (!hasRecentAuth(auth.token)) return reauthRequiredResponse(c, profileUrl(c.env));
  const result = await userStub(c.env, auth.userId).unlinkOAuth(credentialId);
  if (!result.ok) {
    if (result.reason === 'last_method') return apiError(c, 409, 'last_method', OAUTH_MESSAGES.last_method!);
    return apiError(c, 404, 'not_found', OAUTH_MESSAGES.not_found!);
  }
  await indexStub(c.env).releaseIdentity(result.provider, result.subject, auth.userId);
  return c.json({ ok: true });
});

// --- profile page (PROFILE_SLOTS hook) ------------------------------------------

PROFILE_SLOTS.social = async ({ c, user }) => {
  const linked = await userStub(c.env, user.sub).listOAuthCredentials();
  const providers = enabledProviders(c.env);
  if (linked.length === 0 && providers.length === 0) return null;
  return {
    html: oauthSection(
      linked.map((l) => ({ ...l, providerLabel: providerLabel(l.provider) })),
      providers.map((p) => ({ id: p.id, label: p.label })),
      profileUrl(c.env),
    ),
  };
};

// --- /login and /signup slot -------------------------------------------------------

/** Provider links for the /login (verb "Continue") or /signup ("Sign up") social slot. */
export function socialLoginSlot(env: Env, returnTo: string, verb?: string) {
  return socialButtons(enabledProviders(env).map((p) => ({ id: p.id, label: p.label })), returnTo, verb);
}

// --- helpers -------------------------------------------------------------------------

interface SignedIn {
  userId: string;
  sessionId: string;
  username: string;
  token: AccessTokenPayload;
}

/** A valid bcn_at for a live session (not revoked, account not disabled), else null. */
async function signedIn(c: AppContext): Promise<SignedIn | null> {
  const live = await liveSession(c);
  if (!live || typeof live.token.auth_time !== 'number') return null;
  return { userId: live.token.sub, sessionId: live.token.sid, username: live.claims.preferred_username, token: live.token };
}

/**
 * Claim the identity in the UserIndex (uniqueness across accounts), then
 * store the credential on the User DO; undo the claim if that fails.
 */
async function attachIdentity(
  env: Env,
  userId: string,
  provider: string,
  subject: string,
  email: string | null,
  label: string,
): Promise<{ ok: true } | { ok: false; reason: 'identity_taken' | 'too_many' }> {
  const index = indexStub(env);
  const claim = await index.claimIdentity({ provider, subject, userId });
  if (!claim.ok) return { ok: false, reason: claim.reason === 'taken' ? 'identity_taken' : 'too_many' };
  const added = await userStub(env, userId).addOAuthCredential({ provider, subject, email, label });
  if (!added.ok && added.reason !== 'duplicate') {
    await index.releaseIdentity(provider, subject, userId);
    return { ok: false, reason: 'too_many' };
  }
  return { ok: true };
}

function credentialLabel(providerName: string, username?: string, email?: string): string {
  const who = username ?? email;
  return who ? `${providerName} (${who})` : providerName;
}

function profileUrl(env: Env): string {
  return `${env.ISSUER}/profile`;
}

/** Cookies for the social flow: HttpOnly, Path=/oauth, SameSite=Lax (the provider redirect is top-level). */
function cookieOptions(c: AppContext, maxAgeMs?: number) {
  return {
    path: '/oauth',
    httpOnly: true,
    secure: isSecureRequest(c),
    sameSite: 'Lax' as const,
    ...(maxAgeMs !== undefined ? { maxAge: Math.floor(maxAgeMs / 1000) } : {}),
  };
}

/** completeLogin answers JSON for non-form requests; a GET callback needs a redirect with the same cookies. */
function asRedirect(res: Response, returnTo: string): Response {
  if (res.status !== 200) return res;
  const headers = new Headers(res.headers);
  headers.delete('Content-Type');
  headers.delete('Content-Length');
  headers.set('Location', returnTo);
  headers.set('Cache-Control', 'no-store');
  return new Response(null, { status: 302, headers });
}

function errorPage(c: AppContext, code: string, status: 400 | 403 | 404 | 409 | 429 = 400, returnTo?: string) {
  const rt = returnTo ?? validateReturnTo(undefined, c.env);
  return renderPage(c, {
    title: "Couldn't sign you in",
    body: oauthErrorPage(code, `/login?return_to=${encodeURIComponent(rt)}`),
    status: status as 400,
  });
}

function notFound(c: AppContext) {
  return c.json({ error: 'not_found' }, 404);
}

function startError(c: AppContext, reason: string, retryAfterMs?: number): Response {
  switch (reason) {
    case 'not_found':
      return apiError(c, 400, 'signup_expired', OAUTH_MESSAGES.signup_expired!);
    case 'username_taken':
      return apiError(c, 409, 'username_taken', OAUTH_MESSAGES.username_taken!);
    case 'email_taken':
      return apiError(c, 409, 'email_taken', OAUTH_MESSAGES.email_taken!);
    case 'rate_limited':
      return apiError(c, 429, 'rate_limited', OAUTH_MESSAGES.rate_limited!, retryAfterMs);
    case 'invalid_email':
      return apiError(c, 400, 'invalid_email', OAUTH_MESSAGES.invalid_email!);
    default:
      return apiError(c, 400, 'invalid_username', OAUTH_MESSAGES.invalid_username!);
  }
}
