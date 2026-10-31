/**
 * OpenID Connect provider (design §9): authorization code + PKCE (S256 only).
 *
 * GET  /authorize                 code flow; reuses the auth.bcnelson.dev session
 * POST /authorize/consent         { consent_token, decision: allow|deny }  (form; Origin-checked)
 * POST /oauth/token               authorization_code | refresh_token  (form; back-channel, no Origin check)
 * GET|POST /userinfo              Bearer client access token  (back-channel for POST)
 * GET  /logout                    RP-initiated logout: confirmation page
 * POST /logout/end-session        sign out, then back to a registered post_logout_redirect_uri
 *
 * Client auth at /oauth/token: client_secret_basic or client_secret_post for
 * confidential clients, none (client_id only) for public ones. Errors are
 * RFC 6749 §5.2 JSON `{ error, error_description }`.
 */

import { Hono } from 'hono';
import type { ContentfulStatusCode } from 'hono/utils/http-status';
import { config } from '../config';
import type { Env } from '../env';
import { clientIp, type AppContext, type AppEnv } from '../http';
import { readBody } from '../http/body';
import { verifyClientSecret, type OAuthClientRecord } from '../oidc/clients';
import { formatClientRefreshToken, formatCode, parseClientRefreshToken, parseCode, PKCE_PATTERN } from '../oidc/formats';
import { scopedClaims } from '../oidc/claims';
import { AUTH_AFTER_PARAM, parseAuthorizeRequest, redirectWith } from '../oidc/request';
import { signClientTokens, verifyClientAccessToken, verifyIdTokenHint } from '../oidc/tokens';
import type { AuthorizeRequest, IssuedGrant } from '../oidc/types';
import { consentPage, logoutConfirmPage, oidcErrorPage, signedOutPage } from '../pages/consent';
import { renderPage } from '../pages/layout';
import { connectedAppsSection } from '../pages/profile';
import { PROFILE_SLOTS } from './profile';
import { checkIp } from '../ratelimit';
import { clearSessionCookies, issueSession, readRefreshToken } from '../session';
import type { UserClaims } from '../types';
import { currentAccessToken, indexStub, ipLimitPosts, noStore, userStub } from './auth-common';

export const oidcRoutes = new Hono<AppEnv>();

/**
 * Back-channel endpoints called by client servers, not browsers: they carry
 * no cookies, so the global Origin check (CSRF) doesn't apply. app.ts skips
 * it for exactly these.
 */
export function isOidcBackChannel(method: string, path: string): boolean {
  return method.toUpperCase() === 'POST' && (path === '/oauth/token' || path === '/userinfo');
}

oidcRoutes.use('/authorize', noStore);
oidcRoutes.use('/authorize/*', noStore);
oidcRoutes.use('/logout/end-session', noStore);
// IP limit for the browser POSTs (/oauth/token checks it itself, in its error format).
oidcRoutes.use('/authorize/consent', ipLimitPosts);
oidcRoutes.use('/logout/end-session', ipLimitPosts);
oidcRoutes.use('/userinfo', ipLimitPosts);

// --- helpers ---------------------------------------------------------------------

interface BrowserSession {
  userId: string;
  sessionId: string;
  claims: UserClaims;
}

/**
 * The signed-in browser session: a valid bcn_at whose session is still live,
 * else the refresh cookie (rotated inline, cookies re-issued). Null when
 * signed out.
 */
async function browserSession(c: AppContext): Promise<BrowserSession | null> {
  const at = await currentAccessToken(c);
  if (at && typeof at.sub === 'string' && typeof at.sid === 'string') {
    const claims = await userStub(c.env, at.sub).getClaims(at.sid);
    if (claims && claims.sub === at.sub && claims.sid === at.sid) return { userId: at.sub, sessionId: at.sid, claims };
  }
  const parts = readRefreshToken(c);
  if (!parts) return null;
  const result = await userStub(c.env, parts.userId).refreshSession(parts.sessionId, parts.secret);
  if (!result.ok || result.claims.sub !== parts.userId || result.claims.sid !== parts.sessionId) {
    clearSessionCookies(c);
    return null;
  }
  await issueSession(c, parts.userId, { sessionId: parts.sessionId, secret: result.secret, claims: result.claims });
  return { userId: parts.userId, sessionId: parts.sessionId, claims: result.claims };
}

function getClient(env: Env, clientId: string): Promise<OAuthClientRecord | null> {
  return indexStub(env).getOAuthClient(clientId);
}

async function errorPage(c: AppContext, error: string, description: string): Promise<Response> {
  return renderPage(c, { title: 'Sign-in error', body: oidcErrorPage({ error, description }), status: 400 });
}

/** Redirect an authorization error to the (already validated) redirect URI. */
function redirectError(c: AppContext, redirectUri: string, state: string | undefined, error: string, description: string) {
  return c.redirect(redirectWith(redirectUri, { error, error_description: description, state, iss: c.env.ISSUER }), 302);
}

/** A rendered page whose forms may also land on `target`'s origin (browsers apply form-action to redirects). */
async function allowFormTarget(response: Response | Promise<Response>, target: string): Promise<Response> {
  const res = await response;
  const csp = res.headers.get('Content-Security-Policy');
  if (csp) res.headers.set('Content-Security-Policy', csp.replace("form-action 'self'", `form-action 'self' ${new URL(target).origin}`));
  return res;
}

/** True when the remembered grant covers every requested scope. */
function covered(granted: string[] | null, scopes: string[]): boolean {
  return granted !== null && scopes.every((s) => granted.includes(s));
}

/** Issue a code and send the browser back to the client. */
async function completeAuthorization(
  c: AppContext,
  session: BrowserSession,
  request: AuthorizeRequest,
  status: 302 | 303,
): Promise<Response> {
  const result = await userStub(c.env, session.userId).createOAuthCode({
    sessionId: session.sessionId,
    clientId: request.clientId,
    redirectUri: request.redirectUri,
    codeChallenge: request.codeChallenge,
    nonce: request.nonce,
    scopes: request.scopes,
  });
  if (!result.ok) {
    return redirectError(c, request.redirectUri, request.state, 'login_required', 'Your session ended. Please sign in again.');
  }
  const code = formatCode({ userId: session.userId, secret: result.secret });
  return c.redirect(redirectWith(request.redirectUri, { code, state: request.state, iss: c.env.ISSUER }), status);
}

/** /login (reauth=1 when forced) with a return_to that comes back here without forcing again. */
function loginRedirect(c: AppContext, params: URLSearchParams, forced: boolean, request: AuthorizeRequest): Response {
  const back = new URLSearchParams(params);
  const prompt = (back.get('prompt') ?? '').split(' ').filter((p) => p && p !== 'login');
  if (prompt.length) back.set('prompt', prompt.join(' '));
  else back.delete('prompt');
  if (forced) back.set(AUTH_AFTER_PARAM, String(Math.floor(Date.now() / 1000)));
  const returnTo = `${c.env.ISSUER}/authorize?${back.toString()}`;
  if (returnTo.length > config.MAX_RETURN_TO_LENGTH) {
    return redirectError(c, request.redirectUri, request.state, 'invalid_request', 'The authorization request is too long.');
  }
  return c.redirect(`/login?${forced ? 'reauth=1&' : ''}return_to=${encodeURIComponent(returnTo)}`, 302);
}

// --- authorize -----------------------------------------------------------------------

oidcRoutes.get('/authorize', async (c) => {
  const params = new URL(c.req.url).searchParams;
  const parsed = await parseAuthorizeRequest(params, (id) => getClient(c.env, id));
  if (!parsed.ok) {
    if (!parsed.redirect) return errorPage(c, parsed.error, parsed.description);
    return redirectError(c, parsed.redirectUri, parsed.state, parsed.error, parsed.description);
  }
  const { request, client } = parsed;
  const fail = (error: string, description: string) => redirectError(c, request.redirectUri, request.state, error, description);

  const session = await browserSession(c);
  if (!session) {
    if (request.prompt.none) return fail('login_required', 'The user is not signed in.');
    return loginRedirect(c, params, false, request);
  }
  const authTime = session.claims.auth_time;
  // bcn_auth_after (set by loginRedirect) both demands and satisfies a login after that time,
  // so prompt=login / max_age=0 don't loop once the user has signed in again.
  const fresh = request.authAfter !== undefined && authTime >= request.authAfter;
  const tooOld = request.maxAge !== undefined && Math.floor(Date.now() / 1000) - authTime > request.maxAge;
  if (!fresh && (request.prompt.login || tooOld || request.authAfter !== undefined)) {
    if (request.prompt.none) return fail('login_required', 'A fresh sign-in is required.');
    return loginRedirect(c, params, true, request);
  }

  const user = userStub(c.env, session.userId);
  const needConsent = request.prompt.consent || (!client.firstParty && !covered(await user.getOAuthGrant(client.clientId), request.scopes));
  if (needConsent) {
    if (request.prompt.none) return fail('consent_required', 'The user has not approved this application.');
    const { token } = await user.startOAuthConsent(session.sessionId, request);
    return allowFormTarget(renderPage(c, {
      title: `Allow ${client.name}?`,
      body: consentPage({
        clientName: client.name,
        clientHost: new URL(request.redirectUri).host,
        username: session.claims.preferred_username,
        scopes: request.scopes,
        consentToken: token,
      }),
    }), request.redirectUri);
  }
  return completeAuthorization(c, session, request, 302);
});

oidcRoutes.post('/authorize/consent', async (c) => {
  const body = await readBody(c);
  const session = await browserSession(c);
  if (!session) return errorPage(c, 'login_required', 'Your session ended. Go back to the application and try again.');
  const token = body?.fields.consent_token ?? '';
  const user = userStub(c.env, session.userId);
  const request = await user.takeOAuthConsent(token, session.sessionId);
  if (!request) return errorPage(c, 'invalid_request', 'This consent screen has expired. Go back to the application and try again.');
  const client = await getClient(c.env, request.clientId);
  if (!client || client.disabledAt !== null || !client.redirectUris.includes(request.redirectUri)) {
    return errorPage(c, 'invalid_client', 'This application is no longer registered.');
  }
  if (body?.fields.decision !== 'allow') {
    return c.redirect(redirectWith(request.redirectUri, {
      error: 'access_denied', error_description: 'The user declined.', state: request.state, iss: c.env.ISSUER,
    }), 303);
  }
  await user.saveOAuthGrant(client.clientId, request.scopes);
  return completeAuthorization(c, session, request, 303);
});

// --- token -------------------------------------------------------------------------------

function tokenError(c: AppContext, status: ContentfulStatusCode, error: string, description: string, basic = false): Response {
  // RFC 6749 §5.2: a 401 for a client that used the Authorization header names the scheme.
  if (status === 401 && basic) c.header('WWW-Authenticate', 'Basic realm="oauth"');
  return c.json({ error, error_description: description }, status);
}

/** Client credentials from Authorization: Basic (RFC 6749 §2.3.1: form-urlencoded id and secret). */
function basicCredentials(header: string | undefined): { id: string; secret: string } | null | 'malformed' {
  if (!header) return null;
  const match = /^Basic\s+([A-Za-z0-9+/=]+)$/i.exec(header.trim());
  if (!match) return header.trim().toLowerCase().startsWith('basic') ? 'malformed' : null;
  try {
    const decoded = atob(match[1]!);
    const i = decoded.indexOf(':');
    if (i < 0) return 'malformed';
    const unform = (s: string) => decodeURIComponent(s.replace(/\+/g, ' '));
    return { id: unform(decoded.slice(0, i)), secret: unform(decoded.slice(i + 1)) };
  } catch {
    return 'malformed';
  }
}

oidcRoutes.post('/oauth/token', async (c) => {
  c.header('Cache-Control', 'no-store');
  c.header('Pragma', 'no-cache');
  if (!(await checkIp(c.env, clientIp(c.req.raw) ?? 'unknown'))) {
    c.header('Retry-After', '60');
    return tokenError(c, 429, 'temporarily_unavailable', 'Too many requests. Try again in a minute.');
  }
  const type = (c.req.header('Content-Type') ?? '').split(';')[0]!.trim().toLowerCase();
  if (type !== 'application/x-www-form-urlencoded') {
    return tokenError(c, 400, 'invalid_request', 'Send application/x-www-form-urlencoded.');
  }
  const text = await c.req.text();
  if (text.length > config.OIDC_MAX_TOKEN_BODY) return tokenError(c, 400, 'invalid_request', 'The request is too large.');
  const params = new URLSearchParams(text);
  for (const key of new Set(params.keys())) {
    if (params.getAll(key).length > 1) return tokenError(c, 400, 'invalid_request', `${key} was given more than once.`);
  }

  // --- client authentication
  const basic = basicCredentials(c.req.header('Authorization'));
  if (basic === 'malformed') return tokenError(c, 401, 'invalid_client', 'Malformed client credentials.', true);
  const bodySecret = params.get('client_secret');
  if (basic && bodySecret !== null) return tokenError(c, 400, 'invalid_request', 'Use one client authentication method.');
  const bodyId = params.get('client_id');
  if (basic && bodyId !== null && bodyId !== basic.id) return tokenError(c, 401, 'invalid_client', 'client_id mismatch.', true);
  const clientId = basic?.id ?? bodyId ?? '';
  const secret = basic?.secret ?? bodySecret;
  const client = clientId && clientId.length <= 128 ? await getClient(c.env, clientId) : null;
  if (!client || client.disabledAt !== null) return tokenError(c, 401, 'invalid_client', 'Unknown or disabled client.', Boolean(basic));
  if (client.confidential) {
    if (secret === null || !(await verifyClientSecret(client, secret))) {
      return tokenError(c, 401, 'invalid_client', 'Client authentication failed.', Boolean(basic));
    }
  } else if (secret !== null && secret !== '') {
    return tokenError(c, 401, 'invalid_client', 'Public clients do not use a secret.', Boolean(basic));
  }

  const grantType = params.get('grant_type');
  if (grantType === 'authorization_code') return exchangeCode(c, client, params);
  if (grantType === 'refresh_token') return refreshClientToken(c, client, params);
  return tokenError(c, 400, 'unsupported_grant_type', 'Use authorization_code or refresh_token.');
});

async function exchangeCode(c: AppContext, client: OAuthClientRecord, params: URLSearchParams): Promise<Response> {
  const code = params.get('code');
  const redirectUri = params.get('redirect_uri');
  const verifier = params.get('code_verifier');
  if (!code || !redirectUri) return tokenError(c, 400, 'invalid_request', 'code and redirect_uri are required.');
  if (!verifier) return tokenError(c, 400, 'invalid_request', 'code_verifier is required (PKCE).');
  if (!PKCE_PATTERN.test(verifier)) return tokenError(c, 400, 'invalid_grant', 'code_verifier is malformed.');
  // No UserIndex hop: a forged code's User DO has no schema and answers 'invalid'
  // without writing storage (do/user.ts exists()).
  const parts = parseCode(code);
  if (!parts) {
    return tokenError(c, 400, 'invalid_grant', 'The authorization code is invalid.');
  }
  const result = await userStub(c.env, parts.userId).redeemOAuthCode({
    secret: parts.secret, clientId: client.clientId, redirectUri, codeVerifier: verifier,
  });
  if (!result.ok) {
    const description: Record<typeof result.reason, string> = {
      invalid: 'The authorization code is invalid.',
      expired: 'The authorization code has expired.',
      reuse: 'The authorization code was already used; tokens issued from it are revoked.',
      mismatch: 'The authorization code was issued to another client or redirect_uri.',
      pkce: 'PKCE verification failed.',
      session: 'The sign-in behind this code has ended.',
      disabled: 'The account is disabled.',
    };
    return tokenError(c, 400, 'invalid_grant', description[result.reason]);
  }
  return tokenResponse(c, client, parts.userId, result);
}

async function refreshClientToken(c: AppContext, client: OAuthClientRecord, params: URLSearchParams): Promise<Response> {
  if (!client.allowedScopes.includes('offline_access')) {
    return tokenError(c, 400, 'unauthorized_client', 'This client may not use refresh tokens.');
  }
  const parts = parseClientRefreshToken(params.get('refresh_token'));
  if (!parts) {
    return tokenError(c, 400, 'invalid_grant', 'The refresh token is invalid.');
  }
  const rawScope = params.get('scope');
  const scopes = rawScope === null ? undefined : rawScope.split(' ').filter(Boolean);
  const result = await userStub(c.env, parts.userId).refreshOAuthToken({
    tokenId: parts.tokenId, secret: parts.secret, clientId: client.clientId, scopes,
  });
  if (!result.ok) {
    if (result.reason === 'scope') return tokenError(c, 400, 'invalid_scope', 'The scope exceeds what was granted.');
    return tokenError(c, 400, 'invalid_grant', 'The refresh token is invalid, expired or revoked.');
  }
  return tokenResponse(c, client, parts.userId, result);
}

async function tokenResponse(c: AppContext, client: OAuthClientRecord, userId: string, grant: IssuedGrant): Promise<Response> {
  if (grant.claims.sub !== userId) return tokenError(c, 400, 'invalid_grant', 'The grant is invalid.');
  const signed = await signClientTokens(c.env, {
    clientId: client.clientId, claims: grant.claims, scopes: grant.scopes, tokenId: grant.tokenId, nonce: grant.nonce,
  });
  const body: Record<string, unknown> = {
    access_token: signed.accessToken,
    token_type: 'Bearer',
    expires_in: signed.expiresIn,
    id_token: signed.idToken,
    scope: grant.scopes.join(' '),
  };
  if (grant.refreshSecret) {
    body.refresh_token = formatClientRefreshToken({ userId, tokenId: grant.tokenId, secret: grant.refreshSecret });
  }
  return c.json(body, 200);
}

// --- userinfo ------------------------------------------------------------------------------

async function userinfo(c: AppContext): Promise<Response> {
  c.header('Cache-Control', 'no-store');
  const match = /^Bearer\s+([A-Za-z0-9._~+/=-]+)$/i.exec(c.req.header('Authorization')?.trim() ?? '');
  const deny = (error?: string) => {
    c.header('WWW-Authenticate', error ? `Bearer error="${error}"` : 'Bearer');
    return c.json(error ? { error } : { error: 'invalid_request' }, error === 'insufficient_scope' ? 403 : 401);
  };
  if (!match) return deny();
  const payload = await verifyClientAccessToken(c.env, match[1]!);
  if (!payload) return deny('invalid_token');
  const client = await getClient(c.env, payload.aud);
  if (!client || client.disabledAt !== null) return deny('invalid_token');
  const claims = await userStub(c.env, payload.sub).getOAuthTokenClaims(payload.gid, payload.sid, payload.aud);
  if (!claims || claims.sub !== payload.sub) return deny('invalid_token');
  const scopes = payload.scope.split(' ');
  if (!scopes.includes('openid')) return deny('insufficient_scope');
  return c.json(scopedClaims(claims, scopes));
}

oidcRoutes.get('/userinfo', userinfo);
oidcRoutes.post('/userinfo', userinfo);

// --- profile page: connected apps (PROFILE_SLOTS hook) -------------------------------------
// Revoke is POST /api/me/apps/:clientId/revoke (routes/me.ts, reauth). First-party
// clients skip consent, so they keep no grant and aren't listed; their tokens end
// with the browser session like every client's.

PROFILE_SLOTS.apps = async ({ c, user }) => {
  const grants = await userStub(c.env, user.sub).listOAuthGrants();
  if (grants.length === 0) return null;
  const clients = await Promise.all(grants.map((g) => getClient(c.env, g.clientId)));
  return {
    html: connectedAppsSection(grants.map((g, i) => ({
      clientId: g.clientId,
      name: clients[i]?.name ?? g.clientId,
      scopes: g.scopes,
      connectedAt: g.createdAt,
      disabled: !clients[i] || clients[i]!.disabledAt !== null,
    }))),
  };
};

// --- RP-initiated logout -----------------------------------------------------------------------

/** The post-logout redirect when it is registered for that (enabled) client; else undefined. */
async function postLogoutTarget(
  env: Env,
  clientId: string | undefined,
  uri: string | undefined,
): Promise<{ uri: string; client: OAuthClientRecord } | undefined> {
  if (!clientId || !uri) return undefined;
  const client = await getClient(env, clientId);
  if (!client || client.disabledAt !== null || !client.postLogoutRedirectUris.includes(uri)) return undefined;
  return { uri, client };
}

oidcRoutes.get('/logout', async (c) => {
  c.header('Cache-Control', 'no-store');
  const hintRaw = c.req.query('id_token_hint');
  const hint = hintRaw ? await verifyIdTokenHint(c.env, hintRaw) : null;
  const queryClient = c.req.query('client_id');
  // A hint and a client_id that disagree: trust neither for the redirect.
  const clientId = hint && queryClient && hint.aud !== queryClient ? undefined : (hint?.aud ?? queryClient);
  const target = await postLogoutTarget(c.env, clientId, c.req.query('post_logout_redirect_uri'));
  const rawState = c.req.query('state');
  const state = rawState !== undefined && rawState.length <= config.OIDC_MAX_PARAM_LENGTH ? rawState : undefined;

  const signedIn = Boolean(readRefreshToken(c)) || Boolean(await currentAccessToken(c));
  if (!signedIn) {
    if (target) return c.redirect(redirectWith(target.uri, { state }), 302);
    return renderPage(c, { title: 'Signed out', body: signedOutPage() });
  }
  const page = renderPage(c, {
    title: 'Sign out?',
    body: logoutConfirmPage({
      clientName: target?.client.name,
      postLogoutRedirectUri: target?.uri,
      state: target ? state : undefined,
      clientId: target?.client.clientId,
    }),
  });
  return target ? allowFormTarget(page, target.uri) : page;
});

oidcRoutes.post('/logout/end-session', async (c) => {
  const body = await readBody(c);
  const target = await postLogoutTarget(c.env, body?.fields.client_id, body?.fields.post_logout_redirect_uri);
  const parts = readRefreshToken(c);
  if (parts) await userStub(c.env, parts.userId).revokeSession(parts.sessionId, parts.secret);
  clearSessionCookies(c);
  const state = body?.fields.state;
  if (target) return c.redirect(redirectWith(target.uri, { state: state && state.length <= config.OIDC_MAX_PARAM_LENGTH ? state : undefined }), 303);
  return renderPage(c, { title: 'Signed out', body: signedOutPage() });
});
