import { createLocalJWKSet, decodeJwt, decodeProtectedHeader, jwtVerify } from 'jose';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { config } from '../src/config';
import { sha256Base64url } from '../src/crypto/hash';
import type { Env } from '../src/env';
import { newClientSecret } from '../src/oidc/clients';
import { atHash } from '../src/oidc/tokens';
import { getJwks, resetKeyCache, verifyAccessToken } from '../src/tokens';
import { lastCode, makeFakeEnv, type FakeEnv } from './do/fake-env';

vi.mock('cloudflare:workers', async () => ({
  DurableObject: (await import('./do/fake-storage')).FakeDurableObject,
}));
vi.mock('../src/crypto/password', async () => (await import('./do/fake-env')).fakePasswordModule());

const { User } = await import('../src/do/user');
const { UserIndex } = await import('../src/do/user-index');
const { createApp } = await import('../src/app');

const ORIGIN = 'https://auth.bcnelson.dev';
const APP = 'https://app.example.com';
const REDIRECT = `${APP}/callback`;
const LOGOUT_REDIRECT = `${APP}/signed-out`;
const VERIFIER = 'v'.repeat(20) + '-._~' + 'A1b2C3d4E5f6G7h8I9j0K';
const app = createApp();

let keyJson: string;
beforeAll(async () => {
  const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
  const jwk = (await crypto.subtle.exportKey('jwk', pair.privateKey)) as JsonWebKey;
  keyJson = JSON.stringify({ kty: 'OKP', crv: 'Ed25519', x: jwk.x, d: jwk.d, kid: 'k1' });
  vi.stubGlobal('fetch', vi.fn(async (_url: unknown, init?: RequestInit) => {
    const token = (init?.body as FormData).get('response');
    return Response.json({ success: token === 'good' });
  }));
});
afterAll(() => {
  vi.unstubAllGlobals();
  resetKeyCache();
});

let fake: FakeEnv;
beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(1_800_000_000_000);
  fake = makeFakeEnv({ User, UserIndex }, { AUTH_SIGNING_KEY_DEV: keyJson, ADMIN_EMAILS: 'admin@example.com' } as Partial<Env>);
});
afterEach(() => {
  vi.useRealTimers();
});

// --- helpers -----------------------------------------------------------------------

interface Account {
  userId: string;
  cookie: string;
  at: string;
  rt: string;
}

function cookieMap(res: Response): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of res.headers.getSetCookie()) {
    const [pair] = line.split(';');
    const i = pair!.indexOf('=');
    out[pair!.slice(0, i)] = pair!.slice(i + 1);
  }
  return out;
}

function account(res: Response): Account {
  const set = cookieMap(res);
  const at = set[config.ACCESS_COOKIE]!;
  const rt = set[config.REFRESH_COOKIE]!;
  return { userId: decodeJwt(at).sub!, at, rt, cookie: `${config.ACCESS_COOKIE}=${at}; ${config.REFRESH_COOKIE}=${rt}` };
}

function post(path: string, data: unknown, cookie?: string, origin: string | null = ORIGIN) {
  const headers: Record<string, string> = { 'Content-Type': 'application/json', 'CF-Connecting-IP': '1.2.3.4' };
  if (origin) headers.Origin = origin;
  if (cookie) headers.Cookie = cookie;
  return app.request(`${ORIGIN}${path}`, { method: 'POST', headers, body: JSON.stringify(data) }, fake.env);
}

function postForm(path: string, data: Record<string, string>, opts: { cookie?: string; origin?: string | null; auth?: string } = {}) {
  const headers: Record<string, string> = { 'Content-Type': 'application/x-www-form-urlencoded', 'CF-Connecting-IP': '1.2.3.4' };
  const origin = opts.origin === undefined ? ORIGIN : opts.origin;
  if (origin) headers.Origin = origin;
  if (opts.cookie) headers.Cookie = opts.cookie;
  if (opts.auth) headers.Authorization = opts.auth;
  return app.request(`${ORIGIN}${path}`, { method: 'POST', headers, body: new URLSearchParams(data).toString() }, fake.env);
}

function get(path: string, cookie?: string, headers: Record<string, string> = {}) {
  return app.request(`${ORIGIN}${path}`, { headers: { ...headers, ...(cookie ? { Cookie: cookie } : {}) } }, fake.env);
}

async function signUp(username: string, email: string, password = 'correct-horse'): Promise<Account> {
  const start = await post('/signup/start', { username, email, turnstile: 'good' });
  const { signupId } = (await start.json()) as { signupId: string };
  await post('/signup/verify', { signupId, code: lastCode(fake.mail) });
  const res = await post('/signup/complete', { signupId, password });
  expect(res.status).toBe(200);
  return account(res);
}

function index() {
  return fake.env.USER_INDEX.get(fake.env.USER_INDEX.idFromName('index'));
}

interface TestClient {
  clientId: string;
  secret?: string;
}

async function registerClient(opts: {
  clientId?: string;
  confidential?: boolean;
  firstParty?: boolean;
  scopes?: string[];
  redirectUris?: string[];
} = {}): Promise<TestClient> {
  const confidential = opts.confidential ?? true;
  const secret = confidential ? await newClientSecret() : null;
  const clientId = opts.clientId ?? 'example-app';
  const result = await index().createOAuthClient({
    clientId,
    name: 'Example App',
    redirectUris: opts.redirectUris ?? [REDIRECT],
    postLogoutRedirectUris: [LOGOUT_REDIRECT],
    allowedScopes: opts.scopes ?? ['openid', 'profile', 'email', 'roles', 'offline_access'],
    firstParty: opts.firstParty ?? false,
    confidential,
    secretHash: secret?.hash ?? null,
  });
  expect(result.ok).toBe(true);
  return { clientId, secret: secret?.secret };
}

async function challenge(verifier = VERIFIER): Promise<string> {
  return sha256Base64url(verifier);
}

async function authorizeUrl(client: TestClient, extra: Record<string, string> = {}): Promise<string> {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: client.clientId,
    redirect_uri: REDIRECT,
    scope: 'openid profile email offline_access',
    state: 'st-123',
    nonce: 'n-456',
    code_challenge: await challenge(),
    code_challenge_method: 'S256',
    ...extra,
  });
  return `/authorize?${params.toString()}`;
}

function location(res: Response): URL {
  const loc = res.headers.get('Location');
  expect(loc).toBeTruthy();
  return new URL(loc!, ORIGIN);
}

function basic(client: TestClient): string {
  return `Basic ${btoa(`${encodeURIComponent(client.clientId)}:${encodeURIComponent(client.secret ?? '')}`)}`;
}

/** Authorize (consenting if asked) and return the code from the redirect. */
async function getCode(client: TestClient, user: Account, extra: Record<string, string> = {}): Promise<string> {
  let res = await get(await authorizeUrl(client, extra), user.cookie);
  if (res.status === 200) {
    const page = await res.text();
    const token = /name="consent_token" value="([^"]+)"/.exec(page)![1]!;
    res = await postForm('/authorize/consent', { consent_token: token, decision: 'allow' }, { cookie: user.cookie });
    expect(res.status).toBe(303);
  } else {
    expect(res.status).toBe(302);
  }
  const loc = location(res);
  expect(loc.origin + loc.pathname).toBe(REDIRECT);
  expect(loc.searchParams.get('state')).toBe(extra.state ?? 'st-123');
  expect(loc.searchParams.get('iss')).toBe(ORIGIN);
  const code = loc.searchParams.get('code');
  expect(code).toMatch(/^ac1\.usr_/);
  return code!;
}

function exchange(client: TestClient, code: string, extra: Record<string, string> = {}, useBasic = true) {
  const data: Record<string, string> = { grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: VERIFIER, ...extra };
  if (!useBasic) {
    data.client_id = client.clientId;
    if (client.secret) data.client_secret = client.secret;
  }
  return postForm('/oauth/token', data, { origin: null, auth: useBasic && client.secret ? basic(client) : undefined });
}

function refresh(client: TestClient, refreshToken: string, extra: Record<string, string> = {}) {
  return postForm('/oauth/token', { grant_type: 'refresh_token', refresh_token: refreshToken, ...extra }, {
    origin: null, auth: basic(client),
  });
}

function userinfo(accessToken: string) {
  return get('/userinfo', undefined, { Authorization: `Bearer ${accessToken}` });
}

async function json(res: Response): Promise<any> {
  return res.json();
}

// --- tests -------------------------------------------------------------------------

describe('OIDC code flow', () => {
  it('authorize → consent → code → token → userinfo → refresh rotation', async () => {
    const client = await registerClient();
    const bob = await signUp('Bob', 'bob@example.com');

    // Consent page for a third-party client: no inline scripts, form-action allows the client.
    const page = await get(await authorizeUrl(client), bob.cookie);
    expect(page.status).toBe(200);
    expect(page.headers.get('Cache-Control')).toBe('no-store');
    expect(page.headers.get('Content-Security-Policy')).toContain(`form-action 'self' ${APP}`);
    const html = await page.text();
    expect(html).toContain('Example App');
    expect(html).toContain('See your primary email address');
    expect(html).not.toMatch(/<script>(?!<\/script>)/);

    const code = await getCode(client, bob);
    const res = await exchange(client, code);
    expect(res.status).toBe(200);
    expect(res.headers.get('Cache-Control')).toBe('no-store');
    const tokens = await json(res);
    expect(tokens).toMatchObject({
      token_type: 'Bearer', expires_in: config.OIDC_ACCESS_TOKEN_TTL / 1000, scope: 'openid profile email offline_access',
    });
    expect(tokens.refresh_token).toMatch(/^crt1\.usr_[^.]+\.otk_[^.]+\.[A-Za-z0-9_-]{43}$/);

    // Access token: aud = client, typ at+jwt, never accepted as the site cookie token.
    expect(decodeProtectedHeader(tokens.access_token).typ).toBe('at+jwt');
    const at = decodeJwt(tokens.access_token);
    expect(at).toMatchObject({ iss: ORIGIN, aud: client.clientId, sub: bob.userId, client_id: client.clientId, scope: tokens.scope });
    await expect(verifyAccessToken(fake.env, tokens.access_token)).rejects.toThrow();

    // ID token: signed by our JWKS, aud = client, nonce, at_hash, sid, auth_time, scoped claims.
    const { payload: id } = await jwtVerify(tokens.id_token, createLocalJWKSet(await getJwks(fake.env)), {
      issuer: ORIGIN, audience: client.clientId,
    });
    expect(id).toMatchObject({
      sub: bob.userId, nonce: 'n-456', azp: client.clientId, sid: decodeJwt(bob.at).sid,
      auth_time: decodeJwt(bob.at).auth_time, preferred_username: 'Bob', email: 'bob@example.com', email_verified: true,
    });
    expect(id.at_hash).toBe(await atHash(tokens.access_token));
    expect(id.roles).toBeUndefined();

    let info = await userinfo(tokens.access_token);
    expect(info.status).toBe(200);
    expect(await json(info)).toEqual({ sub: bob.userId, preferred_username: 'Bob', email: 'bob@example.com', email_verified: true });

    // POST /userinfo works without an Origin (back channel).
    info = await app.request(`${ORIGIN}/userinfo`, { method: 'POST', headers: { Authorization: `Bearer ${tokens.access_token}` } }, fake.env);
    expect(info.status).toBe(200);

    // Refresh rotates; the old refresh token is then reuse and kills the grant.
    const r1 = await refresh(client, tokens.refresh_token);
    expect(r1.status).toBe(200);
    const t2 = await json(r1);
    expect(t2.refresh_token).not.toBe(tokens.refresh_token);
    expect(decodeJwt(t2.id_token).nonce).toBeUndefined();
    expect((await userinfo(t2.access_token)).status).toBe(200);

    const replay = await refresh(client, tokens.refresh_token);
    expect(replay.status).toBe(400);
    expect(await json(replay)).toMatchObject({ error: 'invalid_grant' });
    expect((await refresh(client, t2.refresh_token)).status).toBe(400);
    expect((await userinfo(t2.access_token)).status).toBe(401);
  });

  it('remembers consent; a wider scope asks again; deny returns access_denied', async () => {
    const client = await registerClient();
    const bob = await signUp('Bob', 'bob@example.com');
    await getCode(client, bob, { scope: 'openid profile' });
    // Same scopes: straight back with a code.
    const again = await get(await authorizeUrl(client, { scope: 'openid profile' }), bob.cookie);
    expect(again.status).toBe(302);
    expect(location(again).searchParams.get('code')).toBeTruthy();
    // Wider scope: consent again; deny.
    const wider = await get(await authorizeUrl(client, { scope: 'openid profile email' }), bob.cookie);
    expect(wider.status).toBe(200);
    const token = /name="consent_token" value="([^"]+)"/.exec(await wider.text())![1]!;
    const denied = await postForm('/authorize/consent', { consent_token: token, decision: 'deny' }, { cookie: bob.cookie });
    expect(denied.status).toBe(303);
    expect(Object.fromEntries(location(denied).searchParams)).toMatchObject({ error: 'access_denied', state: 'st-123', iss: ORIGIN });
    // The consent token is single use.
    const reused = await postForm('/authorize/consent', { consent_token: token, decision: 'allow' }, { cookie: bob.cookie });
    expect(reused.status).toBe(400);
  });

  it('consent POST needs an allowed Origin and the same browser session', async () => {
    const client = await registerClient();
    const bob = await signUp('Bob', 'bob@example.com');
    const eve = await signUp('Eve', 'eve@example.com');
    const page = await get(await authorizeUrl(client), bob.cookie);
    const token = /name="consent_token" value="([^"]+)"/.exec(await page.text())![1]!;
    const cross = await postForm('/authorize/consent', { consent_token: token, decision: 'allow' }, { cookie: bob.cookie, origin: APP });
    expect(cross.status).toBe(403);
    const other = await postForm('/authorize/consent', { consent_token: token, decision: 'allow' }, { cookie: eve.cookie });
    expect(other.status).toBe(400);
  });

  it('first-party clients skip consent; public clients use PKCE without a secret', async () => {
    const client = await registerClient({ clientId: 'bcnelson-notes', firstParty: true, confidential: false });
    const bob = await signUp('Bob', 'bob@example.com');
    const res = await get(await authorizeUrl(client), bob.cookie);
    expect(res.status).toBe(302);
    const code = location(res).searchParams.get('code')!;
    const tokens = await exchange(client, code, {}, false);
    expect(tokens.status).toBe(200);
  });

  it('client_secret_post works for confidential clients', async () => {
    const client = await registerClient();
    const bob = await signUp('Bob', 'bob@example.com');
    const code = await getCode(client, bob);
    expect((await exchange(client, code, {}, false)).status).toBe(200);
  });
});

describe('authorize errors', () => {
  it('unknown client or unregistered redirect_uri: error page, no redirect', async () => {
    const client = await registerClient();
    const bob = await signUp('Bob', 'bob@example.com');
    let res = await get(await authorizeUrl(client, { redirect_uri: `${APP}/evil` }), bob.cookie);
    expect(res.status).toBe(400);
    expect(res.headers.get('Location')).toBeNull();
    expect(await res.text()).toContain('not registered');
    res = await get(await authorizeUrl({ clientId: 'nope' }), bob.cookie);
    expect(res.status).toBe(400);
    // Prefix / trailing-slash variants don't match either.
    res = await get(await authorizeUrl(client, { redirect_uri: `${REDIRECT}/` }), bob.cookie);
    expect(res.status).toBe(400);
  });

  it('later errors redirect with error, state and iss', async () => {
    const client = await registerClient();
    const bob = await signUp('Bob', 'bob@example.com');
    const cases: [Record<string, string>, string][] = [
      [{ response_type: 'token' }, 'unsupported_response_type'],
      [{ scope: 'profile email' }, 'invalid_scope'],
      [{ code_challenge_method: 'plain' }, 'invalid_request'],
      [{ code_challenge: '' }, 'invalid_request'],
      [{ prompt: 'none login' }, 'invalid_request'],
      [{ max_age: 'abc' }, 'invalid_request'],
    ];
    for (const [extra, error] of cases) {
      const res = await get(await authorizeUrl(client, extra), bob.cookie);
      expect(res.status).toBe(302);
      const loc = location(res);
      expect(loc.origin + loc.pathname).toBe(REDIRECT);
      expect(Object.fromEntries(loc.searchParams)).toMatchObject({ error, state: 'st-123', iss: ORIGIN });
    }
  });

  it('signed out: login redirect; prompt=none → login_required', async () => {
    const client = await registerClient();
    const url = await authorizeUrl(client);
    let res = await get(url);
    expect(res.status).toBe(302);
    const loc = location(res);
    expect(loc.pathname).toBe('/login');
    expect(loc.searchParams.get('reauth')).toBeNull();
    expect(loc.searchParams.get('return_to')).toBe(`${ORIGIN}${url}`);

    res = await get(await authorizeUrl(client, { prompt: 'none' }));
    expect(res.status).toBe(302);
    expect(Object.fromEntries(location(res).searchParams)).toMatchObject({ error: 'login_required', state: 'st-123' });
  });

  it('prompt=none with consent missing → consent_required', async () => {
    const client = await registerClient();
    const bob = await signUp('Bob', 'bob@example.com');
    const res = await get(await authorizeUrl(client, { prompt: 'none' }), bob.cookie);
    expect(location(res).searchParams.get('error')).toBe('consent_required');
  });

  it('uses the refresh cookie when bcn_at is missing', async () => {
    const client = await registerClient({ firstParty: true, clientId: 'bcnelson-blog' });
    const bob = await signUp('Bob', 'bob@example.com');
    const res = await get(await authorizeUrl(client), `${config.REFRESH_COOKIE}=${bob.rt}`);
    expect(res.status).toBe(302);
    expect(location(res).searchParams.get('code')).toBeTruthy();
    expect(cookieMap(res)[config.ACCESS_COOKIE]).toBeTruthy();
  });

  it('prompt=login and max_age force a fresh login, once', async () => {
    const client = await registerClient({ firstParty: true, clientId: 'bcnelson-blog' });
    const bob = await signUp('Bob', 'bob@example.com');
    vi.setSystemTime(Date.now() + 5_000); // (a login in the same second as the request counts as fresh)
    let res = await get(await authorizeUrl(client, { prompt: 'login' }), bob.cookie);
    let loc = location(res);
    expect(loc.pathname).toBe('/login');
    expect(loc.searchParams.get('reauth')).toBe('1');
    const back = new URL(loc.searchParams.get('return_to')!);
    expect(back.pathname).toBe('/authorize');
    expect(back.searchParams.get('prompt')).toBeNull();
    expect(back.searchParams.get('bcn_auth_after')).toBe(String(Math.floor(Date.now() / 1000)));

    // Still the old login → asked again; after a new login → code.
    vi.setSystemTime(Date.now() + 5_000);
    res = await get(back.pathname + back.search, bob.cookie);
    expect(location(res).pathname).toBe('/login');
    const fresh = account(await post('/login/password', { identifier: 'bob', password: 'correct-horse' }, bob.cookie));
    res = await get(back.pathname + back.search, fresh.cookie);
    expect(location(res).searchParams.get('code')).toBeTruthy();

    // max_age: 60 s old login with max_age=30 → login; max_age=600 → fine.
    vi.setSystemTime(Date.now() + 60_000);
    res = await get(await authorizeUrl(client, { max_age: '30' }), fresh.cookie);
    loc = location(res);
    expect(loc.pathname).toBe('/login');
    expect(loc.searchParams.get('reauth')).toBe('1');
    res = await get(await authorizeUrl(client, { max_age: '30', prompt: 'none' }), fresh.cookie);
    expect(location(res).searchParams.get('error')).toBe('login_required');
    res = await get(await authorizeUrl(client, { max_age: '600' }), fresh.cookie);
    expect(location(res).searchParams.get('code')).toBeTruthy();
  });
});

describe('token endpoint', () => {
  it('PKCE failure, wrong redirect_uri and wrong client are invalid_grant', async () => {
    const client = await registerClient();
    const other = await registerClient({ clientId: 'other-app' });
    const bob = await signUp('Bob', 'bob@example.com');

    let res = await exchange(client, await getCode(client, bob), { code_verifier: 'w'.repeat(43) });
    expect(res.status).toBe(400);
    expect(await json(res)).toMatchObject({ error: 'invalid_grant', error_description: expect.stringContaining('PKCE') });

    res = await exchange(client, await getCode(client, bob), { redirect_uri: `${APP}/other` });
    expect(await json(res)).toMatchObject({ error: 'invalid_grant' });

    res = await exchange(other, await getCode(client, bob));
    expect(await json(res)).toMatchObject({ error: 'invalid_grant' });

    res = await exchange(client, await getCode(client, bob), { code_verifier: '' });
    expect(await json(res)).toMatchObject({ error: 'invalid_request' });
  });

  it('code reuse is rejected and revokes the tokens issued from it', async () => {
    const client = await registerClient();
    const bob = await signUp('Bob', 'bob@example.com');
    const code = await getCode(client, bob);
    const first = await json(await exchange(client, code));
    expect((await userinfo(first.access_token)).status).toBe(200);
    const second = await exchange(client, code);
    expect(second.status).toBe(400);
    expect(await json(second)).toMatchObject({ error: 'invalid_grant' });
    expect((await userinfo(first.access_token)).status).toBe(401);
    expect((await refresh(client, first.refresh_token)).status).toBe(400);
  });

  it('expired codes are invalid_grant', async () => {
    const client = await registerClient();
    const bob = await signUp('Bob', 'bob@example.com');
    const code = await getCode(client, bob);
    vi.setSystemTime(Date.now() + config.OIDC_CODE_TTL + 1);
    const res = await exchange(client, code);
    expect(await json(res)).toMatchObject({ error: 'invalid_grant', error_description: expect.stringContaining('expired') });
  });

  it('client authentication failures', async () => {
    const client = await registerClient();
    const pub = await registerClient({ clientId: 'public-app', confidential: false });
    const bob = await signUp('Bob', 'bob@example.com');
    const code = await getCode(client, bob);
    const base = { grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: VERIFIER };

    let res = await postForm('/oauth/token', base, { origin: null, auth: basic({ ...client, secret: 'cs1_' + 'x'.repeat(43) }) });
    expect(res.status).toBe(401);
    expect(res.headers.get('WWW-Authenticate')).toContain('Basic');
    expect(await json(res)).toMatchObject({ error: 'invalid_client' });

    res = await postForm('/oauth/token', { ...base, client_id: client.clientId }, { origin: null });
    expect(res.status).toBe(401);

    res = await postForm('/oauth/token', { ...base, client_id: 'nobody' }, { origin: null });
    expect(res.status).toBe(401);

    res = await postForm('/oauth/token', { ...base, client_id: pub.clientId, client_secret: 'anything' }, { origin: null });
    expect(res.status).toBe(401);

    res = await postForm('/oauth/token', { ...base, client_secret: client.secret! }, { origin: null, auth: basic(client) });
    expect(res.status).toBe(400);
    expect(await json(res)).toMatchObject({ error: 'invalid_request' });

    // The code survived the failed attempts (they never reached it).
    expect((await exchange(client, code)).status).toBe(200);
  });

  it('bad requests: grant type, content type, duplicates, rate limit', async () => {
    const client = await registerClient();
    let res = await postForm('/oauth/token', { grant_type: 'password' }, { origin: null, auth: basic(client) });
    expect(await json(res)).toMatchObject({ error: 'unsupported_grant_type' });

    res = await app.request(`${ORIGIN}/oauth/token`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: basic(client) }, body: '{}',
    }, fake.env);
    expect(await json(res)).toMatchObject({ error: 'invalid_request' });

    res = await app.request(`${ORIGIN}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: basic(client) },
      body: 'grant_type=authorization_code&grant_type=refresh_token',
    }, fake.env);
    expect(await json(res)).toMatchObject({ error: 'invalid_request' });

    fake.limits.ip = false;
    res = await postForm('/oauth/token', { grant_type: 'authorization_code' }, { origin: null, auth: basic(client) });
    expect(res.status).toBe(429);
  });

  it('refresh tokens need offline_access; scope can narrow; never widen', async () => {
    const noOffline = await registerClient({ clientId: 'no-offline', scopes: ['openid', 'profile'] });
    const client = await registerClient();
    const bob = await signUp('Bob', 'bob@example.com');

    const t0 = await json(await exchange(noOffline, await getCode(noOffline, bob)));
    expect(t0.refresh_token).toBeUndefined();
    expect(t0.scope).toBe('openid profile'); // email/offline_access dropped: not allowed for this client

    const t1 = await json(await exchange(client, await getCode(client, bob)));
    const wide = await refresh(client, t1.refresh_token, { scope: 'openid profile email roles' });
    expect(await json(wide)).toMatchObject({ error: 'invalid_scope' });
    const narrow = await json(await refresh(client, t1.refresh_token, { scope: 'openid' }));
    expect(narrow.scope).toBe('openid');
    expect(await json(await userinfo(narrow.access_token))).toEqual({ sub: bob.userId });
    // The refresh token keeps the full grant.
    const full = await json(await refresh(client, narrow.refresh_token));
    expect(full.scope).toBe('openid profile email offline_access');
  });

  it('logout revokes the browser session and every client token bound to it', async () => {
    const client = await registerClient();
    const bob = await signUp('Bob', 'bob@example.com');
    const t = await json(await exchange(client, await getCode(client, bob)));
    expect((await post('/logout', {}, bob.cookie)).status).toBe(204);
    expect((await userinfo(t.access_token)).status).toBe(401);
    expect((await refresh(client, t.refresh_token)).status).toBe(400);
  });
});

describe('scopes and claims', () => {
  it('filters claims by scope', async () => {
    const client = await registerClient();
    const bob = await signUp('Bob', 'bob@example.com');
    const t = await json(await exchange(client, await getCode(client, bob, { scope: 'openid roles' })));
    expect(decodeJwt(t.id_token).email).toBeUndefined();
    expect(decodeJwt(t.id_token).preferred_username).toBeUndefined();
    expect(await json(await userinfo(t.access_token))).toEqual({ sub: bob.userId, roles: [] });
    expect(t.refresh_token).toBeUndefined();
  });

  it('userinfo rejects missing, site and ID tokens', async () => {
    const client = await registerClient();
    const bob = await signUp('Bob', 'bob@example.com');
    const t = await json(await exchange(client, await getCode(client, bob)));
    let res = await get('/userinfo');
    expect(res.status).toBe(401);
    expect(res.headers.get('WWW-Authenticate')).toBe('Bearer');
    res = await userinfo(bob.at);
    expect(res.status).toBe(401);
    expect(res.headers.get('WWW-Authenticate')).toBe('Bearer error="invalid_token"');
    expect((await userinfo(t.id_token)).status).toBe(401);
  });
});

describe('disabled clients and accounts', () => {
  it('a disabled client can no longer authorize, exchange or use its tokens', async () => {
    const client = await registerClient();
    const bob = await signUp('Bob', 'bob@example.com');
    const code = await getCode(client, bob);
    const t = await json(await exchange(client, await getCode(client, bob)));
    await index().setOAuthClientDisabled(client.clientId, true);
    expect((await get(await authorizeUrl(client), bob.cookie)).status).toBe(400);
    expect(await json(await exchange(client, code))).toMatchObject({ error: 'invalid_client' });
    expect((await userinfo(t.access_token)).status).toBe(401);
    expect(await json(await refresh(client, t.refresh_token))).toMatchObject({ error: 'invalid_client' });
  });

  it('a disabled account loses its client tokens', async () => {
    const client = await registerClient();
    const bob = await signUp('Bob', 'bob@example.com');
    const code = await getCode(client, bob);
    const t = await json(await exchange(client, await getCode(client, bob)));
    await fake.env.USER.get(fake.env.USER.idFromName(bob.userId)).setDisabled(true, 'usr_01ADMINADMINADMINADMINADMI');
    expect((await userinfo(t.access_token)).status).toBe(401);
    expect(await json(await refresh(client, t.refresh_token))).toMatchObject({ error: 'invalid_grant' });
    expect(await json(await exchange(client, code))).toMatchObject({ error: 'invalid_grant' });
    // Signed out everywhere → authorize sends to login.
    expect(location(await get(await authorizeUrl(client), bob.cookie)).pathname).toBe('/login');
  });
});

describe('discovery and routing', () => {
  it('advertises the provider endpoints', async () => {
    const doc = await json(await get('/.well-known/openid-configuration'));
    expect(doc).toMatchObject({
      issuer: ORIGIN,
      authorization_endpoint: `${ORIGIN}/authorize`,
      token_endpoint: `${ORIGIN}/oauth/token`,
      userinfo_endpoint: `${ORIGIN}/userinfo`,
      end_session_endpoint: `${ORIGIN}/logout`,
      jwks_uri: `${ORIGIN}/.well-known/jwks.json`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      code_challenge_methods_supported: ['S256'],
      scopes_supported: ['openid', 'profile', 'email', 'roles', 'offline_access'],
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
      id_token_signing_alg_values_supported: ['EdDSA'],
    });
    expect(doc.claims_supported).toEqual(expect.arrayContaining(['nonce', 'at_hash', 'email', 'roles']));
  });

  it('/oauth/token is its own route; /oauth/:provider/* is untouched and keeps the Origin check', async () => {
    const token = await postForm('/oauth/token', { grant_type: 'nope', client_id: 'x' }, { origin: null });
    expect(token.status).toBe(401); // reached the token endpoint (unknown client), not the Origin check
    expect(await json(token)).toMatchObject({ error: 'invalid_client' });

    const callback = await postForm('/oauth/github/callback', { code: 'x' }, { origin: null });
    expect(callback.status).toBe(403);
    expect(await json(callback)).toEqual({ error: 'forbidden_origin' });

    const start = await get('/oauth/github/start');
    const body = await start.text();
    expect(body).not.toContain('invalid_client');
    expect(body).not.toContain('unsupported_grant_type');
  });
});

describe('RP-initiated logout', () => {
  it('confirms, signs out, and returns to a registered post_logout_redirect_uri', async () => {
    const client = await registerClient();
    const bob = await signUp('Bob', 'bob@example.com');
    const t = await json(await exchange(client, await getCode(client, bob)));
    const qs = new URLSearchParams({ id_token_hint: t.id_token, post_logout_redirect_uri: LOGOUT_REDIRECT, state: 'bye' });

    // A GET alone never signs out.
    const page = await get(`/logout?${qs}`, bob.cookie);
    expect(page.status).toBe(200);
    expect(page.headers.get('Content-Security-Policy')).toContain(`form-action 'self' ${APP}`);
    const html = await page.text();
    expect(html).toContain(`value="${LOGOUT_REDIRECT}"`);
    expect((await userinfo(t.access_token)).status).toBe(200);

    const res = await postForm('/logout/end-session', {
      post_logout_redirect_uri: LOGOUT_REDIRECT, state: 'bye', client_id: client.clientId,
    }, { cookie: bob.cookie });
    expect(res.status).toBe(303);
    expect(res.headers.get('Location')).toBe(`${LOGOUT_REDIRECT}?state=bye`);
    expect(cookieMap(res)[config.ACCESS_COOKIE]).toBe('');
    expect((await userinfo(t.access_token)).status).toBe(401);
  });

  it('ignores unregistered post-logout URIs and needs an allowed Origin', async () => {
    const client = await registerClient();
    const bob = await signUp('Bob', 'bob@example.com');
    const page = await get(`/logout?client_id=${client.clientId}&post_logout_redirect_uri=${encodeURIComponent('https://evil.example/')}`, bob.cookie);
    expect(await page.text()).not.toContain('evil.example');
    const res = await postForm('/logout/end-session', {
      post_logout_redirect_uri: 'https://evil.example/', client_id: client.clientId,
    }, { cookie: bob.cookie });
    expect(res.status).toBe(200);
    expect(res.headers.get('Location')).toBeNull();
    const cross = await postForm('/logout/end-session', {}, { cookie: bob.cookie, origin: 'https://evil.example' });
    expect(cross.status).toBe(403);
  });
});

describe('admin client registry', () => {
  async function admin(): Promise<Account> {
    return signUp('Admin1', 'admin@example.com');
  }

  it('creates (secret shown once), lists, updates, rotates and disables clients', async () => {
    const a = await admin();
    let res = await post('/api/admin/clients', {
      name: 'Partner', redirect_uris: [REDIRECT], allowed_scopes: ['openid', 'email'], confidential: true,
    }, a.cookie);
    expect(res.status).toBe(201);
    const created = await json(res);
    expect(created.client_secret).toMatch(/^cs1_/);
    expect(created.client).toMatchObject({ name: 'Partner', confidential: true, hasSecret: true, allowedScopes: ['openid', 'email'] });
    expect(created.client.secretHash).toBeUndefined();
    const id = created.client.clientId as string;
    expect(id).toMatch(/^cli_/);

    const list = await json(await get('/api/admin/clients', a.cookie));
    expect(list.clients.map((c: any) => c.clientId)).toEqual([id]);
    expect(JSON.stringify(list)).not.toContain(created.client_secret);

    res = await post(`/api/admin/clients/${id}`, { name: 'Partner 2', redirect_uris: `${REDIRECT}\n${APP}/cb2`, allowed_scopes: ['openid'] }, a.cookie);
    expect(await json(res)).toMatchObject({ ok: true, client: { name: 'Partner 2', redirectUris: [REDIRECT, `${APP}/cb2`] } });

    res = await post(`/api/admin/clients/${id}/rotate-secret`, {}, a.cookie);
    const rotated = await json(res);
    expect(rotated.client_secret).toMatch(/^cs1_/);
    expect(rotated.client_secret).not.toBe(created.client_secret);

    res = await post(`/api/admin/clients/${id}/disable`, { disabled: true }, a.cookie);
    expect((await json(res)).client.disabledAt).toEqual(expect.any(Number));

    const page = await get('/admin/clients', a.cookie);
    expect(page.status).toBe(200);
    const html = await page.text();
    expect(html).toContain('Partner 2');
    expect(html).toContain('<script src="/assets/clients.js" defer></script>');
    expect(html).not.toContain(' style="');
    expect(await (await get('/admin', a.cookie)).text()).toContain('href="/admin/clients"');
  });

  it('rejects first-party impersonation and bad redirect URIs', async () => {
    const a = await admin();
    const base = { name: 'X App', redirect_uris: [REDIRECT] };
    const bad: [Record<string, unknown>, string][] = [
      [{ ...base, client_id: 'bcnelson.dev' }, 'invalid_client_id'],
      [{ ...base, client_id: 'bcnelson-login' }, 'invalid_client_id'],
      [{ ...base, name: 'bcnelson.dev Login' }, 'invalid_name'],
      [{ ...base, redirect_uris: ['https://app.bcnelson.dev/cb'] }, 'invalid_redirect_uri'],
      [{ ...base, redirect_uris: ['https://auth.bcnelson.dev/cb'], first_party: true }, 'invalid_redirect_uri'],
      [{ ...base, redirect_uris: ['http://app.example.com/cb'] }, 'invalid_redirect_uri'],
      [{ ...base, redirect_uris: ['https://app.example.com/cb#x'] }, 'invalid_redirect_uri'],
      [{ ...base, redirect_uris: ['https://APP.example.com/cb'] }, 'invalid_redirect_uri'],
      [{ ...base, redirect_uris: [] }, 'invalid_redirect_uri'],
      [{ ...base, allowed_scopes: ['email'] }, 'invalid_scope'],
      [{ ...base, allowed_scopes: ['openid', 'admin'] }, 'invalid_scope'],
    ];
    for (const [body, error] of bad) {
      const res = await post('/api/admin/clients', body, a.cookie);
      expect(res.status, JSON.stringify(body)).toBe(400);
      expect(await json(res)).toMatchObject({ error });
    }
    // First-party clients may use the site's name and redirect to the site; loopback http is fine.
    const ok = await post('/api/admin/clients', {
      client_id: 'bcnelson-blog', name: 'bcnelson.dev Blog', first_party: true,
      redirect_uris: ['https://blog.bcnelson.dev/callback', 'http://localhost:8787/callback'],
    }, a.cookie);
    expect(ok.status).toBe(201);
    expect((await json(ok)).client_secret).toBeUndefined();
    expect((await post('/api/admin/clients', { ...base, client_id: 'bcnelson-blog', first_party: true }, a.cookie)).status).toBe(409);
  });

  it('is admin-only', async () => {
    await admin();
    const bob = await signUp('Bob', 'bob@example.com');
    expect((await get('/api/admin/clients', bob.cookie)).status).toBe(403);
    expect((await post('/api/admin/clients', { name: 'x', redirect_uris: [REDIRECT] }, bob.cookie)).status).toBe(403);
    expect((await get('/admin/clients', bob.cookie)).status).toBe(403);
    expect((await get('/admin/clients')).status).toBe(302);
  });
});

// --- integration pass: cross-feature behaviour ------------------------------------------

/** Table names in a User DO's SQLite (empty = nothing was ever written). */
function userTables(userId: string): string[] {
  const entry = fake.users.instances.get(userId);
  if (!entry) return [];
  return (entry.fake.db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all() as { name: string }[])
    .map((r) => r.name);
}

describe('forged but well-formed tokens never create User DO storage', () => {
  const GHOST = 'usr_01JGHOSTGHOSTGHOSTGHOSTGH0';
  const SECRET = 'A'.repeat(43);

  it('rt1 (refresh cookie), pr1 (reset link), ac1 (code) and crt1 (client refresh)', async () => {
    const client = await registerClient();
    const rt = `${config.REFRESH_COOKIE}=rt1.${GHOST}.ses_01JGHOSTGHOSTGHOSTGHOSTGH0.${SECRET}`;
    expect(location(await get('/refresh', rt)).pathname).toBe('/login');
    expect((await get('/session/token', rt)).status).toBe(401);
    expect((await post('/logout', {}, rt)).status).toBe(204);
    expect((await get(`/password/reset?token=pr1.${GHOST}.${SECRET}`)).status).toBe(400);
    const reset = await post('/password/reset', { token: `pr1.${GHOST}.${SECRET}`, password: 'correct-horse-2' });
    expect(await json(reset)).toMatchObject({ error: 'invalid_token' });
    expect(await json(await exchange(client, `ac1.${GHOST}.${SECRET}`))).toMatchObject({ error: 'invalid_grant' });
    const crt = `crt1.${GHOST}.otk_01JGHOSTGHOSTGHOSTGHOSTGH0.${SECRET}`;
    expect(await json(await refresh(client, crt))).toMatchObject({ error: 'invalid_grant' });
    expect(userTables(GHOST)).toEqual([]);
  });

  it('signup still creates the schema (first write migrates)', async () => {
    const bob = await signUp('Bob', 'bob@example.com');
    expect(userTables(bob.userId)).toContain('profile');
    expect((await get('/session/token', bob.cookie)).status).toBe(200);
  });
});

describe('OIDC client tokens across re-login, logout and reset', () => {
  async function connect(bob: Account) {
    const client = await registerClient();
    const tokens = await json(await exchange(client, await getCode(client, bob)));
    expect(tokens.refresh_token).toMatch(/^crt1\./);
    return { client, tokens };
  }

  it('a same-browser re-login keeps the app connected (tokens move to the new session)', async () => {
    const bob = await signUp('Bob', 'bob@example.com');
    const { client, tokens } = await connect(bob);
    vi.setSystemTime(Date.now() + 5_000);
    const fresh = account(await post('/login/password', { identifier: 'bob', password: 'correct-horse' }, bob.cookie));
    expect(decodeJwt(fresh.at).sid).not.toBe(decodeJwt(bob.at).sid);
    // The old browser session is gone…
    expect((await get('/session/token', bob.cookie)).status).toBe(401);
    // …but the app's access token and refresh token still work.
    expect((await userinfo(tokens.access_token)).status).toBe(200);
    const rotated = await refresh(client, tokens.refresh_token);
    expect(rotated.status).toBe(200);
    const next = await json(rotated);
    expect(decodeJwt(next.id_token).sid).toBe(decodeJwt(fresh.at).sid);

    // Logout still ends them.
    expect((await post('/logout', {}, fresh.cookie)).status).toBe(204);
    expect(await json(await refresh(client, next.refresh_token))).toMatchObject({ error: 'invalid_grant' });
    expect((await userinfo(next.access_token)).status).toBe(401);
  });

  it('a password reset revokes client tokens', async () => {
    const bob = await signUp('Bob', 'bob@example.com');
    const { client, tokens } = await connect(bob);
    await post('/password/forgot', { email: 'bob@example.com', turnstile: 'good' });
    const link = /token=([^\s&]+)/.exec(fake.mail.at(-1)!.text)![1]!;
    const res = await post('/password/reset', { token: decodeURIComponent(link), password: 'correct-horse-2' });
    expect(res.status).toBe(200);
    expect(await json(await refresh(client, tokens.refresh_token))).toMatchObject({ error: 'invalid_grant' });
    expect((await userinfo(tokens.access_token)).status).toBe(401);
  });
});

describe('profile page: connected apps and admin links', () => {
  it('lists granted apps; disconnect needs a recent login and revokes the tokens', async () => {
    const client = await registerClient();
    const bob = await signUp('Bob', 'bob@example.com');
    const tokens = await json(await exchange(client, await getCode(client, bob)));
    const page = await (await get('/profile', bob.cookie)).text();
    expect(page).toContain('Connected apps');
    expect(page).toContain('Example App');
    expect(page).toContain('/api/me/apps/example-app/revoke');
    expect(page).not.toContain('href="/admin"');

    vi.setSystemTime(Date.now() + config.REAUTH_WINDOW + 60_000);
    const fresh = account(await get('/refresh', bob.cookie));
    const stale = await post('/api/me/apps/example-app/revoke', {}, fresh.cookie);
    expect(stale.status).toBe(403);
    expect(await json(stale)).toMatchObject({ error: 'reauth_required', reauthUrl: expect.stringContaining('reauth=1') });

    const relogin = account(await post('/login/password', { identifier: 'bob', password: 'correct-horse' }, fresh.cookie));
    expect((await post('/api/me/apps/example-app/revoke', {}, relogin.cookie)).status).toBe(200);
    expect(await json(await refresh(client, tokens.refresh_token))).toMatchObject({ error: 'invalid_grant' });
    expect((await post('/api/me/apps/example-app/revoke', {}, relogin.cookie)).status).toBe(404);
    expect(await (await get('/profile', relogin.cookie)).text()).not.toContain('Connected apps');
  });

  it('admins get /admin and /admin/clients links', async () => {
    const admin = await signUp('Alice', 'admin@example.com');
    const page = await (await get('/profile', admin.cookie)).text();
    expect(page).toContain('href="/admin"');
    expect(page).toContain('href="/admin/clients"');
  });
});

describe('IP limits on every POST', () => {
  it('admin mutations, consent, end-session, userinfo, logout', async () => {
    const admin = await signUp('Alice', 'admin@example.com');
    fake.limits.ip = false;
    expect((await post('/api/admin/clients', { name: 'x', redirect_uris: [REDIRECT] }, admin.cookie)).status).toBe(429);
    expect((await get('/api/admin/users', admin.cookie)).status).toBe(200);
    for (const path of ['/authorize/consent', '/logout/end-session', '/logout']) {
      expect((await postForm(path, {}, { cookie: admin.cookie })).status).toBe(429);
    }
    expect((await postForm('/userinfo', {}, { origin: null, auth: 'Bearer x' })).status).toBe(429);
  });
});
