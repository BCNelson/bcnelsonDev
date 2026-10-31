import { SignJWT, decodeJwt, exportJWK, generateKeyPair, type JWK } from 'jose';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { config } from '../src/config';
import type { Env } from '../src/env';
import { resetKeyCache } from '../src/tokens';
import { lastCode, makeFakeEnv, type FakeEnv } from './do/fake-env';

vi.mock('cloudflare:workers', async () => ({
  DurableObject: (await import('./do/fake-storage')).FakeDurableObject,
}));
vi.mock('../src/crypto/password', async () => (await import('./do/fake-env')).fakePasswordModule());

const { User } = await import('../src/do/user');
const { UserIndex } = await import('../src/do/user-index');
const { createApp } = await import('../src/app');
const { pickGitHubEmail } = await import('../src/oauth/github');
const { verifyGoogleIdToken } = await import('../src/oauth/google');

const ORIGIN = 'https://auth.bcnelson.dev';
const START = 1_800_000_000_000;
const APP = 'https://app.bcnelson.dev/after';
const app = createApp();

// --- provider mock (all outbound HTTP goes through the stubbed global fetch) ------

interface GitHubAccount {
  user: Record<string, unknown>;
  emails: { email: string; primary: boolean; verified: boolean }[];
}

/** What the mocked providers answer, keyed by authorization code. */
const codes = new Map<string, { github?: GitHubAccount; google?: Record<string, unknown> }>();
const requests: { url: string; headers: Headers; body?: string }[] = [];
let googleKey: CryptoKey;
let googleJwk: JWK;
let keyJson: string;

async function googleIdToken(claims: Record<string, unknown>): Promise<string> {
  return new SignJWT({ iss: 'https://accounts.google.com', aud: 'g-client', ...claims })
    .setProtectedHeader({ alg: 'RS256', kid: 'gk1' })
    .setIssuedAt(Math.floor(Date.now() / 1000))
    .setExpirationTime(Math.floor(Date.now() / 1000) + 3600)
    .sign(googleKey);
}

async function mockFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const req = input instanceof Request ? input : new Request(String(input), init);
  const url = req.url;
  const body = req.method === 'POST' && !(init?.body instanceof FormData) ? await req.clone().text() : undefined;
  requests.push({ url, headers: req.headers, body });
  if (url.startsWith('https://challenges.cloudflare.com/')) {
    const token = (init?.body as FormData).get('response');
    return Response.json({ success: token === 'good' });
  }
  if (url === 'https://github.com/login/oauth/access_token') {
    const code = new URLSearchParams(body).get('code')!;
    if (!codes.get(code)?.github) return Response.json({ error: 'bad_verification_code' }, { status: 400 });
    return Response.json({ access_token: `gh_${code}`, token_type: 'bearer', scope: 'read:user,user:email' });
  }
  if (url.startsWith('https://api.github.com/')) {
    const code = (req.headers.get('Authorization') ?? '').replace('Bearer gh_', '');
    const account = codes.get(code)?.github;
    if (!account) return new Response('unauthorized', { status: 401 });
    return Response.json(url.endsWith('/user/emails') ? account.emails : account.user);
  }
  if (url === 'https://oauth2.googleapis.com/token') {
    const code = new URLSearchParams(body).get('code')!;
    const claims = codes.get(code)?.google;
    if (!claims) return Response.json({ error: 'invalid_grant' }, { status: 400 });
    return Response.json({ access_token: 'ya29', token_type: 'Bearer', expires_in: 3600, id_token: await googleIdToken(claims) });
  }
  if (url === 'https://www.googleapis.com/oauth2/v3/certs') {
    return Response.json({ keys: [{ ...googleJwk, kid: 'gk1', alg: 'RS256', use: 'sig' }] });
  }
  return new Response('unexpected', { status: 599 });
}

beforeAll(async () => {
  const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
  const jwk = (await crypto.subtle.exportKey('jwk', pair.privateKey)) as JsonWebKey;
  keyJson = JSON.stringify({ kty: 'OKP', crv: 'Ed25519', x: jwk.x, d: jwk.d, kid: 'k1' });
  const google = await generateKeyPair('RS256');
  googleKey = google.privateKey as CryptoKey;
  googleJwk = await exportJWK(google.publicKey);
  vi.stubGlobal('fetch', vi.fn(mockFetch));
});
afterAll(() => {
  vi.unstubAllGlobals();
  resetKeyCache();
});

const PROVIDERS = {
  GITHUB_CLIENT_ID: 'gh-client',
  GITHUB_CLIENT_SECRET_DEV: 'gh-secret',
  GOOGLE_CLIENT_ID: 'g-client',
  GOOGLE_CLIENT_SECRET_DEV: 'g-secret',
};

let fake: FakeEnv;
function setup(overrides: Partial<Env> = PROVIDERS as Partial<Env>) {
  fake = makeFakeEnv({ User, UserIndex }, { AUTH_SIGNING_KEY_DEV: keyJson, ...overrides } as Partial<Env>);
}
beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(START);
  codes.clear();
  requests.length = 0;
  setup();
});
afterEach(() => {
  vi.useRealTimers();
});

// --- helpers ---------------------------------------------------------------------

type Jar = Record<string, string>;

function cookieHeader(jar: Jar): Record<string, string> {
  const value = Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ');
  return value ? { Cookie: value } : {};
}

/** Apply Set-Cookie lines to a jar (Max-Age=0 deletes). */
function absorb(jar: Jar, res: Response): Jar {
  for (const line of res.headers.getSetCookie()) {
    const [pair] = line.split(';');
    const i = pair!.indexOf('=');
    const name = pair!.slice(0, i);
    const value = pair!.slice(i + 1);
    if (/max-age=0/i.test(line) || value === '') delete jar[name];
    else jar[name] = value;
  }
  return jar;
}

function setCookieLine(res: Response, name: string): string | undefined {
  return res.headers.getSetCookie().find((l) => l.startsWith(`${name}=`));
}

function get(path: string, jar: Jar = {}) {
  return app.request(`${ORIGIN}${path}`, { headers: cookieHeader(jar) }, fake.env);
}

function post(path: string, data: unknown, jar: Jar = {}) {
  return app.request(`${ORIGIN}${path}`, {
    method: 'POST',
    headers: { Origin: ORIGIN, 'CF-Connecting-IP': '1.2.3.4', 'Content-Type': 'application/json', ...cookieHeader(jar) },
    body: JSON.stringify(data),
  }, fake.env);
}

function postForm(path: string, data: Record<string, string>, jar: Jar = {}) {
  return app.request(`${ORIGIN}${path}`, {
    method: 'POST',
    headers: { Origin: ORIGIN, 'CF-Connecting-IP': '1.2.3.4', 'Content-Type': 'application/x-www-form-urlencoded', ...cookieHeader(jar) },
    body: new URLSearchParams(data).toString(),
  }, fake.env);
}

function github(code: string, id: number, login: string, emails: GitHubAccount['emails'], extra: Record<string, unknown> = {}) {
  codes.set(code, { github: { user: { id, login, name: `${login} name`, avatar_url: `https://avatars.example/${id}`, ...extra }, emails } });
}

/** /start then /callback for `code`; returns the callback response and the jar. */
async function oauth(provider: 'github' | 'google', code: string, jar: Jar = {}, query = `return_to=${encodeURIComponent(APP)}`) {
  const start = await get(`/oauth/${provider}/start?${query}`, jar);
  expect(start.status).toBe(302);
  absorb(jar, start);
  const location = new URL(start.headers.get('Location')!);
  const state = location.searchParams.get('state')!;
  const res = await get(`/oauth/${provider}/callback?code=${code}&state=${encodeURIComponent(state)}`, jar);
  absorb(jar, res);
  return { res, jar, location, start };
}

async function passwordAccount(userId: string, username: string, email: string) {
  const user = fake.users.get(userId);
  await user.initProfile({ userId, username, email });
  await fake.index.get('index').registerAccount({ userId, username, email });
  await user.setPassword('v2$password123');
  return user;
}

async function login(identifier: string, jar: Jar = {}): Promise<Jar> {
  const res = await post('/login/password', { identifier, password: 'password123' }, jar);
  expect(res.status).toBe(200);
  return absorb(jar, res);
}

/** Social signup through GitHub with a verified email; returns userId + signed-in jar. */
async function githubSignup(code = 'c-new', id = 500, username = 'octo', email = 'octo@example.com') {
  github(code, id, username, [{ email, primary: true, verified: true }]);
  const { res, jar } = await oauth('github', code);
  expect(res.status).toBe(302);
  const done = await post('/oauth/social/signup/complete', { username, return_to: APP }, jar);
  expect(done.status).toBe(200);
  absorb(jar, done);
  const claims = decodeJwt(jar[config.ACCESS_COOKIE]!);
  return { userId: claims.sub!, claims, jar };
}

const index = () => fake.index.get('index');

// --- tests -------------------------------------------------------------------------

describe('providers and buttons', () => {
  it('a provider with no client ID is hidden and its routes are 404', async () => {
    setup({});
    let body = await (await get('/login')).text();
    expect(body).not.toContain('/oauth/github/start');
    expect(body).not.toContain('/oauth/google/start');
    expect((await get('/oauth/github/start')).status).toBe(404);
    expect((await get('/oauth/google/callback?code=x&state=y')).status).toBe(404);

    setup({ GITHUB_CLIENT_ID: 'gh-client', GITHUB_CLIENT_SECRET_DEV: 's' } as Partial<Env>);
    body = await (await get(`/login?return_to=${encodeURIComponent(APP)}`)).text();
    expect(body).toContain(`href="/oauth/github/start?return_to=${encodeURIComponent(APP)}"`);
    expect(body).toContain('Continue with GitHub');
    expect(body).not.toContain('Google');
    expect((await get('/oauth/google/start')).status).toBe(404);
    const signup = await (await get('/signup')).text();
    expect(signup).toContain('Sign up with GitHub');
    expect(signup).not.toMatch(/<script(?![^>]*\ssrc=)[^>]*>/);
  });

  it('with no providers configured, login, signup and the profile show no social UI', async () => {
    setup({});
    for (const path of ['/login', '/signup']) {
      const body = await (await get(path)).text();
      expect(body).not.toMatch(/GitHub|Google|\/oauth\/[a-z]+\/start/);
    }
    await passwordAccount('usr_01JCCCCCCCCCCCCCCCCCCCCCCC', 'plain', 'plain@example.com');
    const jar = await login('plain');
    const profile = await (await get('/profile', jar)).text();
    expect(profile).not.toContain('id="linked-accounts"');
    expect(profile).not.toMatch(/GitHub|Google/);
  });

  it('start redirects to GitHub with PKCE, scopes and the callback URL; the state cookie is HttpOnly on /oauth', async () => {
    const res = await get(`/oauth/github/start?return_to=${encodeURIComponent(APP)}`);
    expect(res.status).toBe(302);
    const url = new URL(res.headers.get('Location')!);
    expect(url.origin + url.pathname).toBe('https://github.com/login/oauth/authorize');
    expect(url.searchParams.get('client_id')).toBe('gh-client');
    expect(url.searchParams.get('redirect_uri')).toBe(`${ORIGIN}/oauth/github/callback`);
    expect(url.searchParams.get('scope')).toBe('read:user user:email');
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(url.searchParams.get('state')).toBeTruthy();
    const line = setCookieLine(res, config.OAUTH_STATE_COOKIE)!;
    expect(line).toMatch(/HttpOnly/);
    expect(line).toMatch(/Path=\/oauth/);
    expect(line).toMatch(/SameSite=Lax/);
    expect(line).toMatch(/Secure/);
    expect(line).toMatch(new RegExp(`Max-Age=${config.OAUTH_STATE_TTL / 1000}`));

    const g = new URL((await get('/oauth/google/start')).headers.get('Location')!);
    expect(g.origin + g.pathname).toBe('https://accounts.google.com/o/oauth2/v2/auth');
    expect(g.searchParams.get('scope')).toBe('openid email profile');
    expect(g.searchParams.get('code_challenge_method')).toBe('S256');
    expect(g.searchParams.get('redirect_uri')).toBe(`${ORIGIN}/oauth/google/callback`);
  });
});

describe('state cookie', () => {
  async function started(provider = 'github') {
    const res = await get(`/oauth/${provider}/start`);
    const state = new URL(res.headers.get('Location')!).searchParams.get('state')!;
    return { state, cookie: absorb({}, res)[config.OAUTH_STATE_COOKIE]! };
  }

  it('is cleared on the callback and refuses tampering, a wrong state, another provider or a missing cookie', async () => {
    github('c1', 1, 'one', [{ email: 'one@example.com', primary: true, verified: true }]);
    const { state, cookie } = await started();
    const flipped = cookie.slice(0, 5) + (cookie[5] === 'A' ? 'B' : 'A') + cookie.slice(6);
    const tampered = await get(`/oauth/github/callback?code=c1&state=${state}`, { [config.OAUTH_STATE_COOKIE]: flipped });
    expect(tampered.status).toBe(400);
    expect(await tampered.text()).toContain('expired or was started in another browser');
    expect(setCookieLine(tampered, config.OAUTH_STATE_COOKIE)).toMatch(/Max-Age=0/);

    expect((await get(`/oauth/github/callback?code=c1&state=${state}x`, { [config.OAUTH_STATE_COOKIE]: cookie })).status).toBe(400);
    expect((await get(`/oauth/github/callback?code=c1&state=${state}`)).status).toBe(400);
    expect((await get(`/oauth/google/callback?code=c1&state=${state}`, { [config.OAUTH_STATE_COOKIE]: cookie })).status).toBe(400);
    // No provider call was made for any of them.
    expect(requests.filter((r) => r.url.includes('github.com'))).toHaveLength(0);

    const ok = await get(`/oauth/github/callback?code=c1&state=${state}`, { [config.OAUTH_STATE_COOKIE]: cookie });
    expect(ok.status).toBe(302);
  });

  it('expires after OAUTH_STATE_TTL', async () => {
    github('c1', 1, 'one', [{ email: 'one@example.com', primary: true, verified: true }]);
    const { state, cookie } = await started();
    vi.setSystemTime(START + config.OAUTH_STATE_TTL + 1);
    const res = await get(`/oauth/github/callback?code=c1&state=${state}`, { [config.OAUTH_STATE_COOKIE]: cookie });
    expect(res.status).toBe(400);
  });

  it('a provider error or a failed exchange shows an error page', async () => {
    let { state, cookie } = await started();
    let res = await get(`/oauth/github/callback?error=access_denied&state=${state}`, { [config.OAUTH_STATE_COOKIE]: cookie });
    expect(res.status).toBe(400);
    expect(await res.text()).toContain('cancelled');
    ({ state, cookie } = await started());
    res = await get(`/oauth/github/callback?code=unknown&state=${state}`, { [config.OAUTH_STATE_COOKIE]: cookie });
    expect(res.status).toBe(400);
    expect(await res.text()).toContain('confirm your account');
  });
});

describe('social signup', () => {
  it('verified email: pick a username, account created with identity + credential, then GitHub logs in', async () => {
    github('c-new', 500, 'Octo', [
      { email: 'old@example.com', primary: false, verified: true },
      { email: 'octo@example.com', primary: true, verified: true },
    ]);
    const { res, jar } = await oauth('github', 'c-new');
    expect(res.status).toBe(302);
    expect(res.headers.get('Location')).toBe(`/oauth/social/signup?return_to=${encodeURIComponent(APP)}`);
    expect(jar[config.OAUTH_SIGNUP_COOKIE]).toBeTruthy();
    expect(jar[config.ACCESS_COOKIE]).toBeUndefined();
    // GitHub API calls carry a User-Agent.
    expect(requests.find((r) => r.url === 'https://api.github.com/user')!.headers.get('User-Agent')).toBeTruthy();

    const page = await (await get(`/oauth/social/signup?return_to=${encodeURIComponent(APP)}`, jar)).text();
    expect(page).toContain('value="Octo"');
    expect(page).toContain('octo@example.com');
    expect(page).toContain('Verified by GitHub');
    expect(page).toContain('/assets/oauth-signup.js');
    expect(page).not.toMatch(/<script(?![^>]*\ssrc=)[^>]*>/);

    let done = await post('/oauth/social/signup/complete', { username: 'admin', return_to: APP }, jar);
    expect(done.status).toBe(400);
    done = await post('/oauth/social/signup/complete', { username: 'Octo', return_to: APP }, jar);
    expect(done.status).toBe(200);
    expect(await done.json()).toEqual({ ok: true, redirect: APP });
    expect(fake.mail).toHaveLength(0);
    absorb(jar, done);
    expect(jar[config.OAUTH_SIGNUP_COOKIE]).toBeUndefined();
    const claims = decodeJwt(jar[config.ACCESS_COOKIE]!);
    expect(claims).toMatchObject({ preferred_username: 'Octo', email: 'octo@example.com', amr: ['oauth:github'], name: 'Octo name' });
    const userId = claims.sub!;
    expect(await index().findIdentity('github', '500')).toBe(userId);
    expect(await fake.users.get(userId).listOAuthCredentials()).toMatchObject([
      { provider: 'github', subject: '500', email: 'octo@example.com', label: 'GitHub (Octo)' },
    ]);

    // Signing in again with the same GitHub account.
    codes.set('c-again', codes.get('c-new')!);
    const again = await oauth('github', 'c-again', {});
    expect(again.res.status).toBe(302);
    expect(again.res.headers.get('Location')).toBe(APP);
    const next = decodeJwt(again.jar[config.ACCESS_COOKIE]!);
    expect(next).toMatchObject({ sub: userId, amr: ['oauth:github'] });
    expect(again.jar[config.REFRESH_COOKIE]).toBeTruthy();
  });

  it('unverified email: the email-code step runs before the account exists', async () => {
    github('c-u', 600, 'unv', [{ email: 'unv@example.com', primary: true, verified: false }]);
    const { jar } = await oauth('github', 'c-u');
    const page = await (await get('/oauth/social/signup', jar)).text();
    expect(page).toContain('Send code');
    expect(page).toContain('data-sitekey');

    expect((await post('/oauth/social/signup/complete', { username: 'unv' }, jar)).status).toBe(400);
    let res = await post('/oauth/social/signup/start', { username: 'unv', email: 'unv@example.com', turnstile: 'bad' }, jar);
    expect(res.status).toBe(403);
    res = await post('/oauth/social/signup/start', { username: 'unv', email: 'unv@example.com', turnstile: 'good' }, jar);
    expect(await res.json()).toEqual({ ok: true, verified: false });
    expect(fake.mail.at(-1)!.to).toBe('unv@example.com');
    expect((await post('/oauth/social/signup/verify', { code: '000000' }, jar)).status).toBe(400);
    expect(await (await post('/oauth/social/signup/verify', { code: lastCode(fake.mail) }, jar)).json()).toEqual({ ok: true });
    const done = await post('/oauth/social/signup/complete', { return_to: APP }, jar);
    expect(done.status).toBe(200);
    const claims = decodeJwt(absorb(jar, done)[config.ACCESS_COOKIE]!);
    expect(claims).toMatchObject({ preferred_username: 'unv', email: 'unv@example.com', amr: ['oauth:github'] });
    expect(await index().findIdentity('github', '600')).toBe(claims.sub);
  });

  it('without the signup cookie the page and endpoints refuse', async () => {
    expect((await get('/oauth/social/signup')).status).toBe(400);
    expect((await post('/oauth/social/signup/complete', { username: 'x' })).status).toBe(400);
  });

  it('Google: a validated id_token; an unverified Google email uses the code flow', async () => {
    codes.set('g1', { google: { sub: 'g-sub-1', email: 'gee@example.com', email_verified: true, name: 'Gee' } });
    const { res, jar } = await oauth('google', 'g1');
    expect(res.status).toBe(302);
    const done = await post('/oauth/social/signup/complete', { username: 'gee' }, jar);
    expect(done.status).toBe(200);
    expect(decodeJwt(absorb(jar, done)[config.ACCESS_COOKIE]!)).toMatchObject({ amr: ['oauth:google'], email: 'gee@example.com' });

    codes.set('g2', { google: { sub: 'g-sub-2', email: 'nov@example.com', email_verified: false } });
    const second = await oauth('google', 'g2');
    expect(await (await get('/oauth/social/signup', second.jar)).text()).toContain('Send code');
  });
});

describe('existing account with the same email', () => {
  it('is never auto-linked: sign in first, then confirm, then GitHub signs in to that account', async () => {
    const alice = await passwordAccount('usr_01JAAAAAAAAAAAAAAAAAAAAAAA', 'alice', 'alice@example.com');
    github('c-a', 700, 'alicegh', [{ email: 'Alice@Example.com', primary: true, verified: true }]);
    const { res, jar } = await oauth('github', 'c-a');
    expect(res.status).toBe(200);
    const page = await res.text();
    expect(page).toContain('An account with <strong>Alice@Example.com</strong> already exists');
    expect(jar[config.ACCESS_COOKIE]).toBeUndefined();
    expect(await index().findIdentity('github', '700')).toBeNull();
    expect(await alice.listOAuthCredentials()).toEqual([]);
    const loginHref = /href="(\/login\?return_to=[^"]+)"/.exec(page)![1]!.replace(/&amp;/g, '&');
    const linkUrl = new URL(loginHref, ORIGIN).searchParams.get('return_to')!;
    expect(linkUrl).toBe(`${ORIGIN}/oauth/social/link?return_to=${encodeURIComponent(APP)}`);

    // Not signed in: the confirm page sends the browser to log in.
    let confirm = await get(new URL(linkUrl).pathname + new URL(linkUrl).search, jar);
    expect(confirm.status).toBe(302);
    expect(confirm.headers.get('Location')).toMatch(/^\/login\?return_to=/);

    await login('alice', jar);
    confirm = await get(new URL(linkUrl).pathname + new URL(linkUrl).search, jar);
    expect(confirm.status).toBe(200);
    expect(await confirm.text()).toContain('Link GitHub?');
    const linked = await postForm('/oauth/social/link', { return_to: APP }, jar);
    expect(linked.status).toBe(303);
    expect(linked.headers.get('Location')).toBe(APP);
    absorb(jar, linked);
    expect(jar[config.OAUTH_LINK_COOKIE]).toBeUndefined();
    expect(await index().findIdentity('github', '700')).toBe('usr_01JAAAAAAAAAAAAAAAAAAAAAAA');

    codes.set('c-a2', codes.get('c-a')!);
    const again = await oauth('github', 'c-a2', {});
    expect(again.res.status).toBe(302);
    expect(decodeJwt(again.jar[config.ACCESS_COOKIE]!)).toMatchObject({ sub: 'usr_01JAAAAAAAAAAAAAAAAAAAAAAA', amr: ['oauth:github'] });
  });

  it('another signed-in user cannot take the pending link', async () => {
    await passwordAccount('usr_01JAAAAAAAAAAAAAAAAAAAAAAA', 'alice', 'alice@example.com');
    await passwordAccount('usr_01JBBBBBBBBBBBBBBBBBBBBBBB', 'bob', 'bob@example.com');
    github('c-a', 700, 'alicegh', [{ email: 'alice@example.com', primary: true, verified: true }]);
    const { jar } = await oauth('github', 'c-a');
    await login('bob', jar);
    expect((await get('/oauth/social/link', jar)).status).toBe(400);
    expect((await postForm('/oauth/social/link', {}, jar)).status).toBe(400);
    expect(await index().findIdentity('github', '700')).toBeNull();
  });

  it('a held (recently removed) address falls back to the code flow', async () => {
    await passwordAccount('usr_01JAAAAAAAAAAAAAAAAAAAAAAA', 'alice', 'alice@example.com');
    await index().holdEmail('usr_01JAAAAAAAAAAAAAAAAAAAAAAA', 'alice@example.com');
    github('c-h', 701, 'held', [{ email: 'alice@example.com', primary: true, verified: true }]);
    const { res, jar } = await oauth('github', 'c-h');
    expect(res.status).toBe(302);
    expect(await (await get('/oauth/social/signup', jar)).text()).toContain('Send code');
  });
});

describe('linking from the profile (intent=link)', () => {
  it('needs a session and a recent login; then attaches the identity to the current user', async () => {
    await passwordAccount('usr_01JAAAAAAAAAAAAAAAAAAAAAAA', 'alice', 'alice@example.com');
    let res = await get('/oauth/github/start?intent=link');
    expect(res.status).toBe(302);
    expect(res.headers.get('Location')).toMatch(/^\/refresh\?return_to=/);

    const jar = await login('alice');
    github('c-l', 800, 'alice-gh', [{ email: 'other@example.com', primary: true, verified: true }]);
    const { res: cb } = await oauth('github', 'c-l', jar, 'intent=link');
    expect(cb.status).toBe(302);
    expect(cb.headers.get('Location')).toBe(`${ORIGIN}/profile`);
    expect(await index().findIdentity('github', '800')).toBe('usr_01JAAAAAAAAAAAAAAAAAAAAAAA');
    const creds = await fake.users.get('usr_01JAAAAAAAAAAAAAAAAAAAAAAA').listOAuthCredentials();
    expect(creds).toMatchObject([{ provider: 'github', subject: '800', email: 'other@example.com' }]);

    vi.setSystemTime(START + config.REAUTH_WINDOW + 60_000);
    res = await get('/oauth/github/start?intent=link', jar);
    expect(res.status).toBe(302);
    expect(res.headers.get('Location')).toMatch(/^\/login\?reauth=1/);
  });

  it('refuses an identity linked to another account, and a callback without the starting session', async () => {
    await passwordAccount('usr_01JAAAAAAAAAAAAAAAAAAAAAAA', 'alice', 'alice@example.com');
    const bob = await githubSignup('c-b', 900, 'bobgh', 'bob@example.com');
    const jar = await login('alice');
    codes.set('c-b2', codes.get('c-b')!);
    const { res } = await oauth('github', 'c-b2', jar, 'intent=link');
    expect(res.status).toBe(409);
    expect(await res.text()).toContain('already linked to a different');
    expect(await index().findIdentity('github', '900')).toBe(bob.userId);
    expect(await fake.users.get('usr_01JAAAAAAAAAAAAAAAAAAAAAAA').listOAuthCredentials()).toEqual([]);

    github('c-x', 901, 'x', [{ email: 'x@example.com', primary: true, verified: true }]);
    const start = await get('/oauth/github/start?intent=link', jar);
    const state = new URL(start.headers.get('Location')!).searchParams.get('state')!;
    const stateJar = absorb({}, start);
    const cb = await get(`/oauth/github/callback?code=c-x&state=${state}`, stateJar);
    expect(cb.status).toBe(400);
    expect(await cb.text()).toContain('signed in or out while linking');
    expect(await index().findIdentity('github', '901')).toBeNull();
  });
});

describe('profile section and unlink', () => {
  it('lists linked accounts with Unlink and offers Link buttons', async () => {
    const { userId, jar } = await githubSignup();
    const res = await app.request(`${ORIGIN}/profile`, { headers: cookieHeader(jar) }, fake.env);
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toContain('id="linked-accounts"');
    const [cred] = await fake.users.get(userId).listOAuthCredentials();
    expect(body).toContain(`value="${cred.id}"`);
    expect(body).toContain('data-api="/oauth/social/unlink"');
    expect(body).toContain('/oauth/google/start?return_to=');
    expect(body).toContain('intent=link');
  });

  it('refuses to remove the last sign-in method, needs a recent login, then unlinks', async () => {
    const { userId, jar } = await githubSignup();
    const [cred] = await fake.users.get(userId).listOAuthCredentials();
    let res = await post('/oauth/social/unlink', { credentialId: cred.id }, jar);
    expect(res.status).toBe(409);
    expect(await res.json()).toMatchObject({ error: 'last_method' });

    await fake.users.get(userId).setPassword('v2$password123');
    vi.setSystemTime(START + config.REAUTH_WINDOW + 60_000);
    res = await post('/oauth/social/unlink', { credentialId: cred.id }, jar);
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ error: 'reauth_required', reauthUrl: expect.stringContaining('/login?reauth=1') });

    vi.setSystemTime(START);
    expect((await post('/oauth/social/unlink', { credentialId: 'nope' }, jar)).status).toBe(400);
    expect((await post('/oauth/social/unlink', { credentialId: cred.id })).status).toBe(401);
    res = await post('/oauth/social/unlink', { credentialId: cred.id }, jar);
    expect(await res.json()).toEqual({ ok: true });
    expect(await index().findIdentity('github', '500')).toBeNull();
    expect(await fake.users.get(userId).listOAuthCredentials()).toEqual([]);
  });
});

describe('disabled accounts', () => {
  it('a known identity of a disabled account cannot sign in', async () => {
    const { userId } = await githubSignup();
    await fake.users.get(userId).setDisabled(true, 'usr_admin');
    codes.set('c-again', codes.get('c-new')!);
    const { res, jar } = await oauth('github', 'c-again', {});
    expect(res.status).toBe(403);
    expect(await res.text()).toContain('disabled');
    expect(jar[config.ACCESS_COOKIE]).toBeUndefined();
  });
});

describe('adapters', () => {
  it('GitHub email choice: primary verified, else any verified, else unverified primary', () => {
    expect(pickGitHubEmail([
      { email: 'a@x', primary: false, verified: true }, { email: 'b@x', primary: true, verified: true },
    ])).toEqual({ email: 'b@x', emailVerified: true });
    expect(pickGitHubEmail([
      { email: 'a@x', primary: false, verified: true }, { email: 'b@x', primary: true, verified: false },
    ])).toEqual({ email: 'a@x', emailVerified: true });
    expect(pickGitHubEmail([{ email: 'b@x', primary: true, verified: false }])).toEqual({ email: 'b@x', emailVerified: false });
    expect(pickGitHubEmail('garbage', 'pub@x')).toEqual({ email: 'pub@x', emailVerified: false });
  });

  it('Google id_token: wrong audience, issuer or expiry is rejected', async () => {
    const deps = { fetch: mockFetch as typeof fetch };
    const good = await googleIdToken({ sub: 's', email: 'e@x', email_verified: true });
    expect(await verifyGoogleIdToken(good, 'g-client', deps)).toMatchObject({ subject: 's', emailVerified: true });
    await expect(verifyGoogleIdToken(good, 'other-client', deps)).rejects.toThrow();
    await expect(verifyGoogleIdToken(await googleIdToken({ sub: 's', iss: 'https://evil.example' }), 'g-client', deps)).rejects.toThrow();
    const expired = await new SignJWT({ iss: 'accounts.google.com', aud: 'g-client', sub: 's' })
      .setProtectedHeader({ alg: 'RS256', kid: 'gk1' })
      .setIssuedAt(Math.floor(Date.now() / 1000) - 7200)
      .setExpirationTime(Math.floor(Date.now() / 1000) - 3600)
      .sign(googleKey);
    await expect(verifyGoogleIdToken(expired, 'g-client', deps)).rejects.toThrow();
    const unverified = await googleIdToken({ sub: 's', email: 'e@x', email_verified: 'true' });
    expect(await verifyGoogleIdToken(unverified, 'g-client', deps)).toMatchObject({ emailVerified: false });
  });

  it('oauth-signup.js is served and parses', async () => {
    const res = await get('/assets/oauth-signup.js');
    expect(res.status).toBe(200);
    const source = await res.text();
    expect(() => new Function(source)).not.toThrow();
  });
});
