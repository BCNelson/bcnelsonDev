import { decodeJwt } from 'jose';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { config } from '../src/config';
import type { Env } from '../src/env';
import { resetKeyCache, signAccessToken } from '../src/tokens';
import { dummyCalls, lastCode, makeFakeEnv, type FakeEnv } from './do/fake-env';

vi.mock('cloudflare:workers', async () => ({
  DurableObject: (await import('./do/fake-storage')).FakeDurableObject,
}));
vi.mock('../src/crypto/password', async () => (await import('./do/fake-env')).fakePasswordModule());

const { User } = await import('../src/do/user');
const { UserIndex } = await import('../src/do/user-index');
const { createApp } = await import('../src/app');

const ORIGIN = 'https://auth.bcnelson.dev';
const app = createApp();

let keyJson: string;
beforeAll(async () => {
  const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
  const jwk = (await crypto.subtle.exportKey('jwk', pair.privateKey)) as JsonWebKey;
  keyJson = JSON.stringify({ kty: 'OKP', crv: 'Ed25519', x: jwk.x, d: jwk.d, kid: 'k1' });
  // Turnstile siteverify: token "good" passes.
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
  fake = makeFakeEnv({ User, UserIndex }, { AUTH_SIGNING_KEY_DEV: keyJson } as Partial<Env>);
});
afterEach(() => {
  vi.useRealTimers();
});

interface PostOptions {
  form?: boolean;
  headers?: Record<string, string>;
}

function post(path: string, data: Record<string, string>, opts: PostOptions = {}) {
  const headers: Record<string, string> = { Origin: ORIGIN, 'CF-Connecting-IP': '1.2.3.4', ...opts.headers };
  let body: string;
  if (opts.form) {
    headers['Content-Type'] = 'application/x-www-form-urlencoded';
    body = new URLSearchParams(data).toString();
  } else {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(data);
  }
  return app.request(`${ORIGIN}${path}`, { method: 'POST', headers, body }, fake.env);
}

function get(path: string, headers: Record<string, string> = {}) {
  return app.request(`${ORIGIN}${path}`, { headers }, fake.env);
}

function cookies(res: Response): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of res.headers.getSetCookie()) {
    const [pair] = line.split(';');
    const i = pair!.indexOf('=');
    out[pair!.slice(0, i)] = pair!.slice(i + 1);
  }
  return out;
}

async function signUp(username = 'Brad', email = 'brad@example.com', password = 'correct-horse') {
  const start = await post('/signup/start', { username, email, turnstile: 'good' });
  expect(start.status).toBe(200);
  const { signupId } = (await start.json()) as { signupId: string };
  const verify = await post('/signup/verify', { signupId, code: lastCode(fake.mail) });
  expect(await verify.json()).toEqual({ ok: true });
  return post('/signup/complete', { signupId, password, return_to: 'https://app.bcnelson.dev/after' });
}

describe('signup routes', () => {
  it('start → verify → complete sets cookies and returns the redirect', async () => {
    const res = await signUp();
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, redirect: 'https://app.bcnelson.dev/after' });
    const set = cookies(res);
    expect(set[config.REFRESH_COOKIE]).toMatch(/^rt1\.usr_/);
    const claims = decodeJwt(set[config.ACCESS_COOKIE]!);
    expect(claims).toMatchObject({ preferred_username: 'Brad', email: 'brad@example.com', amr: ['pwd'] });
    expect(claims.roles).toBeUndefined();
    expect(res.headers.get('Cache-Control')).toBe('no-store');
  });

  it('accepts form-encoded bodies', async () => {
    const res = await post('/signup/start', { username: 'formuser', email: 'f@example.com', turnstile: 'good' }, { form: true });
    expect(await res.json()).toMatchObject({ ok: true, signupId: expect.stringMatching(/^sig_/) });
  });

  it('start validates input, Turnstile and username availability', async () => {
    let res = await post('/signup/start', { username: 'a', email: 'a@example.com', turnstile: 'good' });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ ok: false, error: 'invalid_username', message: expect.any(String) });

    res = await post('/signup/start', { username: 'brad', email: 'nope', turnstile: 'good' });
    expect(await res.json()).toMatchObject({ error: 'invalid_email' });

    res = await post('/signup/start', { username: 'brad', email: 'b@example.com', turnstile: 'bad' });
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ error: 'turnstile_failed' });
    expect(fake.mail).toHaveLength(0);

    await signUp('taken', 't@example.com');
    res = await post('/signup/start', { username: 'TAKEN', email: 'x@example.com', turnstile: 'good' });
    expect(res.status).toBe(409);
    expect(await res.json()).toMatchObject({ error: 'username_taken' });
  });

  it('start requires an allowed Origin', async () => {
    const res = await post('/signup/start', { username: 'brad', email: 'b@example.com', turnstile: 'good' },
      { headers: { Origin: 'https://evil.example' } });
    expect(res.status).toBe(403);
  });

  it('IP and identifier limits apply', async () => {
    fake.limits.ip = false;
    let res = await post('/signup/start', { username: 'brad', email: 'b@example.com', turnstile: 'good' });
    expect(res.status).toBe(429);
    fake.limits.ip = true;
    fake.limits.identifier = false;
    res = await post('/signup/start', { username: 'brad', email: 'b@example.com', turnstile: 'good' });
    expect(res.status).toBe(429);
  });

  it('verify maps errors', async () => {
    const start = await post('/signup/start', { username: 'brad', email: 'b@example.com', turnstile: 'good' });
    const { signupId } = (await start.json()) as { signupId: string };
    const wrong = lastCode(fake.mail) === '000000' ? '111111' : '000000';
    let res = await post('/signup/verify', { signupId, code: wrong });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: 'invalid_code' });
    res = await post('/signup/verify', { signupId: 'nope', code: wrong });
    expect(await res.json()).toMatchObject({ error: 'bad_request' });
  });

  it('complete refuses unverified signups and weak passwords', async () => {
    const start = await post('/signup/start', { username: 'brad', email: 'b@example.com', turnstile: 'good' });
    const { signupId } = (await start.json()) as { signupId: string };
    let res = await post('/signup/complete', { signupId, password: 'correct-horse' });
    expect(await res.json()).toMatchObject({ error: 'not_verified' });

    await post('/signup/verify', { signupId, code: lastCode(fake.mail) });
    res = await post('/signup/complete', { signupId, password: 'short' });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: 'weak_password' });
    expect(fake.users.instances.size).toBe(0);

    res = await post('/signup/complete', { signupId });
    expect(await res.json()).toMatchObject({ error: 'bad_request' });
  });

  it('complete fails generically when the email was claimed meanwhile', async () => {
    const a = await post('/signup/start', { username: 'first', email: 'same@example.com', turnstile: 'good' });
    const idA = ((await a.json()) as { signupId: string }).signupId;
    await post('/signup/verify', { signupId: idA, code: lastCode(fake.mail) });
    const b = await post('/signup/start', { username: 'second', email: 'same@example.com', turnstile: 'good' });
    const idB = ((await b.json()) as { signupId: string }).signupId;
    await post('/signup/verify', { signupId: idB, code: lastCode(fake.mail) });
    expect((await post('/signup/complete', { signupId: idA, password: 'correct-horse' })).status).toBe(200);
    const res = await post('/signup/complete', { signupId: idB, password: 'correct-horse' });
    expect(res.status).toBe(409);
    expect(await res.json()).toMatchObject({ error: 'signup_failed' });
  });

  it('ADMIN_EMAILS bootstraps the admin role at signup', async () => {
    fake = makeFakeEnv({ User, UserIndex }, { AUTH_SIGNING_KEY_DEV: keyJson, ADMIN_EMAILS: 'x@x.io, Brad@Example.com' } as Partial<Env>);
    const res = await signUp();
    expect(decodeJwt(cookies(res)[config.ACCESS_COOKIE]!).roles).toEqual(['admin']);
  });
});

describe('POST /login/password', () => {
  beforeEach(async () => {
    await signUp();
    fake.mail.length = 0;
  });

  it('logs in by username or email', async () => {
    for (const identifier of ['brad', 'BRAD@example.com']) {
      const res = await post('/login/password', { identifier, password: 'correct-horse' });
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ ok: true, redirect: 'https://bcnelson.dev/' });
      expect(cookies(res)[config.ACCESS_COOKIE]).toBeTruthy();
    }
  });

  it('validates return_to from the body or the query', async () => {
    let res = await post('/login/password', { identifier: 'brad', password: 'correct-horse', return_to: 'https://evil.example/' });
    expect(await res.json()).toMatchObject({ redirect: 'https://bcnelson.dev/' });
    res = await post(`/login/password?return_to=${encodeURIComponent('https://app.bcnelson.dev/x')}`,
      { identifier: 'brad', password: 'correct-horse' });
    expect(await res.json()).toMatchObject({ redirect: 'https://app.bcnelson.dev/x' });
  });

  it('unknown user and wrong password get the same answer', async () => {
    const before = dummyCalls.count;
    const unknown = await post('/login/password', { identifier: 'nobody', password: 'correct-horse' });
    expect(dummyCalls.count).toBe(before + 1);
    const wrong = await post('/login/password', { identifier: 'brad', password: 'wrong-password' });
    expect(unknown.status).toBe(401);
    expect(wrong.status).toBe(401);
    expect(await unknown.json()).toEqual(await wrong.json());
  });

  it('missing fields → 400; limits → 429', async () => {
    expect((await post('/login/password', { identifier: 'brad' })).status).toBe(400);
    fake.limits.identifier = false;
    expect((await post('/login/password', { identifier: 'brad', password: 'x' })).status).toBe(429);
    fake.limits.ip = false;
    expect((await post('/login/password', { identifier: 'brad', password: 'x' })).status).toBe(429);
  });

  it('backoff: turnstile_required, then locked with Retry-After', async () => {
    for (let i = 0; i < config.TURNSTILE_AFTER_FAILURES; i++) {
      await post('/login/password', { identifier: 'brad', password: 'wrong-password' });
    }
    let res = await post('/login/password', { identifier: 'brad', password: 'correct-horse' });
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ error: 'turnstile_required' });
    res = await post('/login/password', { identifier: 'brad', password: 'correct-horse', turnstile: 'bad' });
    expect(await res.json()).toMatchObject({ error: 'turnstile_required' });

    for (let i = config.TURNSTILE_AFTER_FAILURES; i < config.BACKOFF_AFTER_FAILURES; i++) {
      await post('/login/password', { identifier: 'brad', password: 'wrong-password', turnstile: 'good' });
    }
    res = await post('/login/password', { identifier: 'brad', password: 'correct-horse', turnstile: 'good' });
    expect(res.status).toBe(429);
    expect(res.headers.get('Retry-After')).toBe(String(config.BACKOFF_BASE / 1000));
    expect(await res.json()).toMatchObject({ error: 'locked', retryAfterMs: expect.any(Number), message: /1 minute/ });
  });

  it('no-JS form posts get 303 redirects', async () => {
    let res = await post('/login/password', { identifier: 'brad', password: 'correct-horse', return_to: 'https://app.bcnelson.dev/' }, { form: true });
    expect(res.status).toBe(303);
    expect(res.headers.get('Location')).toBe('https://app.bcnelson.dev/');
    expect(cookies(res)[config.ACCESS_COOKIE]).toBeTruthy();

    res = await post('/login/password', { identifier: 'brad', password: 'nope' }, { form: true });
    expect(res.status).toBe(303);
    expect(res.headers.get('Location')).toBe(`/login?error=invalid_credentials&return_to=${encodeURIComponent('https://bcnelson.dev/')}`);

    // A form post that asks for JSON gets JSON.
    res = await post('/login/password', { identifier: 'brad', password: 'nope' }, { form: true, headers: { Accept: 'application/json' } });
    expect(res.status).toBe(401);
  });

  it('ADMIN_EMAILS bootstraps the admin role on login', async () => {
    (fake.env as { ADMIN_EMAILS: string }).ADMIN_EMAILS = 'brad@example.com';
    const res = await post('/login/password', { identifier: 'brad', password: 'correct-horse' });
    expect(decodeJwt(cookies(res)[config.ACCESS_COOKIE]!).roles).toEqual(['admin']);
  });
});

describe('pages', () => {
  it('GET /login renders the form with CSP and no inline script', async () => {
    const res = await get('/login?return_to=https%3A%2F%2Fapp.bcnelson.dev%2F');
    expect(res.status).toBe(200);
    expect(res.headers.get('Content-Type')).toMatch(/text\/html/);
    const csp = res.headers.get('Content-Security-Policy')!;
    expect(csp).toContain("script-src 'self' https://challenges.cloudflare.com");
    expect(csp).toContain("frame-ancestors 'none'");
    const nonce = /style-src 'nonce-([^']+)'/.exec(csp)![1];
    const body = await res.text();
    expect(body).toContain(`<style nonce="${nonce}">`);
    expect(body).toContain('id="login-form"');
    expect(body).toContain('value="https://app.bcnelson.dev/"');
    expect(body).toContain('href="/password/forgot?return_to=https%3A%2F%2Fapp.bcnelson.dev%2F"');
    expect(body).toContain('data-slot="passkey-login"');
    expect(body).toContain('data-slot="social-login"');
    expect(body).toContain('data-sitekey="test-site-key"');
    expect(body).not.toMatch(/<script(?![^>]*\ssrc=)[^>]*>/);
    expect(body).toContain('<script src="/assets/app.js" defer></script>');
    expect(body).toContain('<script src="/assets/login.js" defer></script>');
  });

  it('GET /login escapes and filters ?error and return_to', async () => {
    const res = await get('/login?error=%3Cscript%3E&return_to=https%3A%2F%2Fevil.example');
    const body = await res.text();
    expect(body).not.toContain('<script>');
    expect(body).toContain('value="https://bcnelson.dev/"');
    const known = await (await get('/login?error=invalid_credentials')).text();
    expect(known).toContain('Incorrect username, email or password.');
  });

  it('GET / redirects to the profile when signed in, otherwise to sign-in', async () => {
    let page = await get('/');
    expect(page.status).toBe(302);
    const toLogin = `/login?return_to=${encodeURIComponent(`${fake.env.ISSUER}/profile`)}`;
    expect(page.headers.get('Location')).toBe(toLogin);

    const res = await signUp();
    page = await get('/', { Cookie: `${config.ACCESS_COOKIE}=${cookies(res)[config.ACCESS_COOKIE]!}` });
    expect(page.status).toBe(302);
    expect(page.headers.get('Location')).toBe('/profile');

    // A refresh cookie alone goes through /login, which refreshes and returns to the profile.
    page = await get('/', { Cookie: `${config.REFRESH_COOKIE}=${cookies(res)[config.REFRESH_COOKIE]!}` });
    expect(page.headers.get('Location')).toBe(toLogin);
  });

  it('GET /login redirects when already signed in, or via /refresh with only a refresh cookie', async () => {
    const res = await signUp();
    const at = cookies(res)[config.ACCESS_COOKIE]!;
    const rt = cookies(res)[config.REFRESH_COOKIE]!;
    let page = await get('/login?return_to=https%3A%2F%2Fapp.bcnelson.dev%2Fx', { Cookie: `${config.ACCESS_COOKIE}=${at}` });
    expect(page.status).toBe(302);
    expect(page.headers.get('Location')).toBe('https://app.bcnelson.dev/x');

    page = await get('/login', { Cookie: `${config.REFRESH_COOKIE}=${rt}` });
    expect(page.status).toBe(302);
    expect(page.headers.get('Location')).toBe(`/refresh?return_to=${encodeURIComponent('https://bcnelson.dev/')}`);

    // An invalid access token is ignored.
    const bogus = await signAccessToken({ ...fake.env, ISSUER: 'https://other' } as Env, decodeJwt(at) as never);
    page = await get('/login', { Cookie: `${config.ACCESS_COOKIE}=${bogus.token}` });
    expect(page.status).toBe(200);
  });

  it('GET /signup renders three steps', async () => {
    const res = await get('/signup');
    expect(res.status).toBe(200);
    const body = await res.text();
    for (const id of ['signup-start', 'signup-verify', 'signup-complete']) expect(body).toContain(`id="${id}"`);
    expect(body).toContain('data-slot="passkey-signup"');
    expect(body).toContain('/assets/signup.js');
    expect(body).toContain('turnstile/v0/api.js?render=explicit');
  });

  it('serves registered assets only', async () => {
    const res = await get('/assets/app.js');
    expect(res.status).toBe(200);
    expect(res.headers.get('Content-Type')).toMatch(/javascript/);
    expect(await res.text()).toContain('window.bcn');
    expect((await get('/assets/login.js')).status).toBe(200);
    expect((await get('/assets/signup.js')).status).toBe(200);
    expect((await get('/assets/nope.js')).status).toBe(404);
  });

  it('client scripts parse', async () => {
    for (const name of ['app.js', 'login.js', 'signup.js']) {
      const source = await (await get(`/assets/${name}`)).text();
      expect(() => new Function(source)).not.toThrow();
    }
  });
});
