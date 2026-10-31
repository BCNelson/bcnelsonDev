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

function post(path: string, data: Record<string, string>, opts: { form?: boolean; headers?: Record<string, string> } = {}) {
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
  const { signupId } = (await start.json()) as { signupId: string };
  await post('/signup/verify', { signupId, code: lastCode(fake.mail) });
  const res = await post('/signup/complete', { signupId, password });
  expect(res.status).toBe(200);
  return res;
}

/** The token from the reset link in the most recent mail. */
function lastToken(): string {
  const match = /token=([^\s]+)/.exec(fake.mail.at(-1)?.text ?? '');
  if (!match) throw new Error('no reset link in last mail');
  return decodeURIComponent(match[1]!);
}

async function forgot(email = 'brad@example.com') {
  return post('/password/forgot', { email, turnstile: 'good' });
}

describe('POST /password/forgot', () => {
  beforeEach(async () => {
    await signUp();
    fake.mail.length = 0;
  });

  it('mails a pr1 link to that address and answers { ok: true }', async () => {
    const res = await forgot('BRAD@example.com');
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
    expect(res.headers.get('Cache-Control')).toBe('no-store');
    expect(fake.mail).toHaveLength(1);
    expect(fake.mail[0]!.to).toBe('brad@example.com');
    expect(lastToken()).toMatch(/^pr1\.usr_[0-9A-Z]{26}\.[A-Za-z0-9_-]{43}$/);
  });

  it('unknown email, over the per-user limit, or failing mail: the same response', async () => {
    const known = await forgot();
    const unknown = await forgot('nobody@example.com');
    expect(unknown.status).toBe(known.status);
    expect(await unknown.json()).toEqual({ ok: true });
    expect(fake.mail).toHaveLength(1);

    const [max] = config.ACTION_LIMITS.password_reset!;
    for (let i = 1; i < max; i++) await forgot();
    expect(fake.mail).toHaveLength(max);
    const limited = await forgot();
    expect(limited.status).toBe(200);
    expect(await limited.json()).toEqual({ ok: true });
    expect(fake.mail).toHaveLength(max);

    fake.failMail.value = true;
    expect(await (await forgot('nobody2@example.com')).json()).toEqual({ ok: true });
  });

  it('validates input and Turnstile; IP and identifier limits', async () => {
    let res = await post('/password/forgot', { email: 'nope', turnstile: 'good' });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ ok: false, error: 'invalid_email' });
    res = await post('/password/forgot', { email: 'brad@example.com', turnstile: 'bad' });
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ error: 'turnstile_failed' });
    fake.limits.identifier = false;
    expect((await forgot()).status).toBe(429);
    fake.limits.ip = false;
    expect((await forgot()).status).toBe(429);
    expect(fake.mail).toHaveLength(0);
  });

  it('requires an allowed Origin', async () => {
    const res = await post('/password/forgot', { email: 'brad@example.com', turnstile: 'good' }, { headers: { Origin: 'https://evil.example' } });
    expect(res.status).toBe(403);
    expect(fake.mail).toHaveLength(0);
  });

  it('no-JS form posts get 303s', async () => {
    let res = await post('/password/forgot', { email: 'brad@example.com', turnstile: 'good' }, { form: true });
    expect(res.status).toBe(303);
    expect(res.headers.get('Location')).toBe(`/password/forgot?sent=1&return_to=${encodeURIComponent('https://bcnelson.dev/')}`);
    res = await post('/password/forgot', { email: 'x', turnstile: 'good' }, { form: true });
    expect(res.headers.get('Location')).toMatch(/^\/password\/forgot\?error=invalid_email/);
  });
});

describe('POST /password/reset', () => {
  let loginCookies: Record<string, string>;
  beforeEach(async () => {
    loginCookies = cookies(await signUp());
    fake.mail.length = 0;
  });

  it('sets the password, revokes sessions, alerts, clears cookies and sends to /login (no auto-login)', async () => {
    await forgot();
    const token = lastToken();
    fake.mail.length = 0;

    const res = await post('/password/reset', { token, password: 'new-password-1' });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, redirect: '/login?notice=password_updated' });
    const set = cookies(res);
    expect(set[config.ACCESS_COOKIE]).toBe('');
    expect(Object.values(set).every((v) => v === '')).toBe(true);

    // The old refresh token no longer works.
    const refresh = await get('/refresh', { Cookie: `${config.REFRESH_COOKIE}=${loginCookies[config.REFRESH_COOKIE]}` });
    expect(refresh.headers.get('Location')).toMatch(/^\/login/);

    expect(fake.mail.map((m) => m.to)).toEqual(['brad@example.com']);
    expect(fake.mail[0]!.subject).toMatch(/password was changed/);

    expect((await post('/login/password', { identifier: 'brad', password: 'correct-horse' })).status).toBe(401);
    expect((await post('/login/password', { identifier: 'brad', password: 'new-password-1' })).status).toBe(200);

    // Single use.
    const again = await post('/password/reset', { token, password: 'new-password-2' });
    expect(again.status).toBe(400);
    expect(await again.json()).toMatchObject({ error: 'invalid_token' });
  });

  it('rejects forged, malformed, foreign-user and expired tokens', async () => {
    await forgot();
    const token = lastToken();
    const [prefix, userId, secret] = token.split('.') as [string, string, string];
    const forged = `${prefix}.${userId}.${secret.slice(0, -1)}${secret.endsWith('A') ? 'B' : 'A'}`;
    for (const bad of [forged, 'garbage', `${prefix}.usr_01HZY3T9Q8N6VXK2M4R7B5C0DE.${secret}`]) {
      const res = await post('/password/reset', { token: bad, password: 'new-password-1' });
      expect(res.status).toBe(400);
      expect(await res.json()).toMatchObject({ error: 'invalid_token' });
    }
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(Date.now() + config.RESET_TTL + 1);
    const res = await post('/password/reset', { token, password: 'new-password-1' });
    expect(await res.json()).toMatchObject({ error: 'invalid_token' });
  });

  it('weak password, mismatched confirm, missing fields', async () => {
    await forgot();
    const token = lastToken();
    let res = await post('/password/reset', { token, password: 'short' });
    expect(await res.json()).toMatchObject({ error: 'weak_password' });
    res = await post('/password/reset', { token, password: 'new-password-1', confirm: 'other-password' });
    expect(await res.json()).toMatchObject({ error: 'password_mismatch' });
    res = await post('/password/reset', { token });
    expect(await res.json()).toMatchObject({ error: 'bad_request' });
    // None of that used the token up.
    expect((await post('/password/reset', { token, password: 'new-password-1' })).status).toBe(200);
  });

  it('IP limit', async () => {
    fake.limits.ip = false;
    expect((await post('/password/reset', { token: 'x', password: 'new-password-1' })).status).toBe(429);
  });

  it('no-JS form posts get 303s', async () => {
    await forgot();
    const token = lastToken();
    let res = await post('/password/reset', { token, password: 'short', confirm: 'short' }, { form: true });
    expect(res.status).toBe(303);
    expect(res.headers.get('Location')).toBe(`/password/reset?token=${encodeURIComponent(token)}&error=weak_password`);
    res = await post('/password/reset', { token, password: 'new-password-1', confirm: 'new-password-1' }, { form: true });
    expect(res.status).toBe(303);
    expect(res.headers.get('Location')).toBe('/login?notice=password_updated');
  });
});

describe('password pages', () => {
  it('GET /password/forgot renders the form with Turnstile and no inline script', async () => {
    const res = await get('/password/forgot?return_to=https%3A%2F%2Fapp.bcnelson.dev%2F');
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toContain('id="forgot-form"');
    expect(body).toContain('data-sitekey="test-site-key"');
    expect(body).toContain('value="https://app.bcnelson.dev/"');
    expect(body).toContain('<script src="/assets/password-forgot.js" defer></script>');
    expect(body).toContain('turnstile/v0/api.js?render=explicit');
    expect(body).not.toMatch(/<script(?![^>]*\ssrc=)[^>]*>/);
    const sent = await (await get('/password/forgot?sent=1')).text();
    expect(sent).toMatch(/<form id="forgot-form"[^>]*hidden/);
  });

  it('GET /password/reset shows the form for a live token, an error otherwise', async () => {
    await signUp();
    await post('/password/forgot', { email: 'brad@example.com', turnstile: 'good' });
    const token = lastToken();
    const res = await get(`/password/reset?token=${encodeURIComponent(token)}`);
    expect(res.status).toBe(200);
    expect(res.headers.get('Referrer-Policy')).toBe('no-referrer');
    const body = await res.text();
    expect(body).toContain('id="reset-form"');
    expect(body).toContain(`name="token" value="${token}"`);
    expect(body).toContain('/assets/password-reset.js');
    expect(body).not.toMatch(/<script(?![^>]*\ssrc=)[^>]*>/);

    for (const bad of ['', '?token=nope', `?token=${encodeURIComponent(token.slice(0, -1) + 'x')}`]) {
      const page = await get(`/password/reset${bad}`);
      expect(page.status).toBe(400);
      const text = await page.text();
      expect(text).not.toContain('id="reset-form"');
      expect(text).toContain('href="/password/forgot"');
    }
  });

  it('GET /login shows the password_updated notice and the forgot link', async () => {
    const body = await (await get('/login?notice=password_updated')).text();
    expect(body).toContain('Password updated. Please sign in with your new password.');
    expect(body).toContain('href="/password/forgot?return_to=');
    const unknown = await (await get('/login?notice=%3Cb%3Ex')).text();
    expect(unknown).not.toContain('class="notice"');
  });

  it('client scripts parse', async () => {
    for (const name of ['password-forgot.js', 'password-reset.js']) {
      const res = await get(`/assets/${name}`);
      expect(res.status).toBe(200);
      const source = await res.text();
      expect(() => new Function(source)).not.toThrow();
    }
  });
});
