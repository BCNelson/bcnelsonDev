import { Hono } from 'hono';
import { decodeJwt } from 'jose';
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
const { requireReauth, requireSession } = await import('../src/http/auth');

const ORIGIN = 'https://auth.bcnelson.dev';
const PROFILE_URL = `${ORIGIN}/profile`;
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
  fake = makeFakeEnv({ User, UserIndex }, { AUTH_SIGNING_KEY_DEV: keyJson } as Partial<Env>);
});
afterEach(() => {
  vi.useRealTimers();
});

/** A browser's cookies; updated from every response. */
class Jar {
  values: Record<string, string> = {};
  update(res: Response): Response {
    for (const line of res.headers.getSetCookie()) {
      const [pair, ...attrs] = line.split(';');
      const i = pair!.indexOf('=');
      const name = pair!.slice(0, i);
      const value = pair!.slice(i + 1);
      if (attrs.some((a) => /max-age=0\b/i.test(a.trim())) || value === '') delete this.values[name];
      else this.values[name] = value;
    }
    return res;
  }
  header(): string {
    return Object.entries(this.values).map(([k, v]) => `${k}=${v}`).join('; ');
  }
  claims() {
    return decodeJwt(this.values[config.ACCESS_COOKIE]!);
  }
}

async function post(jar: Jar | null, path: string, data: unknown, headers: Record<string, string> = {}) {
  const res = await app.request(`${ORIGIN}${path}`, {
    method: 'POST',
    headers: {
      Origin: ORIGIN,
      'CF-Connecting-IP': '1.2.3.4',
      'Content-Type': 'application/json',
      ...(jar ? { Cookie: jar.header() } : {}),
      ...headers,
    },
    body: JSON.stringify(data),
  }, fake.env);
  return jar ? jar.update(res) : res;
}

async function get(jar: Jar | null, path: string, headers: Record<string, string> = {}) {
  const res = await app.request(`${ORIGIN}${path}`, { headers: { ...(jar ? { Cookie: jar.header() } : {}), ...headers } }, fake.env);
  return jar ? jar.update(res) : res;
}

async function signUp(username = 'Brad', email = 'brad@example.com', password = 'correct-horse'): Promise<Jar> {
  const jar = new Jar();
  const start = await post(null, '/signup/start', { username, email, turnstile: 'good' });
  const { signupId } = (await start.json()) as { signupId: string };
  await post(null, '/signup/verify', { signupId, code: lastCode(fake.mail) });
  const res = await post(jar, '/signup/complete', { signupId, password });
  expect(res.status).toBe(200);
  fake.mail.length = 0;
  return jar;
}

async function login(identifier = 'brad', password = 'correct-horse'): Promise<Jar> {
  const jar = new Jar();
  const res = await post(jar, '/login/password', { identifier, password });
  expect(res.status).toBe(200);
  return jar;
}

/** Move the clock past REAUTH_WINDOW but keep the access token valid. */
function staleLogin() {
  vi.setSystemTime(Date.now() + config.REAUTH_WINDOW + 1000);
}

describe('requireSession', () => {
  it('pages redirect to /refresh; APIs get 401 JSON', async () => {
    let res = await get(null, '/profile', { Accept: 'text/html' });
    expect(res.status).toBe(302);
    expect(res.headers.get('Location')).toBe(`/refresh?return_to=${encodeURIComponent(PROFILE_URL)}`);
    res = await get(null, '/api/me');
    expect(res.status).toBe(401);
    expect(await res.json()).toMatchObject({ ok: false, error: 'unauthorized' });
    expect((await post(null, '/api/me/profile', { name: 'x' })).status).toBe(401);
  });

  it('rejects a still-valid access token whose session was revoked', async () => {
    const jar = await signUp();
    const at = jar.values[config.ACCESS_COOKIE]!;
    await post(jar, '/logout', {});
    const res = await get(null, '/api/me', { Cookie: `${config.ACCESS_COOKIE}=${at}` });
    expect(res.status).toBe(401);
  });

  it('mutations still need an allowed Origin', async () => {
    const jar = await signUp();
    const res = await post(jar, '/api/me/profile', { name: 'x' }, { Origin: 'https://evil.example' });
    expect(res.status).toBe(403);
  });
});

describe('requireReauth', () => {
  const mini = new Hono<import('../src/http/auth').AuthEnv>();
  mini.get('/danger', requireSession(), requireReauth(), (c) => c.text(`ok ${c.get('user').preferred_username}`));

  it('passes within REAUTH_WINDOW, then redirects pages / answers APIs with reauthUrl', async () => {
    const jar = await signUp();
    let res = await mini.request(`${ORIGIN}/danger`, { headers: { Cookie: jar.header() } }, fake.env);
    expect(await res.text()).toBe('ok Brad');

    staleLogin();
    res = await mini.request(`${ORIGIN}/danger`, { headers: { Cookie: jar.header(), Accept: 'text/html' } }, fake.env);
    expect(res.status).toBe(302);
    expect(res.headers.get('Location')).toBe(`/login?reauth=1&return_to=${encodeURIComponent(`${ORIGIN}/danger`)}`);

    res = await post(jar, '/api/me/username', { username: 'newname' });
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({
      ok: false,
      error: 'reauth_required',
      message: expect.any(String),
      reauthUrl: `/login?reauth=1&return_to=${encodeURIComponent(PROFILE_URL)}`,
    });
    for (const [path, body] of [
      ['/api/me/emails', { email: 'x@example.com' }],
      ['/api/me/emails/primary', { email: 'brad@example.com' }],
      ['/api/me/emails/remove', { email: 'brad@example.com' }],
      ['/api/me/password', { currentPassword: 'correct-horse', newPassword: 'another-horse' }],
    ] as const) {
      expect((await post(jar, path, body)).status).toBe(403);
    }
    // Non-reauth actions still work.
    expect((await post(jar, '/api/me/profile', { name: 'Still fine' })).status).toBe(200);
  });

  it('GET /login?reauth=1 shows the form while signed in; the re-login replaces the old session', async () => {
    const jar = await signUp();
    const oldSid = jar.claims().sid;
    staleLogin();
    const page = await get(jar, `/login?reauth=1&return_to=${encodeURIComponent(PROFILE_URL)}`);
    expect(page.status).toBe(200);
    const body = await page.text();
    expect(body).toContain("Confirm it&#39;s you");
    expect(body).toContain('value="Brad"');
    expect(body).toContain('action="/login/password?reauth=1"');
    expect(body).toContain(`value="${PROFILE_URL}"`);

    const res = await post(jar, '/login/password', { identifier: 'Brad', password: 'correct-horse', return_to: PROFILE_URL });
    expect(await res.json()).toEqual({ ok: true, redirect: PROFILE_URL });
    expect(jar.claims().sid).not.toBe(oldSid);
    const me = (await (await get(jar, '/api/me')).json()) as { sessions: { id: string }[] };
    expect(me.sessions.map((s) => s.id)).toEqual([jar.claims().sid]);
    expect((await post(jar, '/api/me/username', { username: 'newname' })).status).toBe(200);
  });

  it('no-JS reauth failures come back to the reauth form', async () => {
    const res = await app.request(`${ORIGIN}/login/password?reauth=1`, {
      method: 'POST',
      headers: { Origin: ORIGIN, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ identifier: 'nobody', password: 'x', return_to: PROFILE_URL }).toString(),
    }, fake.env);
    expect(res.status).toBe(303);
    expect(res.headers.get('Location')).toBe(`/login?error=invalid_credentials&reauth=1&return_to=${encodeURIComponent(PROFILE_URL)}`);
  });
});

describe('GET /profile', () => {
  it('renders every section, the slots, and no inline script', async () => {
    const jar = await signUp();
    const res = await get(jar, '/profile', { Accept: 'text/html' });
    expect(res.status).toBe(200);
    expect(res.headers.get('Cache-Control')).toBe('no-store');
    const body = await res.text();
    for (const id of ['profile-form', 'username-form', 'add-email-form', 'password-form', 'h-sessions', 'h-sign-in']) {
      expect(body).toContain(`id="${id}"`);
    }
    expect(body).toContain('data-slot="passkeys"');
    expect(body).toContain('data-slot="admin"');
    expect(body).toContain('<strong>brad@example.com</strong> <span class="badge" data-primary>Primary</span>');
    expect(body).toContain(`data-session="${jar.claims().sid}"`);
    expect(body).toContain('data-current>This device');
    expect(body).toContain('id="current-password"');
    expect(body).not.toMatch(/<script(?![^>]*\ssrc=)[^>]*>/);
    expect(body).toContain('<script src="/assets/profile.js" defer></script>');
    const js = await (await get(null, '/assets/profile.js')).text();
    expect(() => new Function(js)).not.toThrow();
  });

  it('PROFILE_SLOTS providers fill the slots; without one, the generic credential list shows', async () => {
    const { PROFILE_SLOTS } = await import('../src/routes/profile');
    const { html } = await import('hono/html');
    const saved = { ...PROFILE_SLOTS };
    try {
      const jar = await signUp();
      delete PROFILE_SLOTS.passkeys;
      delete PROFILE_SLOTS.admin;
      let body = await (await get(jar, '/profile')).text();
      expect(body).toContain('No passkeys or linked accounts yet.');

      PROFILE_SLOTS.passkeys = ({ account }) => ({ html: html`<p id="pk">passkeys for ${account.profile.username}</p>` });
      PROFILE_SLOTS.admin = () => ({ html: html`<a href="/admin">Admin</a>` });
      body = await (await get(jar, '/profile')).text();
      expect(body).toContain('<p id="pk">passkeys for Brad</p>');
      expect(body).toContain('<a href="/admin">Admin</a>');
      expect(body).not.toContain('No passkeys or linked accounts yet.');
    } finally {
      delete PROFILE_SLOTS.passkeys;
      delete PROFILE_SLOTS.admin;
      Object.assign(PROFILE_SLOTS, saved);
    }
  });
});

describe('/api/me', () => {
  it('GET /api/me and /api/me/credentials shapes', async () => {
    const jar = await signUp();
    const res = await get(jar, '/api/me');
    expect(res.headers.get('Cache-Control')).toBe('no-store');
    const me = (await res.json()) as Record<string, any>;
    expect(me).toMatchObject({
      ok: true,
      profile: { username: 'Brad', name: null, picture: null, roles: [] },
      emails: [{ email: 'brad@example.com', primary: true }],
      pendingEmails: [],
      hasPassword: true,
      currentSessionId: jar.claims().sid,
    });
    expect(me.sessions).toEqual([expect.objectContaining({ id: jar.claims().sid, current: true })]);
    const creds = (await (await get(jar, '/api/me/credentials')).json()) as Record<string, any>;
    expect(creds.credentials).toEqual([
      { id: expect.stringMatching(/^cred_/), type: 'password', label: null, createdAt: expect.any(Number), lastUsedAt: null },
    ]);
    expect(JSON.stringify(creds)).not.toContain('correct-horse');
  });

  it('profile edits validate and re-issue the access token', async () => {
    const jar = await signUp();
    let res = await post(jar, '/api/me/profile', { name: 'Bradley', picture: 'https://img.example/me.png' });
    expect(await res.json()).toMatchObject({ ok: true, profile: { name: 'Bradley', picture: 'https://img.example/me.png' } });
    expect(jar.claims()).toMatchObject({ name: 'Bradley', picture: 'https://img.example/me.png' });
    res = await post(jar, '/api/me/profile', { picture: 'http://img.example/x.png' });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: 'invalid_picture' });
    res = await post(jar, '/api/me/profile', { name: 'x'.repeat(101) });
    expect(await res.json()).toMatchObject({ error: 'invalid_name' });
    // Long (but valid) picture URLs beyond MAX_FIELD_LENGTH are accepted.
    const long = `https://img.example/${'a'.repeat(1500)}`;
    expect((await post(jar, '/api/me/profile', { picture: long })).status).toBe(200);
    expect((await post(jar, '/api/me/profile', { name: 42 })).status).toBe(400);
  });

  it('username change: new claims, errors for taken and cooldown', async () => {
    await signUp('taken', 'taken@example.com');
    const jar = await signUp();
    let res = await post(jar, '/api/me/username', { username: 'TAKEN' });
    expect(res.status).toBe(409);
    expect(await res.json()).toMatchObject({ error: 'username_taken' });
    res = await post(jar, '/api/me/username', { username: 'x' });
    expect(await res.json()).toMatchObject({ error: 'invalid_username', message: expect.stringMatching(/3–30/) });
    res = await post(jar, '/api/me/username', { username: 'Bradley' });
    expect(await res.json()).toEqual({ ok: true, username: 'Bradley' });
    expect(jar.claims().preferred_username).toBe('Bradley');
    res = await post(jar, '/api/me/username', { username: 'third' });
    expect(res.status).toBe(429);
    expect(await res.json()).toMatchObject({ error: 'username_cooldown', retryAfterMs: config.USERNAME_CHANGE_COOLDOWN });
    // Old name no longer logs in; new one does.
    expect((await post(null, '/login/password', { identifier: 'brad', password: 'correct-horse' })).status).toBe(401);
    expect((await post(null, '/login/password', { identifier: 'bradley', password: 'correct-horse' })).status).toBe(200);
  });

  it('email add → verify → primary → remove', async () => {
    const jar = await signUp();
    let res = await post(jar, '/api/me/emails', { email: 'Second@Example.com' });
    expect(await res.json()).toMatchObject({ ok: true, email: 'second@example.com', expiresAt: expect.any(Number) });
    const code = lastCode(fake.mail);
    res = await post(jar, '/api/me/emails/verify', { email: 'second@example.com', code: '000000' === code ? '111111' : '000000' });
    expect(await res.json()).toMatchObject({ error: 'invalid_code' });
    res = await post(jar, '/api/me/emails/verify', { email: 'second@example.com', code: ` ${code} ` });
    expect(await res.json()).toEqual({ ok: true, email: 'second@example.com' });

    res = await post(jar, '/api/me/emails', { email: 'second@example.com' });
    expect(res.status).toBe(409);
    expect(await res.json()).toMatchObject({ error: 'already_added' });

    res = await post(jar, '/api/me/emails/primary', { email: 'second@example.com' });
    expect(await res.json()).toEqual({ ok: true, changed: true });
    expect(jar.claims().email).toBe('second@example.com');
    res = await post(jar, '/api/me/emails/primary', { email: 'nope@example.com' });
    expect(res.status).toBe(404);

    res = await post(jar, '/api/me/emails/remove', { email: 'second@example.com' });
    expect(await res.json()).toMatchObject({ error: 'primary_required' });
    res = await post(jar, '/api/me/emails/remove', { email: 'second@example.com', newPrimary: 'brad@example.com' });
    expect(await res.json()).toEqual({ ok: true });
    expect(jar.claims().email).toBe('brad@example.com');
    res = await post(jar, '/api/me/emails/remove', { email: 'brad@example.com' });
    expect(res.status).toBe(409);
    expect(await res.json()).toMatchObject({ error: 'last_email' });
  });

  it("adding another account's address looks the same until verification", async () => {
    await signUp('other', 'other@example.com');
    const jar = await signUp();
    const res = await post(jar, '/api/me/emails', { email: 'other@example.com' });
    expect(await res.json()).toMatchObject({ ok: true, email: 'other@example.com' });
    const verify = await post(jar, '/api/me/emails/verify', { email: 'other@example.com', code: lastCode(fake.mail) });
    expect(verify.status).toBe(409);
    expect(await verify.json()).toMatchObject({ error: 'email_unavailable' });
  });

  it('password change: checks the current one, revokes other sessions, alerts', async () => {
    const jar = await signUp();
    const other = await login();
    let res = await post(jar, '/api/me/password', { newPassword: 'short' });
    expect(await res.json()).toMatchObject({ error: 'weak_password' });
    res = await post(jar, '/api/me/password', { newPassword: 'another-horse' });
    expect(await res.json()).toMatchObject({ error: 'current_password_required' });
    res = await post(jar, '/api/me/password', { currentPassword: 'wrong', newPassword: 'another-horse' });
    expect(await res.json()).toMatchObject({ error: 'invalid_password' });
    res = await post(jar, '/api/me/password', { currentPassword: 'correct-horse', newPassword: 'another-horse' });
    expect(await res.json()).toEqual({ ok: true, revokedSessions: 1 });
    expect((await get(other, '/api/me')).status).toBe(401);
    expect((await get(jar, '/api/me')).status).toBe(200);
    expect(fake.mail.some((m) => m.to === 'brad@example.com' && /password was changed/.test(m.subject))).toBe(true);
    expect((await post(null, '/login/password', { identifier: 'brad', password: 'another-horse' })).status).toBe(200);
  });

  it('sessions: revoke one, revoke others, revoke current clears cookies', async () => {
    const jar = await signUp();
    const b = await login();
    const c = await login();
    let res = await post(jar, `/api/me/sessions/${b.claims().sid}/revoke`, {});
    expect(await res.json()).toEqual({ ok: true, current: false });
    expect((await get(b, '/api/me')).status).toBe(401);
    res = await post(jar, '/api/me/sessions/revoke-others', {});
    expect(await res.json()).toEqual({ ok: true, revoked: 1 });
    expect((await get(c, '/api/me')).status).toBe(401);
    res = await post(jar, '/api/me/sessions/bogus/revoke', {});
    expect(res.status).toBe(404);

    res = await post(jar, `/api/me/sessions/${jar.claims().sid}/revoke`, {});
    expect(await res.json()).toEqual({ ok: true, current: true });
    expect(jar.values[config.ACCESS_COOKIE]).toBeUndefined();
  });
});
