import { decodeJwt } from 'jose';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { config } from '../src/config';
import type { Env } from '../src/env';
import { checkAdmin } from '../src/http/admin';
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

function get(path: string, cookie?: string) {
  return app.request(`${ORIGIN}${path}`, { headers: cookie ? { Cookie: cookie } : {} }, fake.env);
}

async function signUp(username: string, email: string, password = 'correct-horse'): Promise<Account> {
  const start = await post('/signup/start', { username, email, turnstile: 'good' });
  const { signupId } = (await start.json()) as { signupId: string };
  await post('/signup/verify', { signupId, code: lastCode(fake.mail) });
  const res = await post('/signup/complete', { signupId, password });
  expect(res.status).toBe(200);
  return account(res);
}

async function login(identifier: string, password = 'correct-horse') {
  return post('/login/password', { identifier, password });
}

/** An admin (via ADMIN_EMAILS) and a regular user. */
async function setup() {
  const admin = await signUp('Admin1', 'admin@example.com');
  vi.setSystemTime(Date.now() + 1000); // distinct ULID timestamps → stable order
  const bob = await signUp('Bob', 'bob@example.com');
  return { admin, bob };
}

async function json(res: Response): Promise<any> {
  return res.json();
}

describe('checkAdmin', () => {
  const now = 1_800_000_000_000;
  const fresh = Math.floor(now / 1000);
  it('requires the admin role, and a recent login when asked', () => {
    expect(checkAdmin({ roles: ['beta'], auth_time: fresh }, false, now)).toBe('forbidden');
    expect(checkAdmin({ auth_time: fresh }, false, now)).toBe('forbidden');
    expect(checkAdmin({ roles: ['admin'], auth_time: fresh - 3600 }, false, now)).toBe('ok');
    expect(checkAdmin({ roles: ['admin'], auth_time: fresh - 3600 }, true, now)).toBe('reauth_required');
    expect(checkAdmin({ roles: ['admin'], auth_time: fresh - 60 }, true, now)).toBe('ok');
  });
});

describe('admin authz', () => {
  it('signed out: page redirects to /refresh, API is 401', async () => {
    const page = await get('/admin');
    expect(page.status).toBe(302);
    expect(page.headers.get('Location')).toBe(`/refresh?return_to=${encodeURIComponent(`${ORIGIN}/admin`)}`);
    const api = await get('/api/admin/users');
    expect(api.status).toBe(401);
    expect(await json(api)).toMatchObject({ ok: false, error: 'unauthorized' });
  });

  it('non-admins get 403', async () => {
    const { bob } = await setup();
    expect((await get('/admin', bob.cookie)).status).toBe(403);
    const res = await get('/api/admin/users', bob.cookie);
    expect(res.status).toBe(403);
    expect(await json(res)).toMatchObject({ error: 'forbidden' });
    const mut = await post(`/api/admin/users/${bob.userId}/roles`, { roles: ['admin'] }, bob.cookie);
    expect(mut.status).toBe(403);
    expect(await json(mut)).toMatchObject({ error: 'forbidden' });
  });

  it('ADMIN_EMAILS bootstrap puts admin in the token', async () => {
    const { admin, bob } = await setup();
    expect(decodeJwt(admin.at).roles).toEqual(['admin']);
    expect(decodeJwt(bob.at).roles).toBeUndefined();
  });

  it('mutations need a login within REAUTH_WINDOW; reads do not', async () => {
    const { admin, bob } = await setup();
    vi.setSystemTime(Date.now() + config.REAUTH_WINDOW + 60_000); // token still unexpired
    expect((await get('/api/admin/users', admin.cookie)).status).toBe(200);
    const res = await post(`/api/admin/users/${bob.userId}/revoke-sessions`, {}, admin.cookie);
    expect(res.status).toBe(403);
    expect(await json(res)).toMatchObject({
      ok: false, error: 'reauth_required', reauthUrl: `/login?reauth=1&return_to=${encodeURIComponent(`${ORIGIN}/admin`)}`,
    });
  });

  it('a revoked session or removed role loses access at once, despite an unexpired JWT', async () => {
    const { admin } = await setup();
    const second = account(await login('admin@example.com'));
    // Revoke the first session from the second.
    expect((await post(`/api/admin/users/${admin.userId}/revoke-sessions`, {}, second.cookie)).status).toBe(200);
    expect((await get('/api/admin/users', admin.cookie)).status).toBe(401);
    expect((await get('/api/admin/users', second.cookie)).status).toBe(401); // revoked too (all sessions)
  });

  it('POSTs need an allowed Origin', async () => {
    const { admin, bob } = await setup();
    const res = await post(`/api/admin/users/${bob.userId}/revoke-sessions`, {}, admin.cookie, 'https://evil.example');
    expect(res.status).toBe(403);
    expect(await json(res)).toEqual({ error: 'forbidden_origin' });
  });
});

describe('admin page', () => {
  it('renders the directory with search and pagination, no inline scripts', async () => {
    const { admin } = await setup();
    const res = await get('/admin', admin.cookie);
    expect(res.status).toBe(200);
    expect(res.headers.get('Content-Security-Policy')).toContain("script-src 'self'");
    expect(res.headers.get('Cache-Control')).toBe('no-store');
    const page = await res.text();
    expect(page).toContain('Admin1');
    expect(page).toContain('bob@example.com');
    expect(page).toContain(`data-user-id="${admin.userId}"`);
    expect(page).toContain('<script src="/assets/admin.js" defer></script>');
    expect(page).not.toMatch(/<script>(?!<\/script>)/);
    expect(page).not.toContain(' style="');

    const search = await (await get('/admin?q=bo', admin.cookie)).text();
    expect(search).toContain('bob@example.com');
    expect(search).not.toContain('admin@example.com');

    const js = await get('/assets/admin.js');
    expect(js.status).toBe(200);
    expect(await js.text()).toContain('/api/admin/users/');
  });

  it('escapes user-controlled values', async () => {
    const { admin } = await setup();
    await fake.env.USER_INDEX.get(fake.env.USER_INDEX.idFromName('index')).upsertDirectoryEntry({
      userId: 'usr_01ZZZZZZZZZZZZZZZZZZZZZZZZ', username: '<img src=x>', primaryEmail: 'x@example.com',
      roles: [], createdAt: 0, disabledAt: null,
    });
    const page = await (await get('/admin', admin.cookie)).text();
    expect(page).not.toContain('<img src=x>');
    expect(page).toContain('&lt;img src=x&gt;');
  });
});

describe('admin API', () => {
  it('lists, searches and paginates users', async () => {
    const { admin, bob } = await setup();
    let body = await json(await get('/api/admin/users', admin.cookie));
    expect(body.ok).toBe(true);
    expect(body.users.map((u: any) => u.username)).toEqual(['Admin1', 'Bob']);
    expect(body.users[0]).toMatchObject({ userId: admin.userId, primaryEmail: 'admin@example.com', roles: ['admin'] });
    expect(body.nextCursor).toBeNull();

    body = await json(await get('/api/admin/users?limit=1', admin.cookie));
    expect(body.users).toHaveLength(1);
    expect(body.nextCursor).toBe(admin.userId);
    body = await json(await get(`/api/admin/users?limit=1&cursor=${body.nextCursor}`, admin.cookie));
    expect(body.users[0].userId).toBe(bob.userId);

    body = await json(await get('/api/admin/users?q=BOB@', admin.cookie));
    expect(body.users.map((u: any) => u.userId)).toEqual([bob.userId]);
  });

  it('shows a user detail; unknown or malformed ids are 404', async () => {
    const { admin, bob } = await setup();
    const res = await get(`/api/admin/users/${bob.userId}`, admin.cookie);
    expect(res.status).toBe(200);
    const body = await json(res);
    expect(body.user).toMatchObject({ userId: bob.userId, username: 'Bob', emails: ['bob@example.com'], roles: [] });
    expect(body.user.sessions).toHaveLength(1);
    expect(body.user.audit.map((a: any) => a.event)).toContain('profile.created');
    expect(body.directory).toMatchObject({ userId: bob.userId });

    expect((await get('/api/admin/users/usr_01AAAAAAAAAAAAAAAAAAAAAAAA', admin.cookie)).status).toBe(404);
    expect((await get('/api/admin/users/nope', admin.cookie)).status).toBe(404);
  });

  it('sets roles (audited with the actor); they reach the token on the next refresh', async () => {
    const { admin, bob } = await setup();
    let res = await post(`/api/admin/users/${bob.userId}/roles`, { roles: ['beta'] }, admin.cookie);
    expect(res.status).toBe(200);
    expect(await json(res)).toEqual({ ok: true, roles: ['beta'], changed: true });

    const refreshed = await get('/session/token', bob.cookie);
    expect(refreshed.status).toBe(200);
    const { access_token } = await json(refreshed);
    expect(decodeJwt(access_token).roles).toEqual(['beta']);

    const detail = await json(await get(`/api/admin/users/${bob.userId}`, admin.cookie));
    expect(detail.user.audit[0]).toMatchObject({ event: 'role.set', detail: { actor: admin.userId, roles: ['beta'] } });
    expect(detail.directory.roles).toEqual(['beta']);

    res = await post(`/api/admin/users/${bob.userId}/roles`, { roles: ['root'] }, admin.cookie);
    expect(res.status).toBe(400);
    expect(await json(res)).toMatchObject({ error: 'invalid_role' });
    res = await post(`/api/admin/users/${bob.userId}/roles`, { roles: 'beta' }, admin.cookie);
    expect(res.status).toBe(400);
  });

  it('the last admin cannot drop their own admin role', async () => {
    const { admin, bob } = await setup();
    let res = await post(`/api/admin/users/${admin.userId}/roles`, { roles: [] }, admin.cookie);
    expect(res.status).toBe(409);
    expect(await json(res)).toMatchObject({ error: 'last_admin' });

    // With a second admin it works.
    await post(`/api/admin/users/${bob.userId}/roles`, { roles: ['admin'] }, admin.cookie);
    res = await post(`/api/admin/users/${admin.userId}/roles`, { roles: [] }, admin.cookie);
    expect(res.status).toBe(200);
  });

  it('disable blocks login and refresh; enable restores login', async () => {
    const { admin, bob } = await setup();
    let res = await post(`/api/admin/users/${bob.userId}/disable`, { disabled: true }, admin.cookie);
    expect(res.status).toBe(200);
    expect(await json(res)).toMatchObject({ ok: true, disabledAt: expect.any(Number), revokedSessions: 1 });

    expect((await get('/session/token', bob.cookie)).status).toBe(401);
    res = await login('bob');
    expect(res.status).toBe(403);
    expect(await json(res)).toMatchObject({ ok: false, error: 'account_disabled' });
    expect((await login('bob', 'wrong-password')).status).toBe(401);

    const list = await json(await get('/api/admin/users?q=bob', admin.cookie));
    expect(list.users[0].disabledAt).toEqual(expect.any(Number));

    res = await post(`/api/admin/users/${bob.userId}/disable`, { disabled: false }, admin.cookie);
    expect(await json(res)).toMatchObject({ ok: true, disabledAt: null });
    expect((await login('bob')).status).toBe(200);
  });

  it('refuses self-disable and bad bodies', async () => {
    const { admin, bob } = await setup();
    let res = await post(`/api/admin/users/${admin.userId}/disable`, { disabled: true }, admin.cookie);
    expect(res.status).toBe(409);
    expect(await json(res)).toMatchObject({ error: 'cannot_disable_self' });
    res = await post(`/api/admin/users/${bob.userId}/disable`, { disabled: 'maybe' }, admin.cookie);
    expect(res.status).toBe(400);
  });

  it('revokes all of a user\'s sessions', async () => {
    const { admin, bob } = await setup();
    await login('bob');
    const res = await post(`/api/admin/users/${bob.userId}/revoke-sessions`, {}, admin.cookie);
    expect(await json(res)).toEqual({ ok: true, revoked: 2 });
    expect((await get('/session/token', bob.cookie)).status).toBe(401);
    const detail = await json(await get(`/api/admin/users/${bob.userId}`, admin.cookie));
    expect(detail.user.audit[0]).toMatchObject({ event: 'admin.sessions_revoked', detail: { actor: admin.userId, count: 2 } });
  });

  it('rebuilds directory entries (one user, and the backfill)', async () => {
    const { admin, bob } = await setup();
    const indexDb = fake.index.instances.get('index')!.fake.db;
    indexDb.prepare('DELETE FROM users WHERE user_id = ?').run(bob.userId);
    expect((await json(await get('/api/admin/users', admin.cookie))).users).toHaveLength(1);

    let res = await post('/api/admin/directory/rebuild', {}, admin.cookie);
    expect(await json(res)).toEqual({ ok: true, rebuilt: 1, remaining: 0 });
    expect((await json(await get('/api/admin/users', admin.cookie))).users).toHaveLength(2);

    indexDb.prepare('DELETE FROM users WHERE user_id = ?').run(bob.userId);
    res = await post(`/api/admin/users/${bob.userId}/rebuild-directory`, {}, admin.cookie);
    expect(await json(res)).toMatchObject({ ok: true, directory: { userId: bob.userId, username: 'Bob' } });
  });
});
