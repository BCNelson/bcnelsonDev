import { decodeJwt } from 'jose';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { config } from '../src/config';
import type { Env } from '../src/env';
import { resetKeyCache } from '../src/tokens';
import { lastCode, makeFakeEnv, type FakeEnv } from './do/fake-env';
import { SoftAuthenticator, userHandleFor } from './do/passkeys-authenticator';

vi.mock('cloudflare:workers', async () => ({
  DurableObject: (await import('./do/fake-storage')).FakeDurableObject,
}));
vi.mock('../src/crypto/password', async () => (await import('./do/fake-env')).fakePasswordModule());

const { User } = await import('../src/do/user');
const { UserIndex } = await import('../src/do/user-index');
const { createApp } = await import('../src/app');
const { passkeySection } = await import('../src/pages/passkeys');

const ORIGIN = 'https://auth.bcnelson.dev';
const START = 1_800_000_000_000;
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
  vi.setSystemTime(START);
  fake = makeFakeEnv({ User, UserIndex }, { AUTH_SIGNING_KEY_DEV: keyJson } as Partial<Env>);
});
afterEach(() => {
  vi.useRealTimers();
});

function post(path: string, data: unknown, headers: Record<string, string> = {}) {
  return app.request(`${ORIGIN}${path}`, {
    method: 'POST',
    headers: { Origin: ORIGIN, 'CF-Connecting-IP': '1.2.3.4', 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(data),
  }, fake.env);
}

function get(path: string) {
  return app.request(`${ORIGIN}${path}`, {}, fake.env);
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

async function json(res: Response): Promise<any> {
  return res.json();
}

async function verifiedSignup(username = 'Brad', email = 'brad@example.com'): Promise<string> {
  const start = await post('/signup/start', { username, email, turnstile: 'good' });
  const { signupId } = await json(start);
  const verify = await post('/signup/verify', { signupId, code: lastCode(fake.mail) });
  expect(await json(verify)).toEqual({ ok: true });
  return signupId;
}

/** Passkey-only signup; returns the authenticator, userId and access-cookie header. */
async function passkeySignup(auth = new SoftAuthenticator()) {
  const signupId = await verifiedSignup();
  const opts = await json(await post('/passkey/register/options', { signupId }));
  expect(opts.ok).toBe(true);
  const credential = await auth.register(opts.options);
  const res = await post('/signup/complete', { signupId, credential, return_to: 'https://app.bcnelson.dev/after' });
  expect(res.status).toBe(200);
  expect(await json(res)).toEqual({ ok: true, redirect: 'https://app.bcnelson.dev/after' });
  const at = cookies(res)[config.ACCESS_COOKIE]!;
  const claims = decodeJwt(at);
  return { auth, userId: claims.sub!, claims, cookie: { Cookie: `${config.ACCESS_COOKIE}=${at}` } };
}

async function passkeyLogin(auth: SoftAuthenticator, overrides: Parameters<SoftAuthenticator['assert']>[1] = {}) {
  const opts = await json(await post('/passkey/login/options', {}));
  expect(opts.ok).toBe(true);
  const credential = await auth.assert(opts.options, overrides);
  return { res: await post('/passkey/login/verify', { credential, return_to: 'https://app.bcnelson.dev/x' }), credential };
}

describe('passkey signup', () => {
  it('registers during signup: user.id is the pending userId, session amr hwk', async () => {
    const signupId = await verifiedSignup();
    const opts = await json(await post('/passkey/register/options', { signupId }));
    expect(opts.options).toMatchObject({
      rp: { id: 'bcnelson.dev', name: 'bcnelson.dev' },
      user: { name: 'Brad' },
      authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
      excludeCredentials: [],
    });
    const auth = new SoftAuthenticator();
    const credential = await auth.register(opts.options);
    const res = await post('/signup/complete', { signupId, credential });
    expect(res.status).toBe(200);
    const claims = decodeJwt(cookies(res)[config.ACCESS_COOKIE]!);
    expect(claims).toMatchObject({ preferred_username: 'Brad', amr: ['hwk'] });
    expect(opts.options.user.id).toBe(userHandleFor(claims.sub!));

    const passkeys = await fake.users.get(claims.sub!).listPasskeys();
    expect(passkeys).toHaveLength(1);
    expect(await fake.index.get('index').resolve('brad')).toBe(claims.sub);
  });

  it('options need a verified signup; complete refuses a reused or foreign challenge', async () => {
    const start = await json(await post('/signup/start', { username: 'brad', email: 'b@example.com', turnstile: 'good' }));
    let res = await post('/passkey/register/options', { signupId: start.signupId });
    expect(res.status).toBe(400);
    expect(await json(res)).toMatchObject({ error: 'not_verified' });

    // A login challenge can't be used to register.
    const signupId = await verifiedSignup('other', 'o@example.com');
    const login = await json(await post('/passkey/login/options', {}));
    const auth = new SoftAuthenticator();
    const bogus = await auth.register({ challenge: login.options.challenge, user: { id: 'x' } });
    res = await post('/signup/complete', { signupId, credential: bogus });
    expect(res.status).toBe(400);
    expect(await json(res)).toMatchObject({ error: 'challenge_expired' });

    // A challenge issued for another signup is refused.
    const third = await verifiedSignup('third', 't@example.com');
    const opts = await json(await post('/passkey/register/options', { signupId: third }));
    const stolen = await new SoftAuthenticator().register(opts.options);
    res = await post('/signup/complete', { signupId, credential: stolen });
    expect(res.status).toBe(400);
    expect(await json(res)).toMatchObject({ error: 'passkey_failed' });
  });

  it('rejects a registration from the wrong origin', async () => {
    const signupId = await verifiedSignup();
    const opts = await json(await post('/passkey/register/options', { signupId }));
    const credential = await new SoftAuthenticator({ origin: 'https://evil.example' }).register(opts.options);
    const res = await post('/signup/complete', { signupId, credential });
    expect(await json(res)).toMatchObject({ ok: false, error: 'passkey_failed' });
  });
});

describe('passkey login', () => {
  it('discoverable options, then verify → cookies, amr hwk, counter updated', async () => {
    const { auth, userId } = await passkeySignup();
    const opts = await json(await post('/passkey/login/options', {}));
    expect(opts.options).toMatchObject({ rpId: 'bcnelson.dev', userVerification: 'preferred' });
    expect(opts.options.allowCredentials ?? []).toEqual([]);

    vi.setSystemTime(START + 5000);
    const credential = await auth.assert(opts.options);
    const res = await post('/passkey/login/verify', { credential, return_to: 'https://app.bcnelson.dev/x' });
    expect(res.status).toBe(200);
    expect(await json(res)).toEqual({ ok: true, redirect: 'https://app.bcnelson.dev/x' });
    const claims = decodeJwt(cookies(res)[config.ACCESS_COOKIE]!);
    expect(claims).toMatchObject({ sub: userId, amr: ['hwk'] });
    expect(res.headers.get('Cache-Control')).toBe('no-store');
    const [passkey] = await fake.users.get(userId).listPasskeys();
    expect(passkey.lastUsedAt).toBe(START + 5000);

    // The same assertion (and challenge) can't be replayed.
    const replay = await post('/passkey/login/verify', { credential });
    expect(replay.status).toBe(400);
    expect(await json(replay)).toMatchObject({ error: 'challenge_expired' });
  });

  it('expired challenges are refused', async () => {
    const { auth } = await passkeySignup();
    const opts = await json(await post('/passkey/login/options', {}));
    vi.setSystemTime(START + config.WEBAUTHN_CHALLENGE_TTL + 1);
    const res = await post('/passkey/login/verify', { credential: await auth.assert(opts.options) });
    expect(await json(res)).toMatchObject({ error: 'challenge_expired' });
  });

  it('unknown credential, unknown user handle and missing handle get the same generic error', async () => {
    const { userId } = await passkeySignup();
    const stranger = new SoftAuthenticator();
    await stranger.register({ challenge: 'x', user: { id: userHandleFor(userId) } });
    for (const overrides of [{}, { userHandle: userHandleFor('usr_01JZZZZZZZZZZZZZZZZZZZZZZZ') }, { userHandle: null }]) {
      const { res } = await passkeyLogin(stranger, overrides);
      expect(res.status).toBe(401);
      expect(await json(res)).toMatchObject({ ok: false, error: 'passkey_failed' });
    }
    // An unknown handle never creates a User DO.
    expect(fake.users.instances.has('usr_01JZZZZZZZZZZZZZZZZZZZZZZZ')).toBe(false);
  });

  it('is not blocked by password backoff', async () => {
    const { auth, userId } = await passkeySignup();
    await fake.users.get(userId).setPassword('v2$correct-horse');
    for (let i = 0; i < config.BACKOFF_AFTER_FAILURES + 1; i++) {
      await post('/login/password', { identifier: 'brad', password: 'wrong', turnstile: 'good' });
    }
    const locked = await post('/login/password', { identifier: 'brad', password: 'correct-horse', turnstile: 'good' });
    expect(locked.status).toBe(429);
    const { res } = await passkeyLogin(auth);
    expect(res.status).toBe(200);
  });

  it('IP limit and Origin check apply; malformed bodies are 400', async () => {
    fake.limits.ip = false;
    expect((await post('/passkey/login/options', {})).status).toBe(429);
    expect((await post('/passkey/login/verify', {})).status).toBe(429);
    fake.limits.ip = true;
    expect((await post('/passkey/login/options', {}, { Origin: 'https://evil.example' })).status).toBe(403);
    const res = await post('/passkey/login/verify', { credential: { id: 'x', response: {} } });
    expect(res.status).toBe(400);
    expect(await json(res)).toMatchObject({ error: 'bad_request' });
  });
});

describe('signed-in passkey management', () => {
  it('adds a passkey with excludeCredentials, then it can sign in', async () => {
    const { auth, userId, cookie } = await passkeySignup();
    const opts = await json(await post('/passkey/register/options', {}, cookie));
    expect(opts.ok).toBe(true);
    expect(opts.options.excludeCredentials).toEqual([{ id: auth.id, type: 'public-key', transports: ['internal', 'hybrid'] }]);
    expect(opts.options.user.id).toBe(userHandleFor(userId));

    const second = new SoftAuthenticator();
    const credential = await second.register(opts.options);
    const res = await post('/passkey/register/verify', { credential, label: 'Laptop' }, cookie);
    expect(res.status).toBe(200);
    expect(await json(res)).toMatchObject({ ok: true, passkey: { label: 'Laptop', lastUsedAt: null } });
    expect((await passkeyLogin(second)).res.status).toBe(200);

    // Registering the same authenticator again is refused.
    const again = await json(await post('/passkey/register/options', {}, cookie));
    const dup = await post('/passkey/register/verify', { credential: await second.register(again.options) }, cookie);
    expect(dup.status).toBe(409);
  });

  it('signed out → 401 unauthorized; stale login → 403 reauth_required (shared shapes)', async () => {
    const { userId, cookie } = await passkeySignup();
    const [passkey] = await fake.users.get(userId).listPasskeys();
    const paths = [
      '/passkey/register/options', '/passkey/register/verify',
      `/passkey/credentials/${passkey.id}/rename`, `/passkey/credentials/${passkey.id}/delete`,
    ];
    for (const path of paths) {
      const res = await post(path, { label: 'x' });
      expect(res.status).toBe(401);
      expect(await json(res)).toMatchObject({ ok: false, error: 'unauthorized' });
    }
    vi.setSystemTime(START + config.REAUTH_WINDOW + 60_000);
    for (const path of paths) {
      const res = await post(path, { label: 'x' }, cookie);
      expect(res.status).toBe(403);
      expect(await json(res)).toMatchObject({ ok: false, error: 'reauth_required', reauthUrl: expect.stringContaining('/login?reauth=1') });
    }
  });

  it('a registration challenge is bound to the user who asked for it', async () => {
    const a = await passkeySignup();
    const opts = await json(await post('/passkey/register/options', {}, a.cookie));
    const credential = await new SoftAuthenticator().register(opts.options);
    // Bob signs up separately and tries to use Alice's challenge.
    fake.mail.length = 0;
    const signupId = await verifiedSignup('bob', 'bob@example.com');
    const bobOpts = await json(await post('/passkey/register/options', { signupId }));
    const bob = await post('/signup/complete', { signupId, credential: await new SoftAuthenticator().register(bobOpts.options) });
    const bobCookie = { Cookie: `${config.ACCESS_COOKIE}=${cookies(bob)[config.ACCESS_COOKIE]}` };
    const res = await post('/passkey/register/verify', { credential }, bobCookie);
    expect(res.status).toBe(400);
    expect(await json(res)).toMatchObject({ error: 'passkey_failed' });
  });

  it('rename and delete, refusing to delete the last login method', async () => {
    const { userId, cookie } = await passkeySignup();
    const [only] = await fake.users.get(userId).listPasskeys();

    let res = await post(`/passkey/credentials/${only.id}/rename`, { label: 'Phone' }, cookie);
    expect(await json(res)).toEqual({ ok: true });
    res = await post(`/passkey/credentials/${only.id}/rename`, { label: '' }, cookie);
    expect(await json(res)).toMatchObject({ error: 'invalid_label' });
    res = await post('/passkey/credentials/cred_01JZZZZZZZZZZZZZZZZZZZZZZZ/rename', { label: 'x' }, cookie);
    expect(res.status).toBe(404);
    res = await post('/passkey/credentials/not-an-id/delete', {}, cookie);
    expect(res.status).toBe(400);

    res = await post(`/passkey/credentials/${only.id}/delete`, {}, cookie);
    expect(res.status).toBe(409);
    expect(await json(res)).toMatchObject({ error: 'last_method' });

    await fake.users.get(userId).setPassword('v2$correct-horse');
    res = await post(`/passkey/credentials/${only.id}/delete`, {}, cookie);
    expect(await json(res)).toEqual({ ok: true });
    expect(await fake.users.get(userId).listPasskeys()).toEqual([]);
  });
});

describe('passkey pages', () => {
  it('/login has the passkey button and scripts; identifier allows webauthn autofill', async () => {
    const body = await (await get('/login')).text();
    expect(body).toContain('data-action="passkey-login"');
    expect(body).toContain('Sign in with a passkey');
    expect(body).toContain('autocomplete="username webauthn"');
    expect(body).toContain('<script src="/assets/webauthn.js" defer></script>');
    expect(body).toContain('<script src="/assets/passkey-login.js" defer></script>');
    expect(body).not.toMatch(/<script(?![^>]*\ssrc=)[^>]*>/);
  });

  it('/signup offers a passkey on the last step', async () => {
    const body = await (await get('/signup')).text();
    expect(body).toContain('Use a passkey instead');
    expect(body).toContain('/assets/passkey-signup.js');
  });

  it('client scripts are served and parse', async () => {
    for (const name of ['webauthn.js', 'passkey-login.js', 'passkey-signup.js', 'passkey-manage.js']) {
      const res = await get(`/assets/${name}`);
      expect(res.status).toBe(200);
      const source = await res.text();
      expect(() => new Function(source)).not.toThrow();
    }
  });

  it('/profile renders the passkey section through PROFILE_SLOTS', async () => {
    const { userId, cookie } = await passkeySignup();
    const [passkey] = await fake.users.get(userId).listPasskeys();
    const res = await app.request(`${ORIGIN}/profile`, { headers: cookie }, fake.env);
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toContain('id="passkeys"');
    expect(body).toContain(`data-passkey-id="${passkey.id}"`);
    expect(body).toContain('<script src="/assets/webauthn.js" defer></script>');
    expect(body).toContain('<script src="/assets/passkey-manage.js" defer></script>');
  });

  it('passkeySection lists passkeys and escapes labels', async () => {
    const out = String(await passkeySection([
      { id: 'cred_1', label: '<b>Phone</b>', createdAt: START, lastUsedAt: null, backedUp: true, deviceType: 'multiDevice' },
      { id: 'cred_2', label: 'Key', createdAt: START, lastUsedAt: START + 86_400_000, backedUp: false, deviceType: 'singleDevice' },
    ], { reauthUrl: '/login?reauth=1' }));
    expect(out).toContain('data-passkey-id="cred_1"');
    expect(out).toContain('&lt;b&gt;Phone&lt;/b&gt;');
    expect(out).not.toContain('<b>Phone</b>');
    expect(out).toContain('Never used');
    expect(out).toContain('Last used <time');
    expect(out).toContain('data-action="add"');
    expect(out).toContain('data-reauth-url="/login?reauth=1"');
    expect(String(await passkeySection([]))).toContain("You don't have any passkeys yet.");
  });
});
