import { Hono } from 'hono';
import { decodeJwt } from 'jose';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import type { Env } from '../src/env';
import type { AppEnv } from '../src/http';
import { sessionRoutes } from '../src/routes/session';
import { formatRefreshToken, issueSession, parseRefreshToken } from '../src/session';
import { resetKeyCache } from '../src/tokens';
import type { RefreshResult, UserClaims } from '../src/types';

const USER = 'usr_01JBCDEFGHJKMNPQRSTVWXYZ01';
const SESSION = 'ses_01JBCDEFGHJKMNPQRSTVWXYZ02';
const SECRET = 'A'.repeat(42) + 'g';
const NEW_SECRET = 'B'.repeat(42) + 'w';
const TOKEN = `rt1.${USER}.${SESSION}.${SECRET}`;

describe('refresh token format', () => {
  it('formats and parses', () => {
    expect(formatRefreshToken({ userId: USER, sessionId: SESSION, secret: SECRET })).toBe(TOKEN);
    expect(parseRefreshToken(TOKEN)).toEqual({ userId: USER, sessionId: SESSION, secret: SECRET });
  });

  it.each([
    undefined,
    null,
    '',
    'rt1',
    `rt2.${USER}.${SESSION}.${SECRET}`,
    `RT1.${USER}.${SESSION}.${SECRET}`,
    `rt1.${USER}.${SESSION}`,
    `rt1.${USER}.${SESSION}.${SECRET}.extra`,
    `rt1.${USER}.${SESSION}.${SECRET}.`,
    `.rt1.${USER}.${SESSION}.${SECRET}`,
    `rt1.${SESSION}.${USER}.${SECRET}`,
    `rt1.usr_short.${SESSION}.${SECRET}`,
    `rt1.usr_01JBCDEFGHJKMNPQRSTVWXYZ0I.${SESSION}.${SECRET}`, // I is not Crockford
    `rt1.${USER}.ses_01JBCDEFGHJKMNPQRSTVWXYZ0U.${SECRET}`, // U is not Crockford
    `rt1.${USER}.${SESSION}.${SECRET.slice(1)}`,
    `rt1.${USER}.${SESSION}.${SECRET}A`,
    `rt1.${USER}.${SESSION}.${'A'.repeat(42)}=`,
    `rt1.${USER}.${SESSION}.${'A'.repeat(42)}+`,
    `rt1.${USER}.${SESSION}.${'A'.repeat(42)}/`,
    `rt1. ${USER}.${SESSION}.${SECRET}`,
    `rt1.${USER}.${SESSION}.${SECRET}\n`,
  ])('rejects %j', (value) => {
    expect(parseRefreshToken(value)).toBeNull();
  });

  it('refuses to format invalid parts', () => {
    expect(() => formatRefreshToken({ userId: 'usr_x', sessionId: SESSION, secret: SECRET })).toThrow();
    expect(() => formatRefreshToken({ userId: USER, sessionId: SESSION, secret: 'a.b' })).toThrow();
  });
});

const claims: UserClaims = {
  sub: USER,
  sid: SESSION,
  auth_time: 1_700_000_000,
  amr: ['pwd'],
  preferred_username: 'brad',
  email: 'brad@example.com',
};

let keyJson: string;
beforeAll(async () => {
  const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
  const jwk = (await crypto.subtle.exportKey('jwk', pair.privateKey)) as JsonWebKey;
  keyJson = JSON.stringify({ kty: 'OKP', crv: 'Ed25519', x: jwk.x, d: jwk.d, kid: 'k1' });
});
afterEach(() => resetKeyCache());

interface FakeUser {
  refreshResult: RefreshResult;
  calls: string[];
}

function makeEnv(user: FakeUser): Env {
  const stub = {
    refreshSession: async (sessionId: string, secret: string) => {
      user.calls.push(`refresh:${sessionId}:${secret}`);
      return user.refreshResult;
    },
    revokeSession: async (sessionId: string) => {
      user.calls.push(`revoke:${sessionId}`);
    },
  };
  return {
    ISSUER: 'https://auth.bcnelson.dev',
    COOKIE_DOMAIN: 'bcnelson.dev',
    ALLOWED_ORIGINS: 'https://auth.bcnelson.dev',
    AUTH_SIGNING_KEY: { get: async () => keyJson },
    RL_IP: { limit: async () => ({ success: true }) },
    USER: {
      idFromName: (name: string) => {
        user.calls.push(`id:${name}`);
        return name;
      },
      get: () => stub,
    },
  } as unknown as Env;
}

function setCookies(res: Response): string[] {
  return res.headers.getSetCookie();
}

describe('issueSession', () => {
  it('sets bcn_at on the shared domain and a host-only __Host- refresh cookie', async () => {
    const app = new Hono<AppEnv>();
    app.get('/', async (c) => {
      await issueSession(c, USER, { sessionId: SESSION, secret: SECRET, claims });
      return c.text('ok');
    });
    const res = await app.request('https://auth.bcnelson.dev/', {}, makeEnv({ refreshResult: { ok: false, reason: 'invalid' }, calls: [] }));
    const [at, rt] = setCookies(res);
    expect(at).toMatch(/^bcn_at=[^;]+; Max-Age=900; Domain=bcnelson.dev; Path=\/; HttpOnly; Secure; SameSite=Lax$/);
    expect(rt).toBe(`__Host-bcn_rt=${TOKEN}; Max-Age=5184000; Path=/; HttpOnly; Secure; SameSite=Lax`);
  });

  it('uses bcn_rt without Secure over http', async () => {
    const app = new Hono<AppEnv>();
    app.get('/', async (c) => {
      await issueSession(c, USER, { sessionId: SESSION, secret: SECRET, claims });
      return c.text('ok');
    });
    const res = await app.request('http://auth.bcnelson.localhost/', {}, makeEnv({ refreshResult: { ok: false, reason: 'invalid' }, calls: [] }));
    const [, rt] = setCookies(res);
    expect(rt).toBe(`bcn_rt=${TOKEN}; Max-Age=5184000; Path=/; HttpOnly; SameSite=Lax`);
  });

  it('rejects claims for a different user or session', async () => {
    const app = new Hono<AppEnv>();
    app.get('/', async (c) => {
      await issueSession(c, USER, { sessionId: SESSION, secret: SECRET, claims: { ...claims, sid: 'ses_other' } });
      return c.text('ok');
    });
    const res = await app.request('https://auth.bcnelson.dev/', {}, makeEnv({ refreshResult: { ok: false, reason: 'invalid' }, calls: [] }));
    expect(res.status).toBe(500);
  });
});

describe('session routes', () => {
  const app = new Hono<AppEnv>().route('/', sessionRoutes);
  const cookie = { Cookie: `__Host-bcn_rt=${TOKEN}` };
  const ok: RefreshResult = { ok: true, secret: NEW_SECRET, claims };

  it('GET /refresh rotates and redirects to a valid return_to', async () => {
    const user: FakeUser = { refreshResult: ok, calls: [] };
    const res = await app.request(
      'https://auth.bcnelson.dev/refresh?return_to=' + encodeURIComponent('https://app.bcnelson.dev/x'),
      { headers: cookie },
      makeEnv(user),
    );
    expect(res.status).toBe(302);
    expect(res.headers.get('Location')).toBe('https://app.bcnelson.dev/x');
    expect(res.headers.get('Cache-Control')).toBe('no-store');
    expect(user.calls).toEqual([`id:${USER}`, `refresh:${SESSION}:${SECRET}`]);
    const [at, rt] = setCookies(res);
    expect(decodeJwt(at!.split(';')[0]!.slice('bcn_at='.length)).sub).toBe(USER);
    expect(rt).toContain(`__Host-bcn_rt=rt1.${USER}.${SESSION}.${NEW_SECRET};`);
  });

  it('GET /refresh sends the user to /login and clears cookies on failure', async () => {
    for (const reason of ['invalid', 'expired', 'revoked', 'reuse'] as const) {
      const res = await app.request(
        'https://auth.bcnelson.dev/refresh?return_to=https://evil.com/',
        { headers: cookie },
        makeEnv({ refreshResult: { ok: false, reason }, calls: [] }),
      );
      expect(res.status).toBe(302);
      expect(res.headers.get('Location')).toBe('/login?return_to=' + encodeURIComponent('https://bcnelson.dev/'));
      const cleared = setCookies(res);
      expect(cleared).toHaveLength(2);
      expect(cleared.every((c) => c.includes('Max-Age=0'))).toBe(true);
    }
  });

  it('GET /refresh without a cookie skips the DO', async () => {
    const user: FakeUser = { refreshResult: ok, calls: [] };
    const res = await app.request('https://auth.bcnelson.dev/refresh', {}, makeEnv(user));
    expect(res.status).toBe(302);
    expect(user.calls).toEqual([]);
  });

  it('GET /refresh rejects claims that do not match the cookie', async () => {
    const user: FakeUser = { refreshResult: { ...ok, claims: { ...claims, sub: 'usr_01JBCDEFGHJKMNPQRSTVWXYZ99' } }, calls: [] };
    const res = await app.request('https://auth.bcnelson.dev/refresh', { headers: cookie }, makeEnv(user));
    expect(res.headers.get('Location')).toMatch(/^\/login/);
  });

  it('GET /session/token returns the token as JSON with CORS', async () => {
    const res = await app.request(
      'https://auth.bcnelson.dev/session/token',
      { headers: { ...cookie, Origin: 'https://app.bcnelson.dev' } },
      makeEnv({ refreshResult: ok, calls: [] }),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { access_token: string; expires_at: number };
    expect(decodeJwt(body.access_token).exp).toBe(body.expires_at);
    expect(body.expires_at).toBeLessThan(1e11); // seconds, not ms
    expect(res.headers.get('Access-Control-Allow-Origin')).toBe('https://app.bcnelson.dev');
    expect(res.headers.get('Access-Control-Allow-Credentials')).toBe('true');
  });

  it('GET /session/token returns 401 JSON on failure', async () => {
    const res = await app.request(
      'https://auth.bcnelson.dev/session/token',
      { headers: cookie },
      makeEnv({ refreshResult: { ok: false, reason: 'reuse' }, calls: [] }),
    );
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: 'invalid_session', reason: 'reuse' });
    expect(setCookies(res)).toHaveLength(2);
  });

  it('POST /logout revokes and clears', async () => {
    const user: FakeUser = { refreshResult: ok, calls: [] };
    const res = await app.request('https://auth.bcnelson.dev/logout', { method: 'POST', headers: cookie }, makeEnv(user));
    expect(res.status).toBe(204);
    expect(user.calls).toEqual([`id:${USER}`, `revoke:${SESSION}`]);
    const [at] = setCookies(res);
    expect(at).toMatch(/^bcn_at=; Max-Age=0; Domain=bcnelson.dev;/);
  });

  it('POST /logout redirects to a validated return_to', async () => {
    const res = await app.request(
      'https://auth.bcnelson.dev/logout?return_to=https://evil.com/',
      { method: 'POST' },
      makeEnv({ refreshResult: ok, calls: [] }),
    );
    expect(res.status).toBe(303);
    expect(res.headers.get('Location')).toBe('https://bcnelson.dev/');
  });
});
