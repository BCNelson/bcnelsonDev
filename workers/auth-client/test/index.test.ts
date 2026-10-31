import { beforeAll, describe, expect, it, vi } from 'vitest';
import { exportJWK, generateKeyPair, SignJWT, type CryptoKey, type JWK } from 'jose';
import { createAuthClient, type AuthClientOptions, type AuthUser } from '../src/index.js';

const ISSUER = 'https://auth.bcnelson.dev';
const APP = 'https://app.bcnelson.dev/dashboard?x=1';

let key: CryptoKey;
let publicJwk: JWK;
let otherKey: CryptoKey;

beforeAll(async () => {
  ({ privateKey: key, publicKey: publicJwk } = await keyPair('k1'));
  ({ privateKey: otherKey } = await keyPair('k1'));
});

async function keyPair(kid: string) {
  const { privateKey, publicKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
  return { privateKey, publicKey: { ...(await exportJWK(publicKey)), kid, alg: 'EdDSA', use: 'sig' } };
}

/** Mock fetch serving whatever `keys` currently holds. */
function jwksFetch(keys: () => JWK[]) {
  return vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
    new Response(JSON.stringify({ keys: keys() }), { headers: { 'content-type': 'application/json' } }),
  );
}

interface TokenOpts {
  kid?: string;
  signer?: CryptoKey;
  iss?: string;
  aud?: string;
  exp?: number | string;
  roles?: string[];
}

async function token(opts: TokenOpts = {}) {
  const claims: Record<string, unknown> = {
    sid: 'ses_1',
    auth_time: Math.floor(Date.now() / 1000) - 60,
    amr: ['pwd'],
    preferred_username: 'brad',
    name: 'Bradley',
    email: 'brad@example.com',
    email_verified: true,
  };
  if (opts.roles) claims.roles = opts.roles;
  return new SignJWT(claims)
    .setProtectedHeader({ alg: 'EdDSA', kid: opts.kid ?? 'k1' })
    .setSubject('usr_1')
    .setIssuer(opts.iss ?? ISSUER)
    .setAudience(opts.aud ?? 'bcnelson.dev')
    .setIssuedAt()
    .setExpirationTime(opts.exp ?? '15m')
    .sign(opts.signer ?? key);
}

function req(jwt?: string, init: { method?: string; accept?: string; url?: string } = {}) {
  const headers = new Headers();
  if (jwt) headers.set('cookie', `other=1; bcn_at=${jwt}; theme=dark`);
  if (init.accept) headers.set('accept', init.accept);
  return new Request(init.url ?? APP, { method: init.method ?? 'GET', headers });
}

function client(extra: Partial<AuthClientOptions> = {}) {
  const fetch = jwksFetch(() => [publicJwk]);
  return { fetch, auth: createAuthClient({ fetch, ...extra }) };
}

describe('getUser', () => {
  it('returns the user for a valid token', async () => {
    const { auth, fetch } = client();
    const user = await auth.getUser(req(await token({ roles: ['admin'] })));
    expect(user).toMatchObject({
      id: 'usr_1',
      sessionId: 'ses_1',
      username: 'brad',
      name: 'Bradley',
      email: 'brad@example.com',
      roles: ['admin'],
      amr: ['pwd'],
    });
    expect(user?.hasRole('admin')).toBe(true);
    expect(user?.hasRole('beta')).toBe(false);
    expect(user?.claims.iss).toBe(ISSUER);
    expect(fetch).toHaveBeenCalledWith(`${ISSUER}/.well-known/jwks.json`, expect.anything());
  });

  it('defaults roles to [] when omitted', async () => {
    const { auth } = client();
    const user = await auth.getUser(req(await token()));
    expect(user?.roles).toEqual([]);
  });

  it('reads a Bearer token', async () => {
    const { auth } = client();
    const r = new Request(APP, { headers: { authorization: `Bearer ${await token()}` } });
    expect((await auth.getUser(r))?.id).toBe('usr_1');
  });

  it('caches the JWKS across requests', async () => {
    const { auth, fetch } = client();
    const jwt = await token();
    await auth.getUser(req(jwt));
    await auth.getUser(req(jwt));
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('rejects the wrong audience', async () => {
    const { auth } = client();
    expect(await auth.getUser(req(await token({ aud: 'other-client' })))).toBeNull();
  });

  it('rejects the wrong issuer', async () => {
    const { auth } = client();
    expect(await auth.getUser(req(await token({ iss: 'https://evil.example' })))).toBeNull();
  });

  it('rejects an expired token', async () => {
    const { auth } = client();
    const past = Math.floor(Date.now() / 1000) - 120;
    expect(await auth.getUser(req(await token({ exp: past })))).toBeNull();
  });

  it('allows small clock skew', async () => {
    const { auth } = client();
    const justPast = Math.floor(Date.now() / 1000) - 5;
    expect(await auth.getUser(req(await token({ exp: justPast })))).not.toBeNull();
  });

  it('rejects a bad signature', async () => {
    const { auth } = client();
    expect(await auth.getUser(req(await token({ signer: otherKey })))).toBeNull();
  });

  it('returns null without a cookie and skips the JWKS fetch', async () => {
    const { auth, fetch } = client();
    expect(await auth.getUser(req())).toBeNull();
    expect(fetch).not.toHaveBeenCalled();
  });

  it('honors a custom cookie name', async () => {
    const { auth } = client({ cookieName: 'dev_at' });
    const r = new Request(APP, { headers: { cookie: `dev_at=${await token()}` } });
    expect(await auth.getUser(r)).not.toBeNull();
  });
});

describe('key rotation', () => {
  it('refetches once on an unknown kid', async () => {
    const rotated = await keyPair('k2');
    let keys = [publicJwk];
    const fetch = jwksFetch(() => keys);
    const auth = createAuthClient({ fetch, jwksCooldownMs: 0 });

    expect(await auth.getUser(req(await token()))).not.toBeNull();
    keys = [rotated.publicKey, publicJwk];
    const user = await auth.getUser(req(await token({ kid: 'k2', signer: rotated.privateKey })));
    expect(user?.id).toBe('usr_1');
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('rate-limits refetches for unknown kids', async () => {
    const fetch = jwksFetch(() => [publicJwk]);
    const auth = createAuthClient({ fetch, jwksCooldownMs: 60_000 });
    await auth.getUser(req(await token()));
    const bogus = await token({ kid: 'nope' });
    expect(await auth.getUser(req(bogus))).toBeNull();
    expect(await auth.getUser(req(bogus))).toBeNull();
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('refetches after the TTL', async () => {
    const fetch = jwksFetch(() => [publicJwk]);
    const auth = createAuthClient({ fetch, jwksTtlMs: 0 });
    const jwt = await token();
    await auth.getUser(req(jwt));
    await auth.getUser(req(jwt));
    expect(fetch).toHaveBeenCalledTimes(2);
  });
});

describe('service binding', () => {
  it('fetches the JWKS through the binding', async () => {
    const service = { fetch: jwksFetch(() => [publicJwk]) };
    const globalFetch = vi.fn();
    const auth = createAuthClient({ service, fetch: globalFetch });
    expect(await auth.getUser(req(await token()))).not.toBeNull();
    expect(service.fetch).toHaveBeenCalledWith(`${ISSUER}/.well-known/jwks.json`, expect.anything());
    expect(globalFetch).not.toHaveBeenCalled();
  });
});

describe('requireUser', () => {
  it('returns the user when signed in', async () => {
    const { auth } = client();
    const result = await auth.requireUser(req(await token()));
    expect(result).not.toBeInstanceOf(Response);
    expect((result as AuthUser).id).toBe('usr_1');
  });

  it('redirects HTML navigations to /refresh', async () => {
    const { auth } = client();
    const res = (await auth.requireUser(req(undefined, { accept: 'text/html,application/xhtml+xml' }))) as Response;
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe(`${ISSUER}/refresh?return_to=${encodeURIComponent(APP)}`);
  });

  it('redirects expired HEAD navigations too', async () => {
    const { auth } = client();
    const past = Math.floor(Date.now() / 1000) - 120;
    const res = (await auth.requireUser(req(await token({ exp: past }), { method: 'HEAD', accept: 'text/html' }))) as Response;
    expect(res.status).toBe(302);
  });

  it('returns 401 JSON for API requests', async () => {
    const { auth } = client();
    const res = (await auth.requireUser(req(undefined, { accept: 'application/json' }))) as Response;
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: 'unauthenticated' });
  });

  it('returns 401 for non-GET even when HTML is accepted', async () => {
    const { auth } = client();
    const res = (await auth.requireUser(req(undefined, { method: 'POST', accept: 'text/html' }))) as Response;
    expect(res.status).toBe(401);
  });
});

describe('requireRole', () => {
  it('returns the user with the role', async () => {
    const { auth } = client();
    const result = await auth.requireRole(req(await token({ roles: ['admin'] })), 'admin');
    expect((result as AuthUser).id).toBe('usr_1');
  });

  it('returns 403 JSON without the role', async () => {
    const { auth } = client();
    const res = (await auth.requireRole(req(await token({ roles: ['beta'] })), 'admin')) as Response;
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ error: 'forbidden' });
  });

  it('returns 401 when signed out', async () => {
    const { auth } = client();
    const res = (await auth.requireRole(req(), 'admin')) as Response;
    expect(res.status).toBe(401);
  });
});

describe('urls', () => {
  it('builds login and refresh URLs', () => {
    const auth = createAuthClient({ issuer: 'https://auth.bcnelson.localhost/' });
    expect(auth.loginUrl('https://a.bcnelson.dev/x')).toBe(
      'https://auth.bcnelson.localhost/login?return_to=https%3A%2F%2Fa.bcnelson.dev%2Fx',
    );
    expect(auth.refreshUrl('https://a.bcnelson.dev/')).toBe(
      'https://auth.bcnelson.localhost/refresh?return_to=https%3A%2F%2Fa.bcnelson.dev%2F',
    );
  });
});
