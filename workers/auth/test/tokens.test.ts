import { decodeProtectedHeader, decodeJwt } from 'jose';
import { afterEach, describe, expect, it } from 'vitest';
import { config } from '../src/config';
import type { Env } from '../src/env';
import { getJwks, parseKeySet, resetKeyCache, signAccessToken, verifyAccessToken } from '../src/tokens';
import type { UserClaims } from '../src/types';

async function generateKey(kid: string): Promise<Record<string, unknown>> {
  const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
  const jwk = (await crypto.subtle.exportKey('jwk', pair.privateKey)) as JsonWebKey;
  return { kty: 'OKP', crv: 'Ed25519', x: jwk.x, d: jwk.d, kid };
}

function makeEnv(overrides: Partial<Env> = {}): Env {
  return {
    ISSUER: 'https://auth.bcnelson.dev',
    COOKIE_DOMAIN: 'bcnelson.dev',
    ALLOWED_ORIGINS: 'https://auth.bcnelson.dev',
    AUTH_SIGNING_KEY: { get: async () => { throw new Error('not in store'); } },
    ...overrides,
  } as unknown as Env;
}

const claims: UserClaims = {
  sub: 'usr_01JBCDEFGHJKMNPQRSTVWXYZ01',
  sid: 'ses_01JBCDEFGHJKMNPQRSTVWXYZ01',
  auth_time: 1_700_000_000,
  amr: ['pwd'],
  preferred_username: 'brad',
  email: 'brad@example.com',
  roles: [],
};

afterEach(() => resetKeyCache());

describe('signAccessToken', () => {
  it('round-trips through verifyAccessToken', async () => {
    const env = makeEnv({ AUTH_SIGNING_KEY_DEV: JSON.stringify(await generateKey('k1')) });
    const { token, expiresAt } = await signAccessToken(env, { ...claims, roles: ['admin'] });
    const payload = await verifyAccessToken(env, token);
    expect(payload).toMatchObject({
      iss: 'https://auth.bcnelson.dev',
      aud: config.AUDIENCE,
      sub: claims.sub,
      sid: claims.sid,
      email_verified: true,
      roles: ['admin'],
    });
    expect(payload.exp).toBe(expiresAt);
    expect(payload.exp - payload.iat).toBe(config.ACCESS_TOKEN_TTL / 1000);
    expect(decodeProtectedHeader(token)).toMatchObject({ alg: 'EdDSA', kid: 'k1', typ: 'JWT' });
  });

  it('omits empty roles', async () => {
    const env = makeEnv({ AUTH_SIGNING_KEY_DEV: JSON.stringify(await generateKey('k1')) });
    const { token } = await signAccessToken(env, claims);
    expect(decodeJwt(token)).not.toHaveProperty('roles');
  });

  it('prefers the Secrets Store over the dev key', async () => {
    const store = JSON.stringify(await generateKey('store'));
    const env = makeEnv({
      AUTH_SIGNING_KEY: { get: async () => store } as unknown as Env['AUTH_SIGNING_KEY'],
      AUTH_SIGNING_KEY_DEV: JSON.stringify(await generateKey('dev')),
    });
    const { token } = await signAccessToken(env, claims);
    expect(decodeProtectedHeader(token).kid).toBe('store');
  });

  it('rejects tokens signed by an unknown key', async () => {
    const signer = makeEnv({ AUTH_SIGNING_KEY_DEV: JSON.stringify(await generateKey('k1')) });
    const { token } = await signAccessToken(signer, claims);
    resetKeyCache();
    const other = makeEnv({ AUTH_SIGNING_KEY_DEV: JSON.stringify(await generateKey('k1')) });
    await expect(verifyAccessToken(other, token)).rejects.toThrow();
  });

  it('rejects expired tokens', async () => {
    const env = makeEnv({ AUTH_SIGNING_KEY_DEV: JSON.stringify(await generateKey('k1')) });
    const { token } = await signAccessToken(env, claims, Date.now() - 2 * config.ACCESS_TOKEN_TTL);
    await expect(verifyAccessToken(env, token)).rejects.toThrow();
  });

  it('fails clearly when no key is configured', async () => {
    await expect(signAccessToken(makeEnv(), claims)).rejects.toThrow('not in store');
  });
});

describe('getJwks', () => {
  it('publishes only public members', async () => {
    const env = makeEnv({ AUTH_SIGNING_KEY_DEV: JSON.stringify(await generateKey('k1')) });
    const { keys } = await getJwks(env);
    expect(keys).toHaveLength(1);
    expect(keys[0]).not.toHaveProperty('d');
    expect(keys[0]).toMatchObject({ kty: 'OKP', crv: 'Ed25519', kid: 'k1', alg: 'EdDSA', use: 'sig' });
  });

  it('publishes previous keys from a JWK Set; first key signs', async () => {
    const current = await generateKey('new');
    const { d: _d, ...previous } = await generateKey('old');
    const env = makeEnv({ AUTH_SIGNING_KEY_DEV: JSON.stringify({ keys: [current, previous] }) });
    const { keys } = await getJwks(env);
    expect(keys.map((k) => k.kid)).toEqual(['new', 'old']);
    const { token } = await signAccessToken(env, claims);
    expect(decodeProtectedHeader(token).kid).toBe('new');
  });
});

describe('parseKeySet', () => {
  it('rejects bad input without leaking key material', async () => {
    await expect(parseKeySet('not json')).rejects.toThrow('not valid JSON');
    const { d: _d, ...publicOnly } = await generateKey('k');
    await expect(parseKeySet(JSON.stringify(publicOnly))).rejects.toThrow('private JWK');
    const noKid = await generateKey('');
    await expect(parseKeySet(JSON.stringify(noKid))).rejects.toThrow('kid');
    const k = await generateKey('dup');
    await expect(parseKeySet(JSON.stringify({ keys: [k, k] }))).rejects.toThrow('duplicate');
    await expect(parseKeySet(JSON.stringify({ kty: 'RSA', kid: 'x' }))).rejects.toThrow('Ed25519');
  });
});
