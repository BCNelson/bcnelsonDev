import { describe, expect, it } from 'vitest';
import { config } from '../src/config';
import { argon2id } from '../src/crypto/argon2';
import {
  ARGON2_MEMORY_KIB,
  ARGON2_PARALLELISM,
  ARGON2_PASSES,
  KEY_BYTES,
  PBKDF2_MAX_ITERATIONS,
  SALT_BYTES,
  _internal,
  hashPassword,
  validatePasswordPolicy,
  verifyDummy,
  verifyPassword,
} from '../src/crypto/password';

// Node's native (OpenSSL) argon2 as an independent reference. Imported by
// string so tsc (no @types/node) doesn't try to resolve it.
const nodeCrypto = 'node:crypto';
const { argon2Sync } = (await import(nodeCrypto)) as {
  argon2Sync(
    algorithm: 'argon2id',
    params: {
      message: Uint8Array; nonce: Uint8Array; parallelism: number;
      passes: number; memory: number; tagLength: number;
    },
  ): Uint8Array;
};

const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64').replace(/=+$/, '');
const enc = (password: string) => new TextEncoder().encode(password.normalize('NFC'));

/** Builds a PBKDF2 hash (legacy scheme) independently of the module. */
async function pbkdf2Hash(password: string, iterations: number, saltBytes = 16, keyBytes = 32) {
  const salt = crypto.getRandomValues(new Uint8Array(saltBytes));
  const key = await crypto.subtle.importKey('raw', enc(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, keyBytes * 8,
  );
  return `pbkdf2-sha256$${iterations}$${b64(salt)}$${b64(new Uint8Array(bits))}`;
}

/** Builds an argon2id PHC string with Node's native (OpenSSL) argon2, independently of the module. */
function argon2Hash(
  password: string,
  { m = ARGON2_MEMORY_KIB, t = ARGON2_PASSES, p = ARGON2_PARALLELISM, saltBytes = 16, keyBytes = 32 } = {},
) {
  const salt = crypto.getRandomValues(new Uint8Array(saltBytes));
  const tag = argon2Sync('argon2id', {
    message: enc(password), nonce: salt, parallelism: p, passes: t, memory: m, tagLength: keyBytes,
  });
  return `$argon2id$v=19$m=${m},t=${t},p=${p}$${b64(salt)}$${b64(tag)}`;
}

describe('argon2id core', () => {
  it('matches the RFC 9106 §5.3 test vector', async () => {
    const tag = await argon2id({
      password: new Uint8Array(32).fill(1),
      salt: new Uint8Array(16).fill(2),
      secret: new Uint8Array(8).fill(3),
      ad: new Uint8Array(12).fill(4),
      parallelism: 4, passes: 3, memorySize: 32, tagLength: 32,
    });
    expect(Buffer.from(tag).toString('hex'))
      .toBe('0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659');
  });
});

describe('hashPassword / verifyPassword', () => {
  it('round-trips with the current parameters', async () => {
    const stored = await hashPassword('correct horse battery staple');
    expect(stored).toMatch(/^\$argon2id\$v=19\$m=19456,t=2,p=1\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$/);
    expect(await verifyPassword('correct horse battery staple', stored))
      .toEqual({ ok: true, needsRehash: false });
  });

  it('agrees with a reference implementation (Node/OpenSSL argon2) both ways', async () => {
    const stored = await hashPassword('hunter22hunter22');
    const [, , , , salt, hash] = stored.split('$');
    const expected = argon2Sync('argon2id', {
      message: enc('hunter22hunter22'), nonce: Buffer.from(salt!, 'base64'),
      parallelism: 1, passes: 2, memory: 19456, tagLength: 32,
    });
    expect(hash).toBe(b64(expected));
    expect(await verifyPassword('hunter22hunter22', argon2Hash('hunter22hunter22')))
      .toEqual({ ok: true, needsRehash: false });
  });

  it('uses a fresh salt each time', async () => {
    expect(await hashPassword('same password')).not.toBe(await hashPassword('same password'));
  });

  it('rejects a wrong password', async () => {
    const stored = await hashPassword('correct horse battery staple');
    expect(await verifyPassword('correct horse battery stapl', stored))
      .toEqual({ ok: false, needsRehash: false });
    expect(await verifyPassword('', stored)).toEqual({ ok: false, needsRehash: false });
    expect(await verifyPassword('short', stored)).toEqual({ ok: false, needsRehash: false });
  });

  it('verifies legacy PBKDF2 hashes and flags them for rehash', async () => {
    const legacy = await pbkdf2Hash('hunter22hunter22', PBKDF2_MAX_ITERATIONS);
    expect(await verifyPassword('hunter22hunter22', legacy)).toEqual({ ok: true, needsRehash: true });
    expect(await verifyPassword('hunter22hunter2', legacy)).toEqual({ ok: false, needsRehash: false });
    const weak = await pbkdf2Hash('password1234', 10_000, 8, 16);
    expect(await verifyPassword('password1234', weak)).toEqual({ ok: true, needsRehash: true });
  });

  it('flags argon2id hashes with other parameters for rehash', async () => {
    const cases = [
      { m: 8192 }, { t: 1 }, { p: 2 }, // weaker / different cost
      { m: 32768, t: 3 }, // stronger: still normalized to current
      { saltBytes: 8 }, { keyBytes: 16 },
    ];
    for (const params of cases) {
      const stored = argon2Hash('password1234', params);
      expect(await verifyPassword('password1234', stored), JSON.stringify(params))
        .toEqual({ ok: true, needsRehash: true });
    }
  });

  it('does not flag rehash on a failed verification', async () => {
    expect(await verifyPassword('nope-nope', await pbkdf2Hash('password1234', 1_000)))
      .toEqual({ ok: false, needsRehash: false });
    expect(await verifyPassword('nope-nope', argon2Hash('password1234', { t: 1 })))
      .toEqual({ ok: false, needsRehash: false });
  });

  it('returns ok:false for malformed stored strings without throwing', async () => {
    const good = await hashPassword('password1234');
    const [, , , , salt, hash] = good.split('$');
    const legacy = await pbkdf2Hash('password1234', 1_000);
    const [, , ls, lh] = legacy.split('$');
    const a = (params: string, s = salt, h = hash) => `$argon2id$v=19$${params}$${s}$${h}`;
    const bad: unknown[] = [
      '',
      'garbage',
      '$$$',
      '$$$$$',
      good + '$',
      good.toUpperCase(),
      good.slice(1),
      `$argon2i$v=19$m=19456,t=2,p=1$${salt}$${hash}`,
      `$argon2d$v=19$m=19456,t=2,p=1$${salt}$${hash}`,
      `$argon2id$v=16$m=19456,t=2,p=1$${salt}$${hash}`,
      `$argon2id$m=19456,t=2,p=1$${salt}$${hash}`,
      a('m=19456,t=2'),
      a('t=2,m=19456,p=1'),
      a('m=19456,t=2,p=1,keyid=abc'),
      a('m=0,t=2,p=1'),
      a('m=7,t=2,p=1'), // below 8*p
      a('m=31,t=2,p=4'),
      a('m=019456,t=2,p=1'),
      a('m=65537,t=2,p=1'), // above memory cap
      a('m=999999999,t=2,p=1'),
      a('m=19456,t=0,p=1'),
      a('m=19456,t=11,p=1'), // above passes cap
      a('m=19456,t=2,p=0'),
      a('m=19456,t=2,p=5'), // above lanes cap
      a('m=19456,t=2,p=1', ''),
      a('m=19456,t=2,p=1', salt, ''),
      a('m=19456,t=2,p=1', salt, hash + '=='),
      a('m=19456,t=2,p=1', salt, hash!.slice(0, -1)),
      a('m=19456,t=2,p=1', salt, hash!.slice(0, -1) + '!'),
      a('m=19456,t=2,p=1', 'AAAA'), // salt too short
      a('m=19456,t=2,p=1', salt, 'A'.repeat(200)), // key too long
      a('m=19456,t=2,p=1', salt!.replace(/^./, '-')), // base64url alphabet
      `pbkdf2-sha256$0$${ls}$${lh}`,
      `pbkdf2-sha256$-1$${ls}$${lh}`,
      `pbkdf2-sha256$0100000$${ls}$${lh}`,
      `pbkdf2-sha256$1e5$${ls}$${lh}`,
      `pbkdf2-sha256$100001$${ls}$${lh}`, // above the Workers cap
      `pbkdf2-sha256$999999999999$${ls}$${lh}`,
      `pbkdf2-sha256$1000$$${lh}`,
      `pbkdf2-sha256$1000$${ls}$`,
      `pbkdf2-sha256$1000$AAAA$${lh}`,
      `pbkdf2-sha512$1000$${ls}$${lh}`,
      null,
      undefined,
      42,
    ];
    for (const stored of bad) {
      await expect(verifyPassword('password1234', stored as string), String(stored)).resolves
        .toEqual({ ok: false, needsRehash: false });
    }
  });

  it('treats NFC and NFD forms of a password as equal', async () => {
    const composed = 'café-paßwort-Ångström';
    const decomposed = composed.normalize('NFD');
    expect(decomposed).not.toBe(composed);
    const stored = await hashPassword(decomposed);
    expect((await verifyPassword(composed, stored)).ok).toBe(true);
    expect((await verifyPassword(decomposed, stored)).ok).toBe(true);
  });

  it('hashes every policy-valid password (the library needs >= 8 UTF-8 bytes)', async () => {
    const min = 'a'.repeat(config.PASSWORD_MIN_LENGTH);
    expect(validatePasswordPolicy(min)).toBeNull();
    expect((await verifyPassword(min, await hashPassword(min))).ok).toBe(true);
    const max = '\u{1F600}'.repeat(config.PASSWORD_MAX_LENGTH);
    expect(validatePasswordPolicy(max)).toBeNull();
    expect((await verifyPassword(max, await hashPassword(max))).ok).toBe(true);
  });
});

describe('verifyDummy', () => {
  it('resolves and uses the current parameters', async () => {
    await expect(verifyDummy('anything')).resolves.toBeUndefined();
    await expect(verifyDummy('')).resolves.toBeUndefined();
    const parsed = _internal.parse(_internal.DUMMY_HASH);
    expect(parsed).toMatchObject({
      scheme: 'argon2id',
      memoryKiB: ARGON2_MEMORY_KIB,
      passes: ARGON2_PASSES,
      parallelism: ARGON2_PARALLELISM,
    });
    expect(parsed!.salt.byteLength).toBe(SALT_BYTES);
    expect(parsed!.hash.byteLength).toBe(KEY_BYTES);
  });
});

describe('validatePasswordPolicy', () => {
  const min = config.PASSWORD_MIN_LENGTH;
  const max = config.PASSWORD_MAX_LENGTH;

  it('enforces the length bounds', () => {
    expect(validatePasswordPolicy('')).toBe('too_short');
    expect(validatePasswordPolicy('a'.repeat(min - 1))).toBe('too_short');
    expect(validatePasswordPolicy('a'.repeat(min))).toBeNull();
    expect(validatePasswordPolicy('a'.repeat(max))).toBeNull();
    expect(validatePasswordPolicy('a'.repeat(max + 1))).toBe('too_long');
  });

  it('has no composition rules', () => {
    expect(validatePasswordPolicy('        ')).toBeNull();
    expect(validatePasswordPolicy('aaaaaaaa')).toBeNull();
  });

  it('counts code points, not UTF-16 units', () => {
    const emoji = '\u{1F600}'; // 2 UTF-16 units
    expect(validatePasswordPolicy(emoji.repeat(min))).toBeNull();
    expect(validatePasswordPolicy(emoji.repeat(min - 1))).toBe('too_short');
    expect(validatePasswordPolicy(emoji.repeat(max))).toBeNull();
    expect(validatePasswordPolicy(emoji.repeat(max + 1))).toBe('too_long');
  });

  it('counts length after NFC normalization', () => {
    // "e" + combining acute is 2 code points in NFD, 1 after NFC.
    const nfd = 'é'.repeat(min - 1);
    expect(nfd.length).toBe(2 * (min - 1));
    expect(validatePasswordPolicy(nfd)).toBe('too_short');
  });

  it('rejects lone surrogates', () => {
    expect(validatePasswordPolicy('abcdefgh\uD800')).toBe('invalid_unicode');
    expect(validatePasswordPolicy('\uDC00abcdefgh')).toBe('invalid_unicode');
    expect(validatePasswordPolicy('abcdefgh😀')).toBeNull();
  });
});
