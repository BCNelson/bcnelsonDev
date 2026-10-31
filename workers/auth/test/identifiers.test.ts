import { describe, expect, it } from 'vitest';
import { config } from '../src/config';
import { sha256Base64url, timingSafeEqual, toBase64url } from '../src/crypto/hash';
import { newId, randomCode, randomToken, ulid } from '../src/crypto/ids';
import {
  classifyIdentifier,
  normalizeEmail,
  normalizeUsername,
  validateEmail,
  validateUsername,
} from '../src/identifiers';

describe('usernames', () => {
  it('normalizes by trimming and lowercasing ASCII only', () => {
    expect(normalizeUsername('  Brad_N ')).toBe('brad_n');
    // Kelvin sign must not fold into an ASCII "k".
    expect(normalizeUsername('Kate')).toBe('Kate');
  });

  it('accepts valid names and keeps the display form', () => {
    expect(validateUsername(' Brad-N_1 ')).toEqual({ ok: true, norm: 'brad-n_1', display: 'Brad-N_1' });
    expect(validateUsername('abc').ok).toBe(true);
    expect(validateUsername('a'.repeat(30)).ok).toBe(true);
  });

  it('rejects with a typed reason', () => {
    expect(validateUsername('   ')).toEqual({ ok: false, reason: 'empty' });
    expect(validateUsername('bräd')).toEqual({ ok: false, reason: 'non_ascii' });
    expect(validateUsername('Kate')).toEqual({ ok: false, reason: 'non_ascii' });
    expect(validateUsername('ab')).toEqual({ ok: false, reason: 'invalid_format' });
    expect(validateUsername('a'.repeat(31))).toEqual({ ok: false, reason: 'invalid_format' });
    expect(validateUsername('_brad')).toEqual({ ok: false, reason: 'invalid_format' });
    expect(validateUsername('br ad')).toEqual({ ok: false, reason: 'invalid_format' });
    expect(validateUsername('brad.n')).toEqual({ ok: false, reason: 'invalid_format' });
  });

  it('rejects every reserved name in any case', () => {
    for (const name of config.RESERVED_USERNAMES) {
      expect(validateUsername(name.toUpperCase())).toEqual({ ok: false, reason: 'reserved' });
    }
  });
});

describe('emails', () => {
  it('normalizes by trimming and lowercasing, without Gmail stripping', () => {
    expect(normalizeEmail('  First.Last+Tag@GMail.com ')).toBe('first.last+tag@gmail.com');
  });

  it('accepts pragmatic addresses', () => {
    expect(validateEmail(' A.B+c@Example.co.uk ')).toEqual({
      ok: true, norm: 'a.b+c@example.co.uk', display: 'A.B+c@Example.co.uk',
    });
    expect(validateEmail('x@münchen.de').ok).toBe(true);
  });

  it('rejects malformed addresses', () => {
    for (const bad of [
      'plain', '@example.com', 'a@', 'a@b', 'a@@b.com', 'a@b@c.com', 'a b@c.com',
      'a@-b.com', 'a@b-.com', 'a@b..com', '.a@b.com', 'a.@b.com', 'a..b@c.com', 'a@b_c.com',
      `${'a'.repeat(65)}@b.com`,
    ]) {
      expect(validateEmail(bad), bad).toEqual({ ok: false, reason: 'invalid_format' });
    }
    expect(validateEmail('')).toEqual({ ok: false, reason: 'empty' });
  });

  it('enforces the 254 character limit', () => {
    const at254 = `${'a'.repeat(61)}@${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(61)}.io`;
    expect(at254.length).toBe(254);
    expect(validateEmail(at254).ok).toBe(true);
    expect(validateEmail(`a${at254}`)).toEqual({ ok: false, reason: 'too_long' });
  });
});

describe('classifyIdentifier', () => {
  it('treats anything with @ as an email', () => {
    expect(classifyIdentifier(' Brad@Example.com')).toEqual({ kind: 'email', norm: 'brad@example.com' });
    expect(classifyIdentifier('Brad ')).toEqual({ kind: 'username', norm: 'brad' });
  });
});

describe('ids', () => {
  it('ulid is 26 Crockford chars and time-sortable', () => {
    const a = ulid(1_000);
    const b = ulid(2_000);
    expect(a).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);
    expect(a < b).toBe(true);
    expect(ulid(0).slice(0, 10)).toBe('0000000000');
    expect(ulid(2 ** 48 - 1).slice(0, 10)).toBe('7ZZZZZZZZZ');
  });

  it('newId prefixes and is unique', () => {
    expect(newId('usr')).toMatch(/^usr_[0-9A-Z]{26}$/);
    expect(newId('cred')).toMatch(/^cred_/);
    const ids = new Set(Array.from({ length: 1000 }, () => newId('ses')));
    expect(ids.size).toBe(1000);
  });

  it('randomToken is base64url of the requested length', () => {
    expect(randomToken()).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(randomToken(16)).toMatch(/^[A-Za-z0-9_-]{22}$/);
  });

  it('randomCode is numeric, fixed length and roughly uniform', () => {
    expect(randomCode(config.CODE_LENGTH)).toMatch(new RegExp(`^\\d{${config.CODE_LENGTH}}$`));
    expect(randomCode(1)).toMatch(/^\d$/);
    const counts = new Array(10).fill(0);
    const digits = randomCode(20_000);
    for (const d of digits) counts[Number(d)]++;
    for (const c of counts) expect(c).toBeGreaterThan(1700); // expected 2000
  });
});

describe('hash', () => {
  it('sha256Base64url matches a known vector', async () => {
    expect(await sha256Base64url('abc')).toBe('ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0');
  });

  it('toBase64url has no padding or +/', () => {
    expect(toBase64url(new Uint8Array([0xfb, 0xff]))).toBe('-_8');
  });

  it('timingSafeEqual', () => {
    expect(timingSafeEqual('abc', 'abc')).toBe(true);
    expect(timingSafeEqual('abc', 'abd')).toBe(false);
    expect(timingSafeEqual('abc', 'abcd')).toBe(false);
    expect(timingSafeEqual('', '')).toBe(true);
    expect(timingSafeEqual('ä', 'a')).toBe(false);
  });
});
