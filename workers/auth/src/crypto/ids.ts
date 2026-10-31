/**
 * Random identifiers, tokens and verification codes. All randomness comes
 * from crypto.getRandomValues.
 */

import { toBase64url } from './hash';

export type IdPrefix = 'usr' | 'ses' | 'cred' | 'sig';

/** Crockford base32, as used by ULID. */
const ULID_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const ULID_TIME_CHARS = 10;
const ULID_RANDOM_CHARS = 16;

/** A ULID: 48-bit millisecond timestamp + 80 random bits, 26 chars. */
export function ulid(now = Date.now()): string {
  let time = '';
  let t = now;
  for (let i = 0; i < ULID_TIME_CHARS; i++) {
    time = ULID_ALPHABET[t % 32] + time;
    t = Math.floor(t / 32);
  }
  // 16 chars x 5 bits = 80 bits; each random byte is masked to 5 bits (unbiased).
  const bytes = crypto.getRandomValues(new Uint8Array(ULID_RANDOM_CHARS));
  let rand = '';
  for (const b of bytes) rand += ULID_ALPHABET[b & 31];
  return time + rand;
}

/** A prefixed, time-sortable id such as `usr_01J...`. */
export function newId(prefix: IdPrefix): string {
  return `${prefix}_${ulid()}`;
}

/** `bytes` random bytes, base64url encoded. */
export function randomToken(bytes = 32): string {
  return toBase64url(crypto.getRandomValues(new Uint8Array(bytes)));
}

/**
 * A numeric code of `length` digits. Uses rejection sampling: bytes >= 250
 * are discarded so every digit is uniformly distributed.
 */
export function randomCode(length: number): string {
  let code = '';
  while (code.length < length) {
    const bytes = crypto.getRandomValues(new Uint8Array(length * 2));
    for (const b of bytes) {
      if (b >= 250) continue;
      code += String(b % 10);
      if (code.length === length) break;
    }
  }
  return code;
}
