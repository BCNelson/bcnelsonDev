/**
 * Password hashing, verification and policy (design §11).
 *
 * Stored hashes are versioned, self-describing strings so the scheme can change
 * with rehash-on-login (salt/hash: standard base64, no padding):
 *
 *   $argon2id$v=19$m=<KiB>,t=<passes>,p=<lanes>$<salt>$<hash>   current (PHC)
 *   pbkdf2-sha256$<iterations>$<salt>$<hash>                    legacy, verify only
 *
 * New hashes use argon2id with OWASP's minimum (m=19456 KiB, t=2, p=1); see
 * ./argon2.ts for how the wasm is loaded in Workers. PBKDF2 hashes (WebCrypto,
 * capped by Workers at 100,000 iterations) still verify and report
 * `needsRehash`, so they upgrade on the next successful login.
 *
 * Passwords are NFC-normalized before policy checks and hashing, so the same
 * password typed as composed or decomposed Unicode (e.g. "é" vs "e" + U+0301)
 * verifies the same way.
 */

import { config } from '../config';
import { argon2id } from './argon2';

/** Scheme tag of the current hash format. */
export const ARGON2ID_SCHEME = 'argon2id';
/** Argon2 version 0x13. */
export const ARGON2_VERSION = 19;
/** Current parameters (OWASP minimum): memory in KiB, passes, lanes. */
export const ARGON2_MEMORY_KIB = 19_456;
export const ARGON2_PASSES = 2;
export const ARGON2_PARALLELISM = 1;
/** Bounds accepted when parsing stored argon2id hashes (DoS guard). 64 MiB fits the wasm's initial memory. */
const ARGON2_MAX_MEMORY_KIB = 65_536;
const ARGON2_MAX_PASSES = 10;
const ARGON2_MAX_PARALLELISM = 4;

/** Legacy scheme, verify-only. */
export const PBKDF2_SCHEME = 'pbkdf2-sha256';
/** Workers reject PBKDF2 above 100,000 iterations; stored hashes above it cannot verify. */
export const PBKDF2_MAX_ITERATIONS = 100_000;

/** Salt length for new hashes, in bytes. */
export const SALT_BYTES = 16;
/** Derived key length for new hashes, in bytes. */
export const KEY_BYTES = 32;
/** Shortest salt / key accepted when parsing stored hashes, in bytes. */
const MIN_SALT_BYTES = 8;
const MIN_KEY_BYTES = 16;
const MAX_KEY_BYTES = 64;

/**
 * Fixed hash verified for unknown users so their timing matches a real check.
 * Must use the current parameters; regenerate it when they change (a test
 * enforces this). The password behind it is irrelevant.
 */
const DUMMY_HASH =
  '$argon2id$v=19$m=19456,t=2,p=1$FB7LTGDLp9gd3DlijaBOrw$vn4Uu6QX8YHYOFIxf0hXoCIXd8us2/idwe9BtJUXeQo';

const encoder = new TextEncoder();

export type PasswordPolicyError = 'too_short' | 'too_long' | 'invalid_unicode';

export interface VerifyResult {
  ok: boolean;
  /** True when `ok` and the stored hash uses an outdated scheme or weaker parameters. */
  needsRehash: boolean;
}

interface Argon2idHash {
  scheme: typeof ARGON2ID_SCHEME;
  memoryKiB: number;
  passes: number;
  parallelism: number;
  salt: Uint8Array;
  hash: Uint8Array;
}

interface Pbkdf2Hash {
  scheme: typeof PBKDF2_SCHEME;
  iterations: number;
  salt: Uint8Array;
  hash: Uint8Array;
}

type ParsedHash = Argon2idHash | Pbkdf2Hash;

/** NFC normalization applied everywhere a password is read. */
function normalize(password: string): string {
  return password.normalize('NFC');
}

/** Lone UTF-16 surrogates; TextEncoder would turn them into U+FFFD. */
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/**
 * Checks length bounds (in Unicode code points, after NFC) and rejects
 * ill-formed strings. No composition rules. Returns null when acceptable.
 */
export function validatePasswordPolicy(password: string): PasswordPolicyError | null {
  if (LONE_SURROGATE.test(password)) return 'invalid_unicode';
  let length = 0;
  for (const _ of normalize(password)) length++;
  if (length < config.PASSWORD_MIN_LENGTH) return 'too_short';
  if (length > config.PASSWORD_MAX_LENGTH) return 'too_long';
  return null;
}

/**
 * Hashes with the current scheme and parameters. Does not apply the policy,
 * but rejects passwords under 8 UTF-8 bytes (an argon2id library limit that
 * the policy's 8-code-point minimum always satisfies).
 */
export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const hash = await argon2(password, {
    scheme: ARGON2ID_SCHEME,
    memoryKiB: ARGON2_MEMORY_KIB,
    passes: ARGON2_PASSES,
    parallelism: ARGON2_PARALLELISM,
    salt,
    hash: new Uint8Array(KEY_BYTES),
  });
  return formatArgon2id(ARGON2_MEMORY_KIB, ARGON2_PASSES, ARGON2_PARALLELISM, salt, hash);
}

function formatArgon2id(m: number, t: number, p: number, salt: Uint8Array, hash: Uint8Array): string {
  const params = `m=${m},t=${t},p=${p}`;
  return ['', ARGON2ID_SCHEME, `v=${ARGON2_VERSION}`, params, toBase64(salt), toBase64(hash)].join('$');
}

/**
 * Verifies against any stored format `parse` understands. Never throws:
 * malformed or unsupported hashes return `{ ok: false }`.
 */
export async function verifyPassword(password: string, stored: string): Promise<VerifyResult> {
  const parsed = parse(stored);
  if (!parsed) return { ok: false, needsRehash: false };
  let derived: Uint8Array;
  try {
    derived =
      parsed.scheme === ARGON2ID_SCHEME
        ? await argon2(password, parsed)
        : await pbkdf2(password, parsed.salt, parsed.iterations, parsed.hash.byteLength);
  } catch {
    return { ok: false, needsRehash: false };
  }
  const ok = bytesEqual(derived, parsed.hash);
  return { ok, needsRehash: ok && isOutdated(parsed) };
}

/** Burns the same work as a real verification, for unknown users. */
export async function verifyDummy(password: string): Promise<void> {
  await verifyPassword(password, DUMMY_HASH);
}

/** Exposed for tests; not part of the module's contract. */
export const _internal = { DUMMY_HASH, parse };

/**
 * Anything but the exact current argon2id parameters is rehashed on login,
 * stronger ones included, so per-login cost and isolate memory stay predictable.
 */
function isOutdated(parsed: ParsedHash): boolean {
  return (
    parsed.scheme !== ARGON2ID_SCHEME ||
    parsed.memoryKiB !== ARGON2_MEMORY_KIB ||
    parsed.passes !== ARGON2_PASSES ||
    parsed.parallelism !== ARGON2_PARALLELISM ||
    parsed.salt.byteLength < SALT_BYTES ||
    parsed.hash.byteLength < KEY_BYTES
  );
}

const ARGON2ID_PATTERN =
  /^\$argon2id\$v=19\$m=([1-9][0-9]{0,8}),t=([1-9][0-9]{0,8}),p=([1-9][0-9]{0,8})\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$/;
const PBKDF2_PATTERN = /^pbkdf2-sha256\$([1-9][0-9]{0,8})\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$/;

/** Parses a stored hash string, or returns null if it isn't one we can verify. */
function parse(stored: string): ParsedHash | null {
  if (typeof stored !== 'string') return null;
  let m = ARGON2ID_PATTERN.exec(stored);
  if (m) {
    const memoryKiB = Number(m[1]);
    const passes = Number(m[2]);
    const parallelism = Number(m[3]);
    if (parallelism > ARGON2_MAX_PARALLELISM) return null;
    if (memoryKiB < 8 * parallelism || memoryKiB > ARGON2_MAX_MEMORY_KIB) return null;
    if (passes > ARGON2_MAX_PASSES) return null;
    const bytes = saltAndHash(m[4]!, m[5]!);
    return bytes && { scheme: ARGON2ID_SCHEME, memoryKiB, passes, parallelism, ...bytes };
  }
  m = PBKDF2_PATTERN.exec(stored);
  if (m) {
    const iterations = Number(m[1]);
    if (iterations > PBKDF2_MAX_ITERATIONS) return null;
    const bytes = saltAndHash(m[2]!, m[3]!);
    return bytes && { scheme: PBKDF2_SCHEME, iterations, ...bytes };
  }
  return null;
}

function saltAndHash(saltB64: string, hashB64: string): { salt: Uint8Array; hash: Uint8Array } | null {
  const salt = fromBase64(saltB64);
  const hash = fromBase64(hashB64);
  if (!salt || salt.byteLength < MIN_SALT_BYTES) return null;
  if (!hash || hash.byteLength < MIN_KEY_BYTES || hash.byteLength > MAX_KEY_BYTES) return null;
  return { salt, hash };
}

/** Derives a tag with the parameters (and tag length) of `target`. */
function argon2(password: string, target: Argon2idHash): Promise<Uint8Array> {
  return argon2id({
    password: encoder.encode(normalize(password)),
    salt: target.salt,
    memorySize: target.memoryKiB,
    passes: target.passes,
    parallelism: target.parallelism,
    tagLength: target.hash.byteLength,
  });
}

async function pbkdf2(
  password: string,
  salt: Uint8Array,
  iterations: number,
  bytes: number,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(normalize(password)),
    'PBKDF2',
    false,
    ['deriveBits'],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    key,
    bytes * 8,
  );
  return new Uint8Array(bits);
}

/** Constant-time for equal lengths; lengths come from the stored hash, not secrets. */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  let diff = 0;
  for (let i = 0; i < a.byteLength; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/** Standard base64 without padding (PHC style). */
function toBase64(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/=+$/, '');
}

function fromBase64(s: string): Uint8Array | null {
  // Unpadded base64 never has length ≡ 1 (mod 4).
  if (s.length % 4 === 1) return null;
  try {
    const bin = atob(s + '='.repeat((4 - (s.length % 4)) % 4));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    // Reject non-canonical encodings (stray bits in the last character).
    return toBase64(out) === s ? out : null;
  } catch {
    return null;
  }
}
