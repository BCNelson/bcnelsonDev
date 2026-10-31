/**
 * Signing key loading. AUTH_SIGNING_KEY holds either one Ed25519 private JWK or
 * a JWK Set whose first key signs and whose remaining keys (private or public)
 * are only published, so tokens they signed keep verifying during rotation.
 */

import { importJWK, type JWK } from 'jose';
import type { Env } from '../env';

export const SIGNING_ALG = 'EdDSA';

/** The key that signs new tokens. */
export interface SigningKey {
  kid: string;
  privateKey: CryptoKey;
}

export interface KeySet {
  current: SigningKey;
  /** Public JWKs to publish: current first, then previous keys. */
  publicJwks: JWK[];
}

let cached: Promise<KeySet> | undefined;

/** Loads and imports the key set once per isolate. */
export function loadKeySet(env: Env): Promise<KeySet> {
  cached ??= readKeyMaterial(env)
    .then(parseKeySet)
    .catch((err: unknown) => {
      cached = undefined;
      throw err;
    });
  return cached;
}

/** Drops the per-isolate cache (tests, or after a rotation). */
export function resetKeyCache(): void {
  cached = undefined;
}

/** Secrets Store first; AUTH_SIGNING_KEY_DEV when the store is empty or unavailable. */
async function readKeyMaterial(env: Env): Promise<string> {
  try {
    const value = await env.AUTH_SIGNING_KEY?.get();
    if (value) return value;
  } catch (err) {
    if (!env.AUTH_SIGNING_KEY_DEV) throw err;
  }
  if (env.AUTH_SIGNING_KEY_DEV) return env.AUTH_SIGNING_KEY_DEV;
  throw new Error('AUTH_SIGNING_KEY is not set');
}

/** Parses one private JWK or a JWK Set. Error messages never include key material. */
export async function parseKeySet(raw: string): Promise<KeySet> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error('AUTH_SIGNING_KEY is not valid JSON');
  }
  const keys = isRecord(parsed) && Array.isArray(parsed.keys) ? (parsed.keys as unknown[]) : [parsed];
  const [first, ...rest] = keys;
  if (!isRecord(first)) throw new Error('AUTH_SIGNING_KEY has no keys');

  const current = await importSigningKey(first);
  const publicJwks = [first, ...rest].map(toPublicJwk);
  const kids = new Set(publicJwks.map((k) => k.kid));
  if (kids.size !== publicJwks.length) throw new Error('AUTH_SIGNING_KEY has duplicate kids');
  return { current, publicJwks };
}

async function importSigningKey(jwk: Record<string, unknown>): Promise<SigningKey> {
  const pub = toPublicJwk(jwk);
  if (typeof jwk.d !== 'string' || jwk.d === '') {
    throw new Error('current signing key must be a private JWK');
  }
  const privateKey = await importJWK({ kty: 'OKP', crv: 'Ed25519', x: pub.x, d: jwk.d }, SIGNING_ALG);
  if (!(privateKey instanceof CryptoKey)) throw new Error('signing key did not import as a CryptoKey');
  return { kid: pub.kid!, privateKey };
}

/** Validates an Ed25519 JWK and returns only its public members. */
function toPublicJwk(jwk: unknown): JWK {
  if (!isRecord(jwk)) throw new Error('signing key is not an object');
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519') throw new Error('signing key must be Ed25519 (OKP)');
  if (typeof jwk.x !== 'string' || jwk.x === '') throw new Error('signing key is missing x');
  if (typeof jwk.kid !== 'string' || jwk.kid === '') throw new Error('signing key is missing kid');
  return { kty: 'OKP', crv: 'Ed25519', x: jwk.x, kid: jwk.kid, alg: SIGNING_ALG, use: 'sig' };
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}
