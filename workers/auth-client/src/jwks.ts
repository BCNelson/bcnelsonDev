import { createLocalJWKSet, errors, type JSONWebKeySet, type JWTVerifyGetKey } from 'jose';
import type { FetchLike } from './types.js';

/** JWKS fetched on demand, cached for `ttlMs`, refetched once on an unknown kid. */
export interface JwksCache {
  getKey: JWTVerifyGetKey;
}

export function createJwksCache(url: string, doFetch: FetchLike, ttlMs: number, cooldownMs: number): JwksCache {
  let keySet: JWTVerifyGetKey | undefined;
  let fetchedAt = 0;
  let inflight: Promise<JWTVerifyGetKey> | undefined;

  /** Fetches the JWKS, deduping concurrent callers. */
  const load = (): Promise<JWTVerifyGetKey> => {
    inflight ??= (async () => {
      try {
        const res = await doFetch(url, { headers: { accept: 'application/json' } });
        if (!res.ok) throw new Error(`JWKS fetch failed: ${res.status}`);
        const jwks = (await res.json()) as JSONWebKeySet;
        if (!Array.isArray(jwks?.keys)) throw new Error('JWKS response has no keys');
        keySet = createLocalJWKSet(jwks);
        fetchedAt = Date.now();
        return keySet;
      } finally {
        inflight = undefined;
      }
    })();
    return inflight;
  };

  const current = (): Promise<JWTVerifyGetKey> =>
    keySet && Date.now() - fetchedAt < ttlMs ? Promise.resolve(keySet) : load();

  const getKey: JWTVerifyGetKey = async (header, token) => {
    const set = await current();
    try {
      return await set(header, token);
    } catch (err) {
      // Unknown kid: the key may have rotated. Refetch once, rate-limited.
      if (!(err instanceof errors.JWKSNoMatchingKey) || Date.now() - fetchedAt < cooldownMs) throw err;
      return (await load())(header, token);
    }
  };

  return { getKey };
}
