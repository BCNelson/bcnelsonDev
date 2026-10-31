/**
 * Browser helper for SPAs on *.bcnelson.dev: fetch a short-lived access token
 * from the auth Worker, cache it, and share one request between callers.
 */

export interface GetAccessTokenOptions {
  /** Default 'https://auth.bcnelson.dev'. */
  issuer?: string;
  /** Refetch this long before expiry. Default 60 s. */
  leewayMs?: number;
  /** fetch override (tests). */
  fetch?: (input: string, init: { credentials: 'include' }) => Promise<Response>;
}

interface Cached {
  token: string;
  expiresAt: number; // ms
}

const cache = new Map<string, Cached>();
const inflight = new Map<string, Promise<string | null>>();

/** Returns a valid access token, or null when the user isn't signed in. */
export function getAccessToken(options: GetAccessTokenOptions = {}): Promise<string | null> {
  const issuer = (options.issuer ?? 'https://auth.bcnelson.dev').replace(/\/+$/, '');
  const leeway = options.leewayMs ?? 60 * 1000;
  const hit = cache.get(issuer);
  if (hit && hit.expiresAt - leeway > Date.now()) return Promise.resolve(hit.token);

  let pending = inflight.get(issuer);
  if (!pending) {
    // Typed loosely: this package compiles against workers-types, which lacks `credentials`.
    const doFetch = options.fetch ?? ((input, init) => fetch(input, init as RequestInit));
    pending = (async () => {
      try {
        const res = await doFetch(`${issuer}/session/token`, { credentials: 'include' });
        if (!res.ok) {
          cache.delete(issuer);
          return null;
        }
        const body = (await res.json()) as { access_token: string; expires_at: number | string };
        cache.set(issuer, { token: body.access_token, expiresAt: toMs(body.expires_at) });
        return body.access_token;
      } finally {
        inflight.delete(issuer);
      }
    })();
    inflight.set(issuer, pending);
  }
  return pending;
}

/** Drops the cached token (e.g. after logout or a 401). */
export function clearAccessToken(issuer = 'https://auth.bcnelson.dev'): void {
  cache.delete(issuer.replace(/\/+$/, ''));
}

/** Accepts epoch seconds, epoch ms, or an ISO string. */
function toMs(value: number | string): number {
  if (typeof value === 'string') return Date.parse(value);
  return value < 1e12 ? value * 1000 : value;
}
