import { beforeEach, describe, expect, it, vi } from 'vitest';
import { clearAccessToken, getAccessToken } from '../src/browser.js';

const ISSUER = 'https://auth.bcnelson.dev';

function tokenFetch(expiresInSec = 900) {
  let n = 0;
  return vi.fn(async (_input: string, _init: { credentials: 'include' }) => {
    n += 1;
    const body = { access_token: `tok${n}`, expires_at: Math.floor(Date.now() / 1000) + expiresInSec };
    return new Response(JSON.stringify(body), { headers: { 'content-type': 'application/json' } });
  });
}

describe('getAccessToken', () => {
  beforeEach(() => clearAccessToken(ISSUER));

  it('fetches with credentials and caches the token', async () => {
    const fetch = tokenFetch();
    expect(await getAccessToken({ fetch })).toBe('tok1');
    expect(await getAccessToken({ fetch })).toBe('tok1');
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch).toHaveBeenCalledWith(`${ISSUER}/session/token`, { credentials: 'include' });
  });

  it('dedupes concurrent calls', async () => {
    const fetch = tokenFetch();
    const [a, b] = await Promise.all([getAccessToken({ fetch }), getAccessToken({ fetch })]);
    expect(a).toBe('tok1');
    expect(b).toBe('tok1');
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('refetches shortly before expiry', async () => {
    const fetch = tokenFetch(30);
    expect(await getAccessToken({ fetch })).toBe('tok1');
    expect(await getAccessToken({ fetch })).toBe('tok2');
  });

  it('returns null when signed out', async () => {
    const fetch = vi.fn(async () => new Response('{}', { status: 401 }));
    expect(await getAccessToken({ fetch })).toBeNull();
  });
});
