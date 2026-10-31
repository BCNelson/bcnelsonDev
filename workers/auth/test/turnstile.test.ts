import { describe, expect, it, vi } from 'vitest';
import { config } from '../src/config';
import type { Env } from '../src/env';
import { verifyTurnstile } from '../src/http/turnstile';

const ALWAYS_PASS = '1x0000000000000000000000000000000AA';

function env(overrides: Partial<Env> = {}): Env {
  return {
    COOKIE_DOMAIN: 'bcnelson.dev',
    TURNSTILE_SECRET: { get: async () => 'prod-secret' },
    ...overrides,
  } as unknown as Env;
}

const noStore = { get: async () => { throw new Error('not in store'); } };

function fakeFetch(response: unknown, status = 200) {
  return vi.fn(async (_url: string | URL | Request, _init?: RequestInit) =>
    new Response(JSON.stringify(response), { status, headers: { 'Content-Type': 'application/json' } }));
}

describe('verifyTurnstile', () => {
  it('posts secret, token and remoteip to siteverify', async () => {
    const fetch = fakeFetch({ success: true });
    expect(await verifyTurnstile(env(), 'tok', '1.2.3.4', { fetch })).toEqual({ ok: true });
    const [url, init] = fetch.mock.calls[0]!;
    expect(url).toBe(config.TURNSTILE_SITEVERIFY_URL);
    expect(init?.method).toBe('POST');
    const body = init?.body as FormData;
    expect(body.get('secret')).toBe('prod-secret');
    expect(body.get('response')).toBe('tok');
    expect(body.get('remoteip')).toBe('1.2.3.4');
  });

  it('reports rejection with error codes', async () => {
    const fetch = fakeFetch({ success: false, 'error-codes': ['invalid-input-response', 7] });
    expect(await verifyTurnstile(env(), 'tok', undefined, { fetch }))
      .toEqual({ ok: false, reason: 'invalid', errors: ['invalid-input-response'] });
    expect((fetch.mock.calls[0]![1]!.body as FormData).has('remoteip')).toBe(false);
  });

  it('missing or over-long token fails without calling siteverify', async () => {
    const fetch = fakeFetch({ success: true });
    expect(await verifyTurnstile(env(), '', 'ip', { fetch })).toEqual({ ok: false, reason: 'missing' });
    expect(await verifyTurnstile(env(), undefined, 'ip', { fetch })).toEqual({ ok: false, reason: 'missing' });
    expect(await verifyTurnstile(env(), 'x'.repeat(2049), 'ip', { fetch })).toEqual({ ok: false, reason: 'missing' });
    expect(fetch).not.toHaveBeenCalled();
  });

  it('fails closed on network errors and non-2xx', async () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const broken = vi.fn(async () => { throw new Error('boom'); });
    expect(await verifyTurnstile(env(), 'tok', 'ip', { fetch: broken })).toEqual({ ok: false, reason: 'unavailable' });
    expect(await verifyTurnstile(env(), 'tok', 'ip', { fetch: fakeFetch({}, 500) }))
      .toEqual({ ok: false, reason: 'unavailable' });
    spy.mockRestore();
  });

  it('production without a secret, or with a test secret, fails closed', async () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const fetch = fakeFetch({ success: true });
    expect(await verifyTurnstile(env({ TURNSTILE_SECRET: noStore as never }), 'tok', 'ip', { fetch }))
      .toEqual({ ok: false, reason: 'unavailable' });
    expect(await verifyTurnstile(env({ TURNSTILE_SECRET: noStore as never, TURNSTILE_SECRET_DEV: ALWAYS_PASS }), 'tok', 'ip', { fetch }))
      .toEqual({ ok: false, reason: 'unavailable' });
    expect(fetch).not.toHaveBeenCalled();
    spy.mockRestore();
  });

  it('dev: skips without a secret, uses the test secret when given', async () => {
    const dev = { COOKIE_DOMAIN: 'bcnelson.localhost', TURNSTILE_SECRET: noStore as never };
    const fetch = fakeFetch({ success: true });
    expect(await verifyTurnstile(env(dev), undefined, 'ip', { fetch })).toEqual({ ok: true, skipped: true });
    expect(fetch).not.toHaveBeenCalled();
    expect(await verifyTurnstile(env({ ...dev, TURNSTILE_SECRET_DEV: ALWAYS_PASS }), 'XXXX.DUMMY.TOKEN.XXXX', 'ip', { fetch }))
      .toEqual({ ok: true });
    expect((fetch.mock.calls[0]![1]!.body as FormData).get('secret')).toBe(ALWAYS_PASS);
  });

  it('prefers the Secrets Store over TURNSTILE_SECRET_DEV', async () => {
    const fetch = fakeFetch({ success: true });
    await verifyTurnstile(env({ TURNSTILE_SECRET_DEV: 'dev' }), 'tok', 'ip', { fetch });
    expect((fetch.mock.calls[0]![1]!.body as FormData).get('secret')).toBe('prod-secret');
  });
});
