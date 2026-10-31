import { Hono } from 'hono';
import { describe, expect, it } from 'vitest';
import type { Env } from '../src/env';
import {
  checkOrigin,
  clientIp,
  isSiteOrigin,
  originCheck,
  siteCors,
  validateReturnTo,
  type AppEnv,
} from '../src/http';

function makeEnv(overrides: Partial<Env> = {}): Env {
  return {
    ISSUER: 'https://auth.bcnelson.dev',
    COOKIE_DOMAIN: 'bcnelson.dev',
    ALLOWED_ORIGINS: 'https://auth.bcnelson.dev, https://other.example',
    ...overrides,
  } as unknown as Env;
}

const env = makeEnv();
const devEnv = makeEnv({ COOKIE_DOMAIN: 'bcnelson.localhost', ALLOWED_ORIGINS: 'http://auth.bcnelson.localhost:8787' });
const DEFAULT = 'https://bcnelson.dev/';

describe('validateReturnTo', () => {
  it.each([
    ['https://bcnelson.dev', 'https://bcnelson.dev/'],
    ['https://bcnelson.dev/blog?x=1#y', 'https://bcnelson.dev/blog?x=1#y'],
    ['https://app.bcnelson.dev/path', 'https://app.bcnelson.dev/path'],
    ['https://a.b.bcnelson.dev/', 'https://a.b.bcnelson.dev/'],
    ['HTTPS://APP.BCNELSON.DEV/x', 'https://app.bcnelson.dev/x'],
  ])('allows %s', (input, expected) => {
    expect(validateReturnTo(input, env)).toBe(expected);
  });

  it.each([
    undefined,
    null,
    '',
    '/relative',
    '//evil.com',
    '///evil.com',
    '/\\evil.com',
    'https:evil.com',
    'https:/evil.com',
    'https://evil.com',
    'https://bcnelson.dev.evil.com/',
    'https://evilbcnelson.dev/',
    'https://bcnelson.dev.',
    'https://bcnelson.dev%2eevil.com/',
    'https://evil.com/.bcnelson.dev',
    'https://evil.com?.bcnelson.dev',
    'https://evil.com#.bcnelson.dev',
    'https://bcnelson.dev@evil.com/',
    'https://user:pass@bcnelson.dev/',
    'https://evil.com\\@bcnelson.dev/',
    'https://evil.com\\.bcnelson.dev/',
    'https://bcnelson.dev:8443/',
    'http://bcnelson.dev/',
    'javascript:alert(1)',
    'JaVaScRiPt:alert(1)//https://bcnelson.dev',
    'java\tscript:alert(1)',
    'data:text/html,hi',
    ' https://bcnelson.dev/',
    'https://bcnelson.dev/\nSet-Cookie: x',
    'https://bcnelson.dev/' + 'a'.repeat(3000),
    'not a url',
  ])('rejects %j', (input) => {
    expect(validateReturnTo(input, env)).toBe(DEFAULT);
  });

  it('allows http and ports for localhost-style dev domains', () => {
    expect(validateReturnTo('http://app.bcnelson.localhost:5173/x', devEnv)).toBe('http://app.bcnelson.localhost:5173/x');
    expect(validateReturnTo('http://evil.localhost/', devEnv)).toBe('http://bcnelson.localhost/');
    expect(validateReturnTo(undefined, devEnv)).toBe('http://bcnelson.localhost/');
  });
});

describe('isSiteOrigin', () => {
  it.each(['https://bcnelson.dev', 'https://app.bcnelson.dev', 'https://auth.bcnelson.dev'])('allows %s', (o) => {
    expect(isSiteOrigin(o, env)).toBe(true);
  });
  it.each([
    null,
    'null',
    'https://bcnelson.dev/',
    'https://app.bcnelson.dev/path',
    'http://app.bcnelson.dev',
    'https://app.bcnelson.dev:444',
    'https://bcnelson.dev.evil.com',
    'https://evilbcnelson.dev',
    'https://x@bcnelson.dev',
  ])('rejects %j', (o) => {
    expect(isSiteOrigin(o, env)).toBe(false);
  });
});

describe('checkOrigin', () => {
  it('lets safe methods through', () => {
    expect(checkOrigin('GET', null, env)).toBe(true);
    expect(checkOrigin('HEAD', 'https://evil.com', env)).toBe(true);
  });
  it('requires an allowed Origin for POST', () => {
    expect(checkOrigin('POST', 'https://auth.bcnelson.dev', env)).toBe(true);
    expect(checkOrigin('POST', 'https://other.example', env)).toBe(true);
    expect(checkOrigin('POST', undefined, env)).toBe(false);
    expect(checkOrigin('POST', 'null', env)).toBe(false);
    expect(checkOrigin('POST', 'https://evil.com', env)).toBe(false);
    expect(checkOrigin('DELETE', 'https://app.bcnelson.dev', env)).toBe(false);
  });
  it('accepts site origins only when asked', () => {
    expect(checkOrigin('POST', 'https://app.bcnelson.dev', env, true)).toBe(true);
    expect(checkOrigin('POST', 'https://bcnelson.dev.evil.com', env, true)).toBe(false);
  });
});

describe('middleware', () => {
  const app = new Hono<AppEnv>();
  app.use('*', originCheck({ sitePaths: ['/logout'] }));
  app.use('/token', siteCors({ methods: ['GET'] }));
  app.post('/thing', (c) => c.text('ok'));
  app.post('/logout', (c) => c.text('ok'));
  app.get('/token', (c) => c.text('ok'));

  const post = (path: string, origin?: string) =>
    app.request(path, { method: 'POST', headers: origin ? { Origin: origin } : {} }, env);

  it('originCheck blocks bad origins with 403', async () => {
    expect((await post('/thing', 'https://auth.bcnelson.dev')).status).toBe(200);
    expect((await post('/thing')).status).toBe(403);
    expect((await post('/thing', 'https://app.bcnelson.dev')).status).toBe(403);
    expect((await post('/logout', 'https://app.bcnelson.dev')).status).toBe(200);
    expect((await post('/logout', 'https://evil.com')).status).toBe(403);
  });

  it('siteCors reflects site origins with credentials', async () => {
    const ok = await app.request('/token', { headers: { Origin: 'https://app.bcnelson.dev' } }, env);
    expect(ok.headers.get('Access-Control-Allow-Origin')).toBe('https://app.bcnelson.dev');
    expect(ok.headers.get('Access-Control-Allow-Credentials')).toBe('true');
    const bad = await app.request('/token', { headers: { Origin: 'https://evil.com' } }, env);
    expect(bad.headers.get('Access-Control-Allow-Origin')).toBeNull();
    const pre = await app.request('/token', { method: 'OPTIONS', headers: { Origin: 'https://app.bcnelson.dev' } }, env);
    expect(pre.status).toBe(204);
    expect(pre.headers.get('Access-Control-Allow-Methods')).toBe('GET');
    const badPre = await app.request('/token', { method: 'OPTIONS', headers: { Origin: 'https://evil.com' } }, env);
    expect(badPre.status).toBe(403);
  });
});

describe('clientIp', () => {
  it('reads CF-Connecting-IP', () => {
    expect(clientIp(new Request('https://x', { headers: { 'CF-Connecting-IP': '203.0.113.9' } }))).toBe('203.0.113.9');
    expect(clientIp(new Request('https://x'))).toBeUndefined();
  });
});
