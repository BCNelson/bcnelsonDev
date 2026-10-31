import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { config } from '../../src/config';
import { sha256Base64url } from '../../src/crypto/hash';
import type { Env } from '../../src/env';
import { formatClientRefreshToken, formatCode, parseClientRefreshToken, parseCode } from '../../src/oidc/formats';
import type { AuthorizeRequest } from '../../src/oidc/types';
import { fakeState } from './fake-storage';

vi.mock('cloudflare:workers', async () => ({
  DurableObject: (await import('./fake-storage')).FakeDurableObject,
}));

const { User } = await import('../../src/do/user');

const START = 1_800_000_000_000;
const VERIFIER = 'x'.repeat(43);
const USER_ID = 'usr_01HZZZZZZZZZZZZZZZZZZZZZZZ';

async function makeUser() {
  const fake = fakeState();
  const user = new User(fake.state as unknown as DurableObjectState, {} as Env);
  await user.initProfile({ userId: USER_ID, username: 'Brad', email: 'brad@example.com' });
  const session = await user.createSession({ amr: ['pwd'] });
  return { user, session, ...fake };
}

async function code(user: InstanceType<typeof User>, sessionId: string, scopes = ['openid', 'offline_access']) {
  const res = await user.createOAuthCode({
    sessionId, clientId: 'app', redirectUri: 'https://app.example.com/cb',
    codeChallenge: await sha256Base64url(VERIFIER), nonce: 'n', scopes,
  });
  if (!res.ok) throw new Error(res.reason);
  return res.secret;
}

function redeem(user: InstanceType<typeof User>, secret: string, extra: Partial<{ clientId: string; codeVerifier: string }> = {}) {
  return user.redeemOAuthCode({
    secret, clientId: 'app', redirectUri: 'https://app.example.com/cb', codeVerifier: VERIFIER, ...extra,
  });
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(START);
});
afterEach(() => {
  vi.useRealTimers();
});

describe('formats', () => {
  it('round-trips codes and client refresh tokens, rejects others', () => {
    const secret = 'a'.repeat(43);
    expect(parseCode(formatCode({ userId: USER_ID, secret }))).toEqual({ userId: USER_ID, secret });
    const tokenId = 'otk_01HZZZZZZZZZZZZZZZZZZZZZZZ';
    expect(parseClientRefreshToken(formatClientRefreshToken({ userId: USER_ID, tokenId, secret }))).toEqual({ userId: USER_ID, tokenId, secret });
    expect(parseCode(`rt1.${USER_ID}.${secret}`)).toBeNull();
    expect(parseClientRefreshToken(`rt1.${USER_ID}.ses_01HZZZZZZZZZZZZZZZZZZZZZZZ.${secret}`)).toBeNull();
    expect(parseCode(undefined)).toBeNull();
  });
});

describe('User DO oidc', () => {
  it('codes are single use; replay revokes the token row', async () => {
    const { user, session } = await makeUser();
    const secret = await code(user, session.sessionId);
    const first = await redeem(user, secret);
    expect(first).toMatchObject({ ok: true, scopes: ['openid', 'offline_access'], nonce: 'n' });
    if (!first.ok) throw new Error();
    expect(first.claims).toMatchObject({ sub: USER_ID, sid: session.sessionId });
    expect(first.refreshSecret).toBeTruthy();
    expect(await user.getOAuthTokenClaims(first.tokenId, session.sessionId, 'app')).not.toBeNull();
    expect(await redeem(user, secret)).toEqual({ ok: false, reason: 'reuse' });
    expect(await user.getOAuthTokenClaims(first.tokenId, session.sessionId, 'app')).toBeNull();
  });

  it('checks expiry, client, PKCE and the session', async () => {
    const { user, session } = await makeUser();
    let secret = await code(user, session.sessionId);
    vi.setSystemTime(START + config.OIDC_CODE_TTL);
    expect(await redeem(user, secret)).toEqual({ ok: false, reason: 'expired' });

    secret = await code(user, session.sessionId);
    expect(await redeem(user, secret, { clientId: 'other' })).toEqual({ ok: false, reason: 'mismatch' });
    secret = await code(user, session.sessionId);
    expect(await redeem(user, secret, { codeVerifier: 'y'.repeat(43) })).toEqual({ ok: false, reason: 'pkce' });
    expect(await redeem(user, 'z'.repeat(43))).toEqual({ ok: false, reason: 'invalid' });

    secret = await code(user, session.sessionId);
    await user.revokeSession(session.sessionId);
    expect(await redeem(user, secret)).toEqual({ ok: false, reason: 'session' });
    expect(await user.createOAuthCode({
      sessionId: session.sessionId, clientId: 'app', redirectUri: 'https://app.example.com/cb', codeChallenge: 'c'.repeat(43), scopes: ['openid'],
    })).toEqual({ ok: false, reason: 'session' });
  });

  it('refresh rotates without a grace window and outlives an idle browser session, not a revoked one', async () => {
    const { user, session } = await makeUser();
    const first = await redeem(user, await code(user, session.sessionId));
    if (!first.ok) throw new Error();
    // Refresh within the client TTL while the browser session idles out (60 d) → still works.
    let r0: { refreshSecret?: string } = { refreshSecret: first.refreshSecret };
    for (const at of [0.4, 0.8]) {
      vi.setSystemTime(START + config.REFRESH_TOKEN_TTL * at);
      const r = await user.refreshOAuthToken({ tokenId: first.tokenId, secret: r0.refreshSecret!, clientId: 'app' });
      if (!r.ok) throw new Error(r.reason);
      r0 = r;
    }
    vi.setSystemTime(START + config.REFRESH_TOKEN_TTL + 1000);
    const r1 = await user.refreshOAuthToken({ tokenId: first.tokenId, secret: r0.refreshSecret!, clientId: 'app' });
    expect(r1.ok).toBe(true);
    if (!r1.ok) throw new Error();
    expect(await user.refreshOAuthToken({ tokenId: first.tokenId, secret: r0.refreshSecret!, clientId: 'app' }))
      .toEqual({ ok: false, reason: 'reuse' });
    expect(await user.refreshOAuthToken({ tokenId: first.tokenId, secret: r1.refreshSecret!, clientId: 'app' }))
      .toEqual({ ok: false, reason: 'revoked' });

    const { user: u2, session: s2 } = await makeUser();
    const g = await redeem(u2, await code(u2, s2.sessionId));
    if (!g.ok) throw new Error();
    await u2.revokeAllSessions();
    expect(await u2.refreshOAuthToken({ tokenId: g.tokenId, secret: g.refreshSecret!, clientId: 'app' }))
      .toEqual({ ok: false, reason: 'session' });
  });

  it('without offline_access there is no refresh secret', async () => {
    const { user, session } = await makeUser();
    const g = await redeem(user, await code(user, session.sessionId, ['openid']));
    expect(g.ok && g.refreshSecret).toBeFalsy();
  });

  it('consent: grants merge; consent tokens are single use, per session, expiring', async () => {
    const { user, session } = await makeUser();
    expect(await user.getOAuthGrant('app')).toBeNull();
    await user.saveOAuthGrant('app', ['openid', 'email']);
    expect(await user.saveOAuthGrant('app', ['openid', 'profile'])).toEqual(['openid', 'profile', 'email']);
    expect(await user.listOAuthGrants()).toMatchObject([{ clientId: 'app', scopes: ['openid', 'profile', 'email'] }]);

    const request: AuthorizeRequest = {
      clientId: 'app', redirectUri: 'https://app.example.com/cb', scopes: ['openid'], codeChallenge: 'c'.repeat(43),
      prompt: { none: false, login: false, consent: false },
    };
    let { token } = await user.startOAuthConsent(session.sessionId, request);
    expect(await user.takeOAuthConsent(token, 'ses_01HOTHERZZZZZZZZZZZZZZZZZZ')).toBeNull();
    ({ token } = await user.startOAuthConsent(session.sessionId, request));
    expect(await user.takeOAuthConsent(token, session.sessionId)).toEqual(request);
    expect(await user.takeOAuthConsent(token, session.sessionId)).toBeNull();
    ({ token } = await user.startOAuthConsent(session.sessionId, request));
    vi.setSystemTime(START + config.OIDC_CONSENT_TTL);
    expect(await user.takeOAuthConsent(token, session.sessionId)).toBeNull();

    expect(await user.revokeOAuthClient('app')).toBe(true);
    expect(await user.getOAuthGrant('app')).toBeNull();
  });

  it('maintenance prunes oidc rows and keeps expired sessions that live client tokens need', async () => {
    const { user, session, db } = await makeUser();
    const g = await redeem(user, await code(user, session.sessionId));
    await code(user, session.sessionId); // unused, will expire
    await user.startOAuthConsent(session.sessionId, {
      clientId: 'app', redirectUri: 'https://app.example.com/cb', scopes: ['openid'], codeChallenge: 'c'.repeat(43),
      prompt: { none: false, login: false, consent: false },
    });
    if (!g.ok) throw new Error();
    const dead = await redeem(user, await code(user, session.sessionId, ['openid'])); // short-lived, no refresh
    expect(dead.ok).toBe(true);
    // Keep the offline token alive (sliding) while the browser session idles out.
    const day = 24 * 3600 * 1000;
    let secret = g.refreshSecret!;
    for (const at of [25, 50, 75]) {
      vi.setSystemTime(START + at * day);
      const r = await user.refreshOAuthToken({ tokenId: g.tokenId, secret, clientId: 'app' });
      if (!r.ok) throw new Error(r.reason);
      secret = r.refreshSecret!;
    }
    vi.setSystemTime(START + config.REFRESH_TOKEN_TTL + config.SESSION_RETENTION + day);
    await user.runMaintenance();
    const count = (t: string) => (db.prepare(`SELECT COUNT(*) AS n FROM ${t}`).all()[0] as { n: number }).n;
    expect(count('oauth_codes')).toBe(0);
    expect(count('oauth_requests')).toBe(0);
    expect(count('oauth_tokens')).toBe(1);
    expect(count('sessions')).toBe(1); // expired long ago, but the live client token needs it
    expect((await user.refreshOAuthToken({ tokenId: g.tokenId, secret, clientId: 'app' })).ok).toBe(true);
  });
});
