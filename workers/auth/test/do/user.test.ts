import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { config } from '../../src/config';
import { sha256Base64url } from '../../src/crypto/hash';
import type { Env } from '../../src/env';
import { USER_MIGRATIONS } from '../../src/do/schema';
import { fakeState } from './fake-storage';

vi.mock('cloudflare:workers', async () => ({
  DurableObject: (await import('./fake-storage')).FakeDurableObject,
}));

const { User } = await import('../../src/do/user');

const START = 1_800_000_000_000;

async function makeUser(withProfile = true) {
  const fake = fakeState();
  const user = new User(fake.state as unknown as DurableObjectState, {} as Env);
  if (withProfile) {
    await user.initProfile({ userId: 'usr_TEST', username: 'Brad', email: ' Brad@Example.com ' });
  }
  return { user, ...fake };
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(START);
});
afterEach(() => {
  vi.useRealTimers();
});

describe('User DO', () => {
  it('initProfile refuses to run twice', async () => {
    const { user } = await makeUser();
    await expect(user.initProfile({ userId: 'usr_X', username: 'x', email: 'x@x.io' }))
      .rejects.toThrow(/already exists/);
  });

  it('createSession throws without a profile', async () => {
    const { user } = await makeUser(false);
    await expect(user.createSession({ amr: ['pwd'] })).rejects.toThrow(/profile/);
  });

  it('createSession returns claims and stores only the secret hash', async () => {
    const { user, db } = await makeUser();
    const { sessionId, secret, claims } = await user.createSession({ amr: ['pwd'], ip: '1.2.3.4' });
    expect(sessionId).toMatch(/^ses_[0-9A-Z]{26}$/);
    expect(claims).toEqual({
      sub: 'usr_TEST',
      sid: sessionId,
      auth_time: START / 1000,
      amr: ['pwd'],
      preferred_username: 'Brad',
      email: 'brad@example.com',
    });
    const stored = db.prepare('SELECT secret_hash FROM sessions').all()[0]!;
    expect(stored.secret_hash).toBe(await sha256Base64url(secret));
    expect(JSON.stringify(db.prepare('SELECT * FROM sessions').all())).not.toContain(secret);
  });

  it('refresh rotates, honours the grace window, then detects reuse', async () => {
    const { user } = await makeUser();
    const { sessionId, secret: s0 } = await user.createSession({ amr: ['pwd'] });

    vi.setSystemTime(START + 1000);
    const r1 = await user.refreshSession(sessionId, s0);
    expect(r1.ok).toBe(true);
    if (!r1.ok) return;
    expect(r1.secret).not.toBe(s0);
    expect(r1.claims.auth_time).toBe(START / 1000); // refresh is not an interactive login

    // A concurrent tab presents s0 inside the grace window: claims, but no new
    // secret, so the browser keeps r1's cookie.
    vi.setSystemTime(START + 1000 + config.REFRESH_GRACE);
    const r2 = await user.refreshSession(sessionId, s0);
    expect(r2.ok).toBe(true);
    if (!r2.ok) return;
    expect(r2.secret).toBeUndefined();

    // r1's secret is still current after grace and rotates normally.
    vi.setSystemTime(START + 1000 + 2 * config.REFRESH_GRACE + 1);
    const r3 = await user.refreshSession(sessionId, r1.secret!);
    expect(r3.ok).toBe(true);

    // r1's secret is now the previous one; once grace passes it counts as theft.
    vi.setSystemTime(START + 1000 + 3 * config.REFRESH_GRACE + 2);
    expect(await user.refreshSession(sessionId, r1.secret!)).toEqual({ ok: false, reason: 'reuse' });
    expect(await user.listSessions()).toEqual([]);
  });

  it('refresh slides expiry and updates last_seen_at', async () => {
    const { user } = await makeUser();
    const { sessionId, secret } = await user.createSession({ amr: ['pwd'] });
    const later = START + config.REFRESH_TOKEN_TTL - 1;
    vi.setSystemTime(later);
    const r = await user.refreshSession(sessionId, secret);
    expect(r.ok).toBe(true);
    const [info] = await user.listSessions();
    expect(info).toMatchObject({ lastSeenAt: later, expiresAt: later + config.REFRESH_TOKEN_TTL });
  });

  it('refresh rejects wrong secrets, unknown and expired sessions', async () => {
    const { user } = await makeUser();
    const { sessionId, secret } = await user.createSession({ amr: ['pwd'] });
    expect(await user.refreshSession(sessionId, 'wrong')).toEqual({ ok: false, reason: 'invalid' });
    expect(await user.refreshSession('ses_nope', secret)).toEqual({ ok: false, reason: 'invalid' });
    vi.setSystemTime(START + config.REFRESH_TOKEN_TTL);
    expect(await user.refreshSession(sessionId, secret)).toEqual({ ok: false, reason: 'expired' });
  });

  it('revokeSession, revokeAllSessions and getClaims', async () => {
    const { user, db } = await makeUser();
    const a = await user.createSession({ amr: ['pwd'], userAgent: 'A' });
    const b = await user.createSession({ amr: ['hwk'], userAgent: 'B' });
    const c = await user.createSession({ amr: ['pwd'], userAgent: 'C' });
    expect((await user.listSessions()).map((s) => s.userAgent).sort()).toEqual(['A', 'B', 'C']);

    await user.revokeSession(a.sessionId);
    expect(await user.getClaims(a.sessionId)).toBeNull();
    expect(await user.refreshSession(a.sessionId, a.secret)).toEqual({ ok: false, reason: 'revoked' });

    expect(await user.revokeAllSessions(b.sessionId)).toBe(1);
    expect((await user.listSessions()).map((s) => s.id)).toEqual([b.sessionId]);
    expect(await user.getClaims(c.sessionId)).toBeNull();

    db.exec(`UPDATE profile SET roles = '["admin"]', name = 'Bradley'`);
    expect(await user.getClaims(b.sessionId)).toMatchObject({
      sid: b.sessionId, amr: ['hwk'], roles: ['admin'], name: 'Bradley',
    });

    const events = db.prepare('SELECT event FROM audit_log ORDER BY rowid').all().map((r) => r.event);
    expect(events).toEqual([
      'profile.created', 'session.created', 'session.created', 'session.created',
      'session.revoked', 'session.revoked_all',
    ]);
  });

  it('revokeSession with a secret only revokes on a matching secret', async () => {
    const { user } = await makeUser();
    const { sessionId, secret } = await user.createSession({ amr: ['pwd'] });
    await user.revokeSession(sessionId, 'forged');
    expect(await user.getClaims(sessionId)).not.toBeNull();

    // The in-grace previous secret still counts (logout racing a refresh).
    const r = await user.refreshSession(sessionId, secret);
    expect(r.ok).toBe(true);
    await user.revokeSession(sessionId, secret);
    expect(await user.getClaims(sessionId)).toBeNull();
  });

  it('revokeSession with a stale (post-grace) secret does nothing', async () => {
    const { user } = await makeUser();
    const { sessionId, secret } = await user.createSession({ amr: ['pwd'] });
    const r = await user.refreshSession(sessionId, secret);
    if (!r.ok) throw new Error('refresh failed');
    vi.setSystemTime(START + config.REFRESH_GRACE + 1);
    await user.revokeSession(sessionId, secret);
    expect(await user.getClaims(sessionId)).not.toBeNull();
    await user.revokeSession(sessionId, r.secret);
    expect(await user.getClaims(sessionId)).toBeNull();
  });

  it('runs migrations once per storage', async () => {
    const { state, db } = await makeUser();
    new User(state as unknown as DurableObjectState, {} as Env);
    expect(db.prepare('SELECT COUNT(*) AS n FROM _migrations').all()[0]!.n).toBe(USER_MIGRATIONS.length);
  });
});
