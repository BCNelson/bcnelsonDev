import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Env } from '../../src/env';
import { fakeState } from './fake-storage';

vi.mock('cloudflare:workers', async () => ({
  DurableObject: (await import('./fake-storage')).FakeDurableObject,
}));

const { UserIndex } = await import('../../src/do/user-index');

const NOW = 1_800_000_000_000;

function makeIndex() {
  const fake = fakeState();
  const index = new UserIndex(fake.state as unknown as DurableObjectState, {} as Env);
  return { index, ...fake };
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(NOW);
});
afterEach(() => {
  vi.useRealTimers();
});

describe('UserIndex DO', () => {
  it('resolves active usernames and emails, case-insensitively', async () => {
    const { index } = makeIndex();
    await index.registerAccount({ userId: 'usr_A', username: 'Brad', email: 'Brad@Example.com' });
    expect(await index.resolve('brad')).toBe('usr_A');
    expect(await index.resolve(' BRAD ')).toBe('usr_A');
    expect(await index.resolve('brad@example.COM')).toBe('usr_A');
    expect(await index.resolve('nobody')).toBeNull();
    expect(await index.resolve('nobody@example.com')).toBeNull();
  });

  it('does not resolve pending or held rows', async () => {
    const { index, db } = makeIndex();
    db.exec(`
      INSERT INTO handles VALUES ('pend', NULL, 'pending', ${NOW + 1000});
      INSERT INTO handles VALUES ('old', 'usr_B', 'held', ${NOW + 1000});
      INSERT INTO emails VALUES ('gone@example.com', 'usr_B', 'held', ${NOW + 1000});
    `);
    expect(await index.resolve('pend')).toBeNull();
    expect(await index.resolve('old')).toBeNull();
    expect(await index.resolve('gone@example.com')).toBeNull();
  });

  it('isUsernameAvailable honours status, expiry, pattern and reserved names', async () => {
    const { index, db } = makeIndex();
    await index.registerAccount({ userId: 'usr_A', username: 'brad', email: 'b@example.com' });
    db.exec(`
      INSERT INTO handles VALUES ('pend', NULL, 'pending', ${NOW + 1000});
      INSERT INTO handles VALUES ('stale', NULL, 'pending', ${NOW - 1});
    `);
    expect(await index.isUsernameAvailable('brad')).toBe(false);
    expect(await index.isUsernameAvailable('pend')).toBe(false);
    expect(await index.isUsernameAvailable('stale')).toBe(true);
    expect(await index.isUsernameAvailable('fresh')).toBe(true);
    expect(await index.isUsernameAvailable('admin')).toBe(false);
    expect(await index.isUsernameAvailable('x')).toBe(false);
  });

  it('registerAccount refuses taken handles and emails atomically', async () => {
    const { index } = makeIndex();
    await index.registerAccount({ userId: 'usr_A', username: 'brad', email: 'b@example.com' });
    await expect(index.registerAccount({ userId: 'usr_B', username: 'BRAD', email: 'c@example.com' }))
      .rejects.toThrow(/Username taken/);
    await expect(index.registerAccount({ userId: 'usr_B', username: 'other', email: 'B@example.com' }))
      .rejects.toThrow(/Email taken/);
    expect(await index.resolve('other')).toBeNull();
  });

  it('alarm sweeps expired rows only and reschedules for the next expiry', async () => {
    const { index, db, getAlarm } = makeIndex();
    await index.registerAccount({ userId: 'usr_A', username: 'brad', email: 'b@example.com' });
    db.exec(`
      INSERT INTO handles VALUES ('expired', NULL, 'pending', ${NOW - 1});
      INSERT INTO handles VALUES ('later', NULL, 'held', ${NOW + 5000});
      INSERT INTO emails VALUES ('old@example.com', 'usr_B', 'held', ${NOW});
      INSERT INTO pending_signups (signup_id, username, username_norm, email, email_norm,
        code_hash, expires_at) VALUES ('sg1', 'X', 'x', 'x@x.io', 'x@x.io', 'h', ${NOW - 1});
      INSERT INTO challenges (challenge, purpose, expires_at) VALUES ('ch1', 'login', ${NOW - 1});
      INSERT INTO challenges (challenge, purpose, expires_at) VALUES ('ch2', 'login', ${NOW + 3000});
    `);
    await index.alarm();
    const handles = db.prepare('SELECT username_norm FROM handles ORDER BY 1').all().map((r) => r.username_norm);
    expect(handles).toEqual(['brad', 'later']);
    expect(db.prepare('SELECT email_norm FROM emails').all().map((r) => r.email_norm)).toEqual(['b@example.com']);
    expect(db.prepare('SELECT COUNT(*) AS n FROM pending_signups').all()[0]!.n).toBe(0);
    expect(db.prepare('SELECT challenge FROM challenges').all().map((r) => r.challenge)).toEqual(['ch2']);
    expect(getAlarm()).toBe(NOW + 3000);
  });
});
