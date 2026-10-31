import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { config } from '../../src/config';
import { EXPIRING } from '../../src/do/index/maintenance';
import { longestActionWindow } from '../../src/do/user/maintenance';
import { makeFakeEnv } from './fake-env';

vi.mock('cloudflare:workers', async () => ({
  DurableObject: (await import('./fake-storage')).FakeDurableObject,
}));
vi.mock('../../src/crypto/password', async () => (await import('./fake-env')).fakePasswordModule());

const { User } = await import('../../src/do/user');
const { UserIndex } = await import('../../src/do/user-index');

const NOW = 1_800_000_000_000;
const DAY = 24 * 60 * 60 * 1000;

async function setup() {
  const fake = makeFakeEnv({ User, UserIndex });
  const user = fake.env.USER.get(fake.env.USER.idFromName('usr_TEST')) as unknown as InstanceType<typeof User>;
  await user.initProfile({ userId: 'usr_TEST', username: 'Brad', email: 'brad@example.com' });
  const { db } = fake.users.instances.get('usr_TEST')!.fake;
  const count = (table: string) => (db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).all()[0]!.n as number);
  return { user, db, count };
}

function insertSession(db: any, id: string, opts: { expiresAt: number; revokedAt?: number | null }) {
  db.prepare(
    `INSERT INTO sessions (id, secret_hash, created_at, last_seen_at, auth_time, amr, expires_at, revoked_at)
     VALUES (?, 'h', 0, 0, 0, '[]', ?, ?)`,
  ).run(id, opts.expiresAt, opts.revokedAt ?? null);
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(NOW);
});
afterEach(() => {
  vi.useRealTimers();
});

describe('User maintenance', () => {
  it('prunes each table at its threshold', async () => {
    const { user, db } = await setup();
    db.prepare('DELETE FROM audit_log').run();
    const keep = NOW - config.SESSION_RETENTION + 1;
    const drop = NOW - config.SESSION_RETENTION;
    insertSession(db, 'active', { expiresAt: NOW + DAY });
    insertSession(db, 'revoked-recent', { expiresAt: NOW + DAY, revokedAt: keep });
    insertSession(db, 'revoked-old', { expiresAt: NOW + DAY, revokedAt: drop });
    insertSession(db, 'expired-recent', { expiresAt: keep });
    insertSession(db, 'expired-old', { expiresAt: drop });

    const window = longestActionWindow();
    expect(window).toBe(Math.max(...Object.values(config.ACTION_LIMITS).map(([, w]) => w)));
    db.prepare('INSERT INTO action_limits (action, at) VALUES (?, ?)').run('email_add', NOW - window + 1);
    db.prepare('INSERT INTO action_limits (action, at) VALUES (?, ?)').run('email_add', NOW - window);

    const token = db.prepare('INSERT INTO tokens (token_hash, purpose, email, expires_at, used_at) VALUES (?, ?, ?, ?, ?)');
    token.run('live', 'password_reset', 'brad@example.com', NOW + 1, null);
    token.run('used', 'password_reset', 'brad@example.com', NOW + 1, NOW - 1);
    token.run('expired', 'password_reset', 'brad@example.com', NOW, null);

    const audit = db.prepare('INSERT INTO audit_log (at, event) VALUES (?, ?)');
    audit.run(NOW - config.AUDIT_RETENTION + 1, 'keep');
    audit.run(NOW - config.AUDIT_RETENTION, 'drop');

    expect(await user.runMaintenance()).toEqual({ sessions: 2, actionLimits: 1, tokens: 2, audit: 1 });
    expect(db.prepare('SELECT id FROM sessions ORDER BY id').all().map((r: any) => r.id))
      .toEqual(['active', 'expired-recent', 'revoked-recent']);
    expect(db.prepare('SELECT token_hash FROM tokens').all().map((r: any) => r.token_hash)).toEqual(['live']);
    expect(db.prepare('SELECT event FROM audit_log').all().map((r: any) => r.event)).toEqual(['keep']);
    expect(db.prepare('SELECT at FROM action_limits').all()).toEqual([{ at: NOW - window + 1 }]);
  });

  it('runs from createSession at most once per PRUNE_INTERVAL', async () => {
    const { user, db, count } = await setup();
    const oldAudit = db.prepare('INSERT INTO audit_log (at, event) VALUES (?, ?)');
    oldAudit.run(0, 'ancient-1');

    await user.createSession({ amr: ['pwd'] });
    expect(db.prepare('SELECT * FROM maintenance').all()).toEqual([{ task: 'prune', last_run_at: NOW }]);
    expect(db.prepare("SELECT * FROM audit_log WHERE event LIKE 'ancient%'").all()).toHaveLength(0);

    oldAudit.run(0, 'ancient-2');
    vi.setSystemTime(NOW + config.PRUNE_INTERVAL - 1);
    await user.createSession({ amr: ['pwd'] });
    expect(await user.runMaintenance(false)).toBeNull();
    expect(db.prepare("SELECT * FROM audit_log WHERE event LIKE 'ancient%'").all()).toHaveLength(1);

    vi.setSystemTime(NOW + config.PRUNE_INTERVAL);
    await user.createSession({ amr: ['pwd'] });
    expect(db.prepare("SELECT * FROM audit_log WHERE event LIKE 'ancient%'").all()).toHaveLength(0);
    expect(db.prepare('SELECT last_run_at FROM maintenance').all()).toEqual([{ last_run_at: NOW + config.PRUNE_INTERVAL }]);
    expect(count('sessions')).toBe(3);
  });
});

describe('UserIndex sweep', () => {
  it('covers every table with an expires_at column', async () => {
    const fake = makeFakeEnv({ User, UserIndex });
    fake.env.USER_INDEX.get(fake.env.USER_INDEX.idFromName('index'));
    const { db } = fake.index.instances.get('index')!.fake;
    const tables = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE '\\_%' ESCAPE '\\'").all()
      .map((r: any) => r.name as string)
      .filter((name: string) => db.prepare(`PRAGMA table_info(${name})`).all().some((col: any) => col.name === 'expires_at'));
    expect(tables.sort()).toEqual(EXPIRING.map((e) => e.table).sort());
  });

  it('deletes expired pending/held rows, signups, challenges and send limits, keeps live ones, reschedules', async () => {
    const fake = makeFakeEnv({ User, UserIndex });
    const index = fake.env.USER_INDEX.get(fake.env.USER_INDEX.idFromName('index')) as unknown as InstanceType<typeof UserIndex>;
    const entry = fake.index.instances.get('index')!.fake;
    const { db } = entry;
    const past = NOW - 1;
    const future = NOW + 1000;
    const handle = db.prepare('INSERT INTO handles (username_norm, user_id, status, expires_at) VALUES (?, ?, ?, ?)');
    handle.run('pending-old', null, 'pending', past);
    handle.run('held-old', 'usr_A', 'held', past);
    handle.run('held-new', 'usr_A', 'held', future);
    handle.run('active', 'usr_A', 'active', null);
    const email = db.prepare('INSERT INTO emails (email_norm, user_id, status, expires_at) VALUES (?, ?, ?, ?)');
    email.run('held-old@x.io', 'usr_A', 'held', past);
    email.run('active@x.io', 'usr_A', 'active', null);
    db.prepare(
      `INSERT INTO pending_signups (signup_id, username, username_norm, email, email_norm, code_hash, expires_at)
       VALUES ('sig_old', 'a', 'a', 'a@x.io', 'a@x.io', 'h', ?)`,
    ).run(past);
    db.prepare("INSERT INTO challenges (challenge, purpose, expires_at) VALUES ('c-old', 'login', ?)").run(past);
    db.prepare("INSERT INTO send_limits (key, at, expires_at) VALUES ('ip:1', 0, ?)").run(past);
    db.prepare("INSERT INTO send_limits (key, at, expires_at) VALUES ('ip:2', 0, ?)").run(future + 5);

    await index.alarm();

    expect(db.prepare('SELECT username_norm FROM handles ORDER BY 1').all().map((r: any) => r.username_norm))
      .toEqual(['active', 'held-new']);
    expect(db.prepare('SELECT email_norm FROM emails').all().map((r: any) => r.email_norm)).toEqual(['active@x.io']);
    expect(db.prepare('SELECT * FROM pending_signups').all()).toHaveLength(0);
    expect(db.prepare('SELECT * FROM challenges').all()).toHaveLength(0);
    expect(db.prepare('SELECT key FROM send_limits').all().map((r: any) => r.key)).toEqual(['ip:2']);
    expect(entry.getAlarm()).toBe(future);
  });
});
