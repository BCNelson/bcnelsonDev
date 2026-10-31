import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { PasswordLoginContext } from '../../src/types';
import { makeFakeEnv } from './fake-env';

vi.mock('cloudflare:workers', async () => ({
  DurableObject: (await import('./fake-storage')).FakeDurableObject,
}));
vi.mock('../../src/crypto/password', async () => (await import('./fake-env')).fakePasswordModule());

const { User } = await import('../../src/do/user');
const { UserIndex } = await import('../../src/do/user-index');
const { normalizeRoles, isAccountDisabledError } = await import('../../src/do/user/admin');

type UserDO = InstanceType<typeof User>;
type IndexDO = InstanceType<typeof UserIndex>;

const NOW = 1_800_000_000_000;
const LOGIN: PasswordLoginContext = { amr: ['pwd'], ip: '1.2.3.4', userAgent: 'test', turnstileOk: true };

let fake: ReturnType<typeof makeFakeEnv>;
let index: IndexDO;

async function makeUser(userId: string, username: string, roles: string[] = []): Promise<UserDO> {
  const user = fake.env.USER.get(fake.env.USER.idFromName(userId)) as unknown as UserDO;
  await user.initProfile({ userId, username, email: `${username.toLowerCase()}@example.com` });
  await user.setPassword('v2$correct-horse');
  for (const role of roles) await user.ensureRole(role, 'test');
  await user.syncDirectory();
  return user;
}

function audit(userId: string): { event: string; detail: any }[] {
  const { db } = fake.users.instances.get(userId)!.fake;
  return db.prepare('SELECT event, detail FROM audit_log ORDER BY rowid').all()
    .map((r: any) => ({ event: r.event, detail: r.detail ? JSON.parse(r.detail) : null }));
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(NOW);
  fake = makeFakeEnv({ User, UserIndex });
  index = fake.env.USER_INDEX.get(fake.env.USER_INDEX.idFromName('index')) as unknown as IndexDO;
});
afterEach(() => {
  vi.useRealTimers();
});

describe('normalizeRoles', () => {
  it('accepts config.ROLES values, dedupes, orders by config', () => {
    expect(normalizeRoles(['beta', 'admin', 'beta'])).toEqual(['admin', 'beta']);
    expect(normalizeRoles([])).toEqual([]);
  });
  it('rejects unknown roles and non-arrays', () => {
    expect(normalizeRoles(['root'])).toBeNull();
    expect(normalizeRoles(['admin', 1])).toBeNull();
    expect(normalizeRoles('admin')).toBeNull();
    expect(normalizeRoles(null)).toBeNull();
  });
});

describe('User roles', () => {
  it('setRoles validates, stores, audits with the actor and syncs the directory', async () => {
    const user = await makeUser('usr_B', 'Bob');
    expect(await user.setRoles(['root'], 'usr_ADMIN')).toEqual({ ok: false, reason: 'invalid_role' });
    expect(await user.getRoles()).toEqual([]);

    expect(await user.setRoles(['beta'], 'usr_ADMIN')).toEqual({ ok: true, roles: ['beta'], changed: true });
    expect(await user.getRoles()).toEqual(['beta']);
    expect(audit('usr_B').at(-1)).toEqual({
      event: 'role.set', detail: { roles: ['beta'], previous: [], actor: 'usr_ADMIN' },
    });
    expect((await index.getDirectoryEntry('usr_B'))?.roles).toEqual(['beta']);

    expect(await user.setRoles(['beta'], 'usr_ADMIN')).toEqual({ ok: true, roles: ['beta'], changed: false });
  });

  it('new roles appear in claims (next refresh)', async () => {
    const user = await makeUser('usr_B', 'Bob');
    const session = await user.createSession({ amr: ['pwd'] });
    expect(session.claims.roles).toBeUndefined();
    await user.setRoles(['admin', 'beta'], 'usr_ADMIN');
    const refreshed = await user.refreshSession(session.sessionId, session.secret);
    expect(refreshed.ok && refreshed.claims.roles).toEqual(['admin', 'beta']);
  });

  it('ensureRole (ADMIN_EMAILS bootstrap) syncs the directory', async () => {
    const user = await makeUser('usr_A', 'Alice');
    expect((await index.getDirectoryEntry('usr_A'))?.roles).toEqual([]);
    expect(await user.ensureRole('admin', 'admin_emails')).toBe(true);
    expect((await index.getDirectoryEntry('usr_A'))?.roles).toEqual(['admin']);
    expect(await index.countActiveAdmins()).toBe(1);
  });

  it('refuses to remove admin from the last active admin', async () => {
    const alice = await makeUser('usr_A', 'Alice', ['admin']);
    expect(await alice.setRoles([], 'usr_A')).toEqual({ ok: false, reason: 'last_admin' });
    expect(await alice.getRoles()).toEqual(['admin']);
    // Changing other roles is fine.
    expect(await alice.setRoles(['admin', 'beta'], 'usr_A')).toMatchObject({ ok: true });

    const bob = await makeUser('usr_B', 'Bob', ['admin']);
    expect(await alice.setRoles([], 'usr_A')).toMatchObject({ ok: true, roles: [] });
    expect(await bob.setRoles([], 'usr_B')).toEqual({ ok: false, reason: 'last_admin' });
  });

  it('a disabled admin does not count towards the guard', async () => {
    const alice = await makeUser('usr_A', 'Alice', ['admin']);
    const bob = await makeUser('usr_B', 'Bob', ['admin']);
    expect(await bob.setDisabled(true, 'usr_A')).toMatchObject({ ok: true });
    expect(await index.countActiveAdmins()).toBe(1);
    expect(await alice.setRoles([], 'usr_A')).toEqual({ ok: false, reason: 'last_admin' });
    // Removing admin from the disabled one is allowed.
    expect(await bob.setRoles([], 'usr_A')).toMatchObject({ ok: true });
  });
});

describe('User disable', () => {
  it('blocks password login, refresh and claims, and revokes every session', async () => {
    const user = await makeUser('usr_B', 'Bob');
    const login = await user.loginWithPassword('correct-horse', LOGIN);
    if (!login.ok) throw new Error('login failed');
    const { sessionId, secret } = login.session;

    const result = await user.setDisabled(true, 'usr_ADMIN');
    expect(result).toEqual({ ok: true, disabledAt: NOW, revokedSessions: 1 });
    expect(await user.listSessions()).toEqual([]);
    expect(audit('usr_B').at(-1)).toEqual({ event: 'account.disabled', detail: { actor: 'usr_ADMIN', revokedSessions: 1 } });
    expect((await index.getDirectoryEntry('usr_B'))?.disabledAt).toBe(NOW);

    expect(await user.refreshSession(sessionId, secret)).toEqual({ ok: false, reason: 'revoked' });
    expect(await user.getClaims(sessionId)).toBeNull();
    expect(await user.loginWithPassword('correct-horse', LOGIN)).toEqual({ ok: false, reason: 'disabled' });
    // A wrong password still looks like a wrong password.
    expect(await user.loginWithPassword('nope-nope-nope', LOGIN)).toEqual({ ok: false, reason: 'invalid' });
    const err = await user.createSession({ amr: ['hwk'] }).catch((e: unknown) => e);
    expect(isAccountDisabledError(err)).toBe(true);
    expect(audit('usr_B').map((a) => a.event)).toContain('login.blocked_disabled');

    expect(await user.setDisabled(false, 'usr_ADMIN')).toEqual({ ok: true, disabledAt: null, revokedSessions: 0 });
    expect(audit('usr_B').at(-1)).toEqual({ event: 'account.enabled', detail: { actor: 'usr_ADMIN' } });
    expect((await user.loginWithPassword('correct-horse', LOGIN)).ok).toBe(true);
    expect((await index.getDirectoryEntry('usr_B'))?.disabledAt).toBeNull();
  });

  it('refreshSession reports revoked for a disabled account even with a live session row', async () => {
    const user = await makeUser('usr_B', 'Bob');
    const session = await user.createSession({ amr: ['pwd'] });
    const { db } = fake.users.instances.get('usr_B')!.fake;
    db.prepare('UPDATE profile SET disabled_at = ?').run(NOW);
    expect(await user.refreshSession(session.sessionId, session.secret)).toEqual({ ok: false, reason: 'revoked' });
  });

  it('refuses self-disable and disabling the last admin', async () => {
    const alice = await makeUser('usr_A', 'Alice', ['admin']);
    expect(await alice.setDisabled(true, 'usr_A')).toEqual({ ok: false, reason: 'self' });
    expect(await alice.setDisabled(true, 'usr_OTHER')).toEqual({ ok: false, reason: 'last_admin' });
  });
});

describe('admin actions', () => {
  it('revokeSessionsByAdmin revokes all and audits the actor', async () => {
    const user = await makeUser('usr_B', 'Bob');
    await user.createSession({ amr: ['pwd'] });
    await user.createSession({ amr: ['pwd'] });
    expect(await user.revokeSessionsByAdmin('usr_ADMIN')).toBe(2);
    expect(await user.listSessions()).toEqual([]);
    expect(audit('usr_B').at(-1)).toEqual({ event: 'admin.sessions_revoked', detail: { actor: 'usr_ADMIN', count: 2 } });
  });

  it('getAdminDetail returns profile, sessions, credentials and recent audit (newest first)', async () => {
    const user = await makeUser('usr_B', 'Bob', ['beta']);
    await user.createSession({ amr: ['pwd'], ip: '9.9.9.9' });
    const detail = await user.getAdminDetail();
    expect(detail).toMatchObject({
      userId: 'usr_B', username: 'Bob', primaryEmail: 'bob@example.com', emails: ['bob@example.com'],
      roles: ['beta'], createdAt: NOW, disabledAt: null,
      credentials: [{ type: 'password' }],
    });
    expect(detail!.sessions).toHaveLength(1);
    expect(detail!.audit[0]!.event).toBe('session.created');
    expect(detail!.audit.at(-1)!.event).toBe('profile.created');
  });

  it('getAdminDetail / syncDirectory without a profile', async () => {
    const empty = fake.env.USER.get(fake.env.USER.idFromName('usr_NONE')) as unknown as UserDO;
    expect(await empty.getAdminDetail()).toBeNull();
    expect(await empty.syncDirectory()).toBe(false);
    expect(await empty.setRoles(['beta'], 'usr_A')).toEqual({ ok: false, reason: 'not_found' });
  });
});
