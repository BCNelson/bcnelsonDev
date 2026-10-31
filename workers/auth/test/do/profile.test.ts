import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { config } from '../../src/config';
import { newId } from '../../src/crypto/ids';
import { makeFakeEnv, type FakeEnv } from './fake-env';

vi.mock('cloudflare:workers', async () => ({
  DurableObject: (await import('./fake-storage')).FakeDurableObject,
}));
vi.mock('../../src/crypto/password', async () => (await import('./fake-env')).fakePasswordModule());

const { User } = await import('../../src/do/user');
const { UserIndex } = await import('../../src/do/user-index');

type UserDO = InstanceType<typeof User>;
type IndexDO = InstanceType<typeof UserIndex>;

const NOW = 1_800_000_000_000;
const DAY = 86_400_000;

let fake: FakeEnv;
let index: IndexDO;

async function account(username = 'Brad', email = 'brad@example.com') {
  const userId = newId('usr');
  await index.registerAccount({ userId, username, email });
  const user = fake.env.USER.get(fake.env.USER.idFromName(userId)) as unknown as UserDO;
  await user.initProfile({ userId, username, email });
  const db = fake.users.instances.get(userId)!.fake.db;
  return { userId, user, db };
}

function indexDb() {
  return fake.index.instances.get('index')!.fake.db;
}

function handle(norm: string) {
  return indexDb().prepare('SELECT * FROM handles WHERE username_norm = ?').all(norm)[0];
}

function auditEvents(db: Awaited<ReturnType<typeof account>>['db']): string[] {
  return db.prepare('SELECT event FROM audit_log ORDER BY rowid').all().map((r) => String(r.event));
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

describe('User.updateProfile', () => {
  it('sets, keeps and clears name/picture; claims follow', async () => {
    const { user, db } = await account();
    let res = await user.updateProfile({ name: '  Bradley  ', picture: 'https://img.example/a.png' });
    expect(res).toMatchObject({ ok: true, changed: true, profile: { name: 'Bradley', picture: 'https://img.example/a.png' } });
    const { sessionId } = await user.createSession({ amr: ['pwd'] });
    expect(await user.getClaims(sessionId)).toMatchObject({ name: 'Bradley', picture: 'https://img.example/a.png' });

    res = await user.updateProfile({ picture: '' });
    expect(res).toMatchObject({ ok: true, profile: { name: 'Bradley', picture: null } });
    res = await user.updateProfile({ name: 'Bradley' });
    expect(res).toMatchObject({ ok: true, changed: false });
    res = await user.updateProfile({ name: null });
    expect(res).toMatchObject({ ok: true, profile: { name: null } });
    expect((await user.getClaims(sessionId))!.name).toBeUndefined();
    expect(auditEvents(db).filter((e) => e === 'profile.updated')).toHaveLength(3);
  });

  it('validates name length/characters and picture URLs', async () => {
    const { user } = await account();
    expect(await user.updateProfile({ name: 'x'.repeat(config.PROFILE_NAME_MAX_LENGTH) })).toMatchObject({ ok: true });
    expect(await user.updateProfile({ name: 'x'.repeat(config.PROFILE_NAME_MAX_LENGTH + 1) }))
      .toEqual({ ok: false, reason: 'invalid_name' });
    expect(await user.updateProfile({ name: 'a\u0000b' })).toEqual({ ok: false, reason: 'invalid_name' });
    for (const picture of [
      'http://img.example/a.png',
      'javascript:alert(1)',
      'https://user:pw@img.example/a.png',
      'not a url',
      `https://img.example/${'a'.repeat(config.PICTURE_URL_MAX_LENGTH)}`,
    ]) {
      expect(await user.updateProfile({ picture })).toEqual({ ok: false, reason: 'invalid_picture' });
    }
    // An invalid field changes nothing.
    expect(await user.updateProfile({ name: 'ok', picture: 'http://x.example' })).toMatchObject({ ok: false });
    expect((await user.getAccount()).profile.name).toBe('x'.repeat(config.PROFILE_NAME_MAX_LENGTH));
  });
});

describe('User.changeUsername', () => {
  it('activates the new handle, holds the old one, and starts the cooldown', async () => {
    const { userId, user, db } = await account();
    const res = await user.changeUsername('Bradley');
    expect(res).toEqual({ ok: true, username: 'Bradley', changed: true });
    expect(await index.resolve('bradley')).toBe(userId);
    expect(await index.resolve('brad')).toBeNull();
    expect(handle('bradley')).toMatchObject({ user_id: userId, status: 'active', expires_at: null });
    expect(handle('brad')).toMatchObject({ user_id: userId, status: 'held', expires_at: NOW + config.USERNAME_HOLD });
    expect(fake.index.instances.get('index')!.fake.getAlarm()).toBe(NOW + config.USERNAME_HOLD);
    expect(await index.isUsernameAvailable('brad')).toBe(false);

    const accountInfo = await user.getAccount();
    expect(accountInfo.profile).toMatchObject({
      username: 'Bradley',
      usernameChangedAt: NOW,
      usernameChangeAvailableAt: NOW + config.USERNAME_CHANGE_COOLDOWN,
    });
    const { sessionId } = await user.createSession({ amr: ['pwd'] });
    expect((await user.getClaims(sessionId))!.preferred_username).toBe('Bradley');
    expect(auditEvents(db)).toContain('username.changed');

    // Someone else can't take the held name.
    const other = await account('other', 'other@example.com');
    expect(await other.user.changeUsername('brad')).toEqual({ ok: false, reason: 'username_taken' });
  });

  it('enforces USERNAME_CHANGE_COOLDOWN', async () => {
    const { user } = await account();
    await user.changeUsername('second');
    vi.setSystemTime(NOW + DAY);
    const res = await user.changeUsername('third');
    expect(res).toEqual({ ok: false, reason: 'cooldown', retryAfterMs: config.USERNAME_CHANGE_COOLDOWN - DAY });
    vi.setSystemTime(NOW + config.USERNAME_CHANGE_COOLDOWN);
    expect(await user.changeUsername('third')).toMatchObject({ ok: true, username: 'third' });
  });

  it("a refused rename doesn't consume the cooldown", async () => {
    const { user } = await account();
    await account('taken', 'taken@example.com');
    expect(await user.changeUsername('TAKEN')).toEqual({ ok: false, reason: 'username_taken' });
    expect((await user.getAccount()).profile.usernameChangedAt).toBeNull();
    // A pending signup's reservation is taken too.
    await index.startSignup({ username: 'pending1', email: 'p@example.com' });
    expect(await user.changeUsername('pending1')).toEqual({ ok: false, reason: 'username_taken' });
    expect(await user.changeUsername('free-name')).toMatchObject({ ok: true });
  });

  it('case-only changes skip the index and the cooldown', async () => {
    const { userId, user } = await account();
    expect(await user.changeUsername('BRAD')).toEqual({ ok: true, username: 'BRAD', changed: true });
    expect(await user.changeUsername('BRAD')).toEqual({ ok: true, username: 'BRAD', changed: false });
    expect((await user.getAccount()).profile.usernameChangedAt).toBeNull();
    expect(handle('brad')).toMatchObject({ user_id: userId, status: 'active' });
  });

  it('rejects invalid and reserved names', async () => {
    const { user } = await account();
    expect(await user.changeUsername('ab')).toMatchObject({ ok: false, reason: 'invalid_username', detail: 'invalid_format' });
    expect(await user.changeUsername('admin')).toMatchObject({ ok: false, reason: 'invalid_username', detail: 'reserved' });
  });

  it('the owner can take back their own held handle', async () => {
    const { userId } = await account();
    expect(await index.renameHandle({ userId, from: 'brad', to: 'other' })).toMatchObject({ ok: true });
    expect(await index.renameHandle({ userId, from: 'other', to: 'Brad' })).toMatchObject({ ok: true, username: 'Brad' });
    expect(handle('brad')).toMatchObject({ status: 'active', user_id: userId });
    expect(handle('other')).toMatchObject({ status: 'held', user_id: userId });
    // Only from the user's own active handle.
    expect(await index.renameHandle({ userId: 'usr_SOMEONE', from: 'brad', to: 'x-y-z' }))
      .toEqual({ ok: false, reason: 'not_owner' });
  });

  it('held handles are swept after USERNAME_HOLD', async () => {
    const { user } = await account();
    await user.changeUsername('newname');
    vi.setSystemTime(NOW + config.USERNAME_HOLD);
    await index.alarm();
    expect(handle('brad')).toBeUndefined();
    expect(await index.isUsernameAvailable('brad')).toBe(true);
  });
});

describe('User.changePassword', () => {
  it('requires the current password when one is set, revokes other sessions, alerts every address', async () => {
    const { user, db } = await account();
    await user.setPassword('v2$old-password');
    // Second verified address, added directly.
    db.prepare('INSERT INTO emails (email, verified_at, is_primary) VALUES (?, ?, 0)').run('b2@example.com', NOW);
    const keep = await user.createSession({ amr: ['pwd'] });
    const other = await user.createSession({ amr: ['pwd'] });

    expect(await user.changePassword({ hash: 'v2$new-password', keepSessionId: keep.sessionId }))
      .toEqual({ ok: false, reason: 'current_password_required' });
    expect(await user.changePassword({ currentPassword: 'wrong', hash: 'v2$new-password', keepSessionId: keep.sessionId }))
      .toEqual({ ok: false, reason: 'invalid_password' });
    expect(fake.mail).toHaveLength(0);

    const res = await user.changePassword({ currentPassword: 'old-password', hash: 'v2$new-password', keepSessionId: keep.sessionId });
    expect(res).toEqual({ ok: true, revokedSessions: 1 });
    expect(await user.getClaims(keep.sessionId)).not.toBeNull();
    expect(await user.getClaims(other.sessionId)).toBeNull();
    expect(fake.mail.map((m) => m.to).sort()).toEqual(['b2@example.com', 'brad@example.com']);
    expect(fake.mail.every((m) => /password was changed/.test(m.subject))).toBe(true);
    const login = await user.loginWithPassword('new-password', { amr: ['pwd'], turnstileOk: false });
    expect(login.ok).toBe(true);
    expect(auditEvents(db)).toEqual(expect.arrayContaining(['password.change_failed', 'password.changed', 'alert.password_changed']));
  });

  it('a passkey-only account can set a first password without one', async () => {
    const { user } = await account();
    expect(await user.changePassword({ hash: 'v2$first-password' })).toEqual({ ok: true, revokedSessions: 0 });
    expect((await user.getAccount()).hasPassword).toBe(true);
  });
});

describe('User.getAccount / listCredentials', () => {
  it('returns profile, emails, sessions and credential summaries without secrets', async () => {
    const { userId, user, db } = await account();
    await user.setPassword('v2$secret-password');
    db.prepare("INSERT INTO credentials (id, type, label, data, created_at) VALUES ('cred_X', 'passkey', 'Laptop', '{\"publicKey\":\"PK\"}', ?)").run(NOW);
    const { sessionId } = await user.createSession({ amr: ['pwd'], userAgent: 'UA', ip: '1.2.3.4' });
    const info = await user.getAccount();
    expect(info.profile).toMatchObject({ userId, username: 'Brad', roles: [], usernameChangeAvailableAt: null });
    expect(info.emails).toEqual([{ email: 'brad@example.com', verifiedAt: NOW, primary: true }]);
    expect(info.pendingEmails).toEqual([]);
    expect(info.sessions).toEqual([expect.objectContaining({ id: sessionId, userAgent: 'UA', ip: '1.2.3.4' })]);
    expect(info.hasPassword).toBe(true);
    expect(info.credentials.map((c) => c.type).sort()).toEqual(['passkey', 'password']);
    const json = JSON.stringify(await user.listCredentials());
    expect(json).not.toContain('secret-password');
    expect(json).not.toContain('PK');
    expect(await user.listCredentials()).toContainEqual({ id: 'cred_X', type: 'passkey', label: 'Laptop', createdAt: NOW, lastUsedAt: null });
  });
});
