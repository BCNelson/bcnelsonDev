import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { DirectorySummary } from '../../src/do/index/directory';
import { makeFakeEnv } from './fake-env';

vi.mock('cloudflare:workers', async () => ({
  DurableObject: (await import('./fake-storage')).FakeDurableObject,
}));
vi.mock('../../src/crypto/password', async () => (await import('./fake-env')).fakePasswordModule());

const { User } = await import('../../src/do/user');
const { UserIndex } = await import('../../src/do/user-index');

type IndexDO = InstanceType<typeof UserIndex>;

let fake: ReturnType<typeof makeFakeEnv>;
let index: IndexDO;

function summary(n: number, extra: Partial<DirectorySummary> = {}): DirectorySummary {
  const id = `usr_${String(n).padStart(3, '0')}`;
  return {
    userId: id, username: `User${n}`, primaryEmail: `u${n}@example.com`,
    roles: [], createdAt: 1000 + n, disabledAt: null, ...extra,
  };
}

beforeEach(() => {
  fake = makeFakeEnv({ User, UserIndex });
  index = fake.env.USER_INDEX.get(fake.env.USER_INDEX.idFromName('index')) as unknown as IndexDO;
});

describe('UserIndex directory', () => {
  it('upserts and reads entries, normalizing the email and dropping unknown roles', async () => {
    await index.upsertDirectoryEntry(summary(1, { primaryEmail: 'U1@Example.COM', roles: ['admin', 'root'] }));
    expect(await index.getDirectoryEntry('usr_001')).toMatchObject({
      userId: 'usr_001', username: 'User1', primaryEmail: 'u1@example.com', roles: ['admin'], createdAt: 1001,
      disabledAt: null, updatedAt: expect.any(Number),
    });
    await index.upsertDirectoryEntry(summary(1, { username: 'Renamed', roles: [] }));
    expect(await index.getDirectoryEntry('usr_001')).toMatchObject({ username: 'Renamed', roles: [] });
    expect(await index.getDirectoryEntry('usr_999')).toBeNull();
  });

  it('paginates by user_id with a cursor', async () => {
    for (const n of [3, 1, 5, 2, 4]) await index.upsertDirectoryEntry(summary(n));
    const first = await index.listDirectory({ limit: 2 });
    expect(first.users.map((u) => u.userId)).toEqual(['usr_001', 'usr_002']);
    expect(first.nextCursor).toBe('usr_002');
    const second = await index.listDirectory({ limit: 2, cursor: first.nextCursor });
    expect(second.users.map((u) => u.userId)).toEqual(['usr_003', 'usr_004']);
    const last = await index.listDirectory({ limit: 2, cursor: second.nextCursor });
    expect(last.users.map((u) => u.userId)).toEqual(['usr_005']);
    expect(last.nextCursor).toBeNull();
  });

  it('clamps the page size', async () => {
    for (let n = 1; n <= 3; n++) await index.upsertDirectoryEntry(summary(n));
    expect((await index.listDirectory({ limit: 0 })).users).toHaveLength(3);
    expect((await index.listDirectory({ limit: -5 })).users).toHaveLength(1);
  });

  it('searches by username or email prefix, case-insensitively, with LIKE escaped', async () => {
    await index.upsertDirectoryEntry(summary(1, { username: 'Brad', primaryEmail: 'b@example.com' }));
    await index.upsertDirectoryEntry(summary(2, { username: 'brandon', primaryEmail: 'x@other.org' }));
    await index.upsertDirectoryEntry(summary(3, { username: 'carol', primaryEmail: 'brad.alt@example.com' }));
    await index.upsertDirectoryEntry(summary(4, { username: 'dave_1', primaryEmail: 'd@example.com' }));
    const names = async (q: string) => (await index.listDirectory({ q })).users.map((u) => u.username);
    expect(await names('BRA')).toEqual(['Brad', 'brandon', 'carol']);
    expect(await names('brad')).toEqual(['Brad', 'carol']);
    expect(await names('x@')).toEqual(['brandon']);
    expect(await names('%')).toEqual([]);
    expect(await names('dave_')).toEqual(['dave_1']);
    expect(await names('d_ve')).toEqual([]);
    const page = await index.listDirectory({ q: 'bra', limit: 1 });
    expect(page.nextCursor).toBe('usr_001');
    expect((await index.listDirectory({ q: 'bra', limit: 5, cursor: page.nextCursor })).users.map((u) => u.username))
      .toEqual(['brandon', 'carol']);
  });

  it('counts active admins, optionally excluding one', async () => {
    await index.upsertDirectoryEntry(summary(1, { roles: ['admin'] }));
    await index.upsertDirectoryEntry(summary(2, { roles: ['admin', 'beta'] }));
    await index.upsertDirectoryEntry(summary(3, { roles: ['admin'], disabledAt: 5 }));
    await index.upsertDirectoryEntry(summary(4, { roles: ['beta'] }));
    expect(await index.countActiveAdmins()).toBe(2);
    expect(await index.countActiveAdmins('usr_001')).toBe(1);
    expect(await index.countActiveAdmins('usr_003')).toBe(2);
  });

  it('finds active accounts missing from the directory (backfill) and knows real accounts', async () => {
    await index.registerAccount({ userId: 'usr_A', username: 'alice', email: 'a@example.com' });
    await index.registerAccount({ userId: 'usr_B', username: 'bob', email: 'b@example.com' });
    await index.upsertDirectoryEntry(summary(1, { userId: 'usr_B', username: 'bob' }));
    expect(await index.missingDirectoryEntries(10)).toEqual({ userIds: ['usr_A'], remaining: 0 });
    expect(await index.isKnownUser('usr_A')).toBe(true);
    expect(await index.isKnownUser('usr_B')).toBe(true);
    expect(await index.isKnownUser('usr_Z')).toBe(false);

    // The User side fills it in.
    const user = fake.env.USER.get(fake.env.USER.idFromName('usr_A')) as any;
    await user.initProfile({ userId: 'usr_A', username: 'alice', email: 'a@example.com' });
    expect(await user.syncDirectory()).toBe(true);
    expect(await index.missingDirectoryEntries(10)).toEqual({ userIds: [], remaining: 0 });
    expect(await index.getDirectoryEntry('usr_A')).toMatchObject({ username: 'alice', primaryEmail: 'a@example.com' });
  });
});
