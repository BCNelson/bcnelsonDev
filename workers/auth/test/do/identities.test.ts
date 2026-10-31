import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { config } from '../../src/config';
import { EXPIRING } from '../../src/do/index/maintenance';
import { lastCode, makeFakeEnv, type FakeEnv } from './fake-env';

vi.mock('cloudflare:workers', async () => ({
  DurableObject: (await import('./fake-storage')).FakeDurableObject,
}));

const { User } = await import('../../src/do/user');
const { UserIndex } = await import('../../src/do/user-index');

const START = 1_800_000_000_000;

let fake: FakeEnv;
let index: any;
beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(START);
  fake = makeFakeEnv({ User, UserIndex });
  index = fake.index.get('index');
});
afterEach(() => {
  vi.useRealTimers();
});

async function account(userId: string, username: string, email: string) {
  await fake.users.get(userId).initProfile({ userId, username, email });
  await index.registerAccount({ userId, username, email });
  return fake.users.get(userId);
}

describe('UserIndex identities', () => {
  it('claims once per identity, idempotent for the owner, released only by the owner', async () => {
    expect(await index.findIdentity('github', '1')).toBeNull();
    expect(await index.claimIdentity({ provider: 'github', subject: '1', userId: 'usr_a' })).toEqual({ ok: true });
    expect(await index.claimIdentity({ provider: 'github', subject: '1', userId: 'usr_a' })).toEqual({ ok: true });
    expect(await index.claimIdentity({ provider: 'github', subject: '1', userId: 'usr_b' })).toEqual({ ok: false, reason: 'taken' });
    expect(await index.findIdentity('github', '1')).toBe('usr_a');
    expect(await index.releaseIdentity('github', '1', 'usr_b')).toBe(false);
    expect(await index.listIdentities('usr_a')).toEqual([{ provider: 'github', subject: '1' }]);
    expect(await index.releaseIdentity('github', '1', 'usr_a')).toBe(true);
    expect(await index.findIdentity('github', '1')).toBeNull();
  });

  it('caps identities per account', async () => {
    for (let i = 0; i < config.MAX_OAUTH_IDENTITIES_PER_ACCOUNT; i++) {
      expect((await index.claimIdentity({ provider: 'github', subject: String(i), userId: 'usr_a' })).ok).toBe(true);
    }
    expect(await index.claimIdentity({ provider: 'google', subject: 'x', userId: 'usr_a' })).toEqual({ ok: false, reason: 'too_many' });
  });

  it('emailMatch distinguishes active, held and free addresses', async () => {
    await account('usr_a', 'alice', 'Alice@Example.com');
    expect(await index.emailMatch('alice@example.com')).toEqual({ kind: 'active', userId: 'usr_a' });
    expect(await index.holdEmail('usr_a', 'alice@example.com')).toBe(true);
    expect(await index.emailMatch('alice@example.com')).toEqual({ kind: 'held' });
    expect(await index.emailMatch('nobody@example.com')).toEqual({ kind: 'free' });
  });
});

describe('UserIndex pending social records', () => {
  it('a pending link is consumed only by the user it was offered to, and expires', async () => {
    const { handle } = await index.putOAuthPending({
      kind: 'link', provider: 'github', subject: '7', email: 'a@example.com', emailVerified: true, userId: 'usr_a',
    });
    expect(await index.getOAuthPending(handle, 'signup')).toBeNull();
    expect(await index.consumeOAuthLink(handle, 'usr_b')).toBeNull();
    expect(await index.consumeOAuthLink(handle, 'usr_a')).toMatchObject({ provider: 'github', subject: '7', userId: 'usr_a' });
    expect(await index.consumeOAuthLink(handle, 'usr_a')).toBeNull();

    const second = await index.putOAuthPending({
      kind: 'link', provider: 'github', subject: '8', emailVerified: true, userId: 'usr_a',
    });
    vi.setSystemTime(START + config.OAUTH_LINK_TTL + 1);
    expect(await index.consumeOAuthLink(second.handle, 'usr_a')).toBeNull();
  });

  it('oauth_pending is swept by the alarm (EXPIRING)', async () => {
    expect(EXPIRING.map((e) => e.table)).toContain('oauth_pending');
    await index.putOAuthPending({ kind: 'signup', provider: 'google', subject: 's', emailVerified: false });
    const sql = fake.index.instances.get('index')!.fake.state.storage.sql;
    expect(sql.exec('SELECT COUNT(*) AS n FROM oauth_pending').one().n).toBe(1);
    vi.setSystemTime(START + config.OAUTH_SIGNUP_TTL + 1);
    await index.alarm();
    expect(sql.exec('SELECT COUNT(*) AS n FROM oauth_pending').one().n).toBe(0);
  });
});

describe('social signup in the UserIndex', () => {
  it('verified email: no code, handle + email + identity claimed together', async () => {
    const { handle } = await index.putOAuthPending({
      kind: 'signup', provider: 'github', subject: '42', email: 'New@Example.com', emailVerified: true,
      data: { name: 'New Person', username: 'newbie' },
    });
    expect(await index.startOAuthSignup(handle, { username: 'Newbie' })).toEqual({ ok: true, verified: true });
    expect(fake.mail).toHaveLength(0);
    const pending = await index.getOAuthPending(handle, 'signup');
    expect(pending).toMatchObject({ signupVerified: true, username: 'Newbie', data: { name: 'New Person' } });

    // Choosing again releases the first reservation.
    expect(await index.startOAuthSignup(handle, { username: 'other' })).toEqual({ ok: true, verified: true });
    expect(await index.isUsernameAvailable('newbie')).toBe(true);

    const created = await index.completeOAuthSignup(handle);
    expect(created).toMatchObject({ ok: true, username: 'other', email: 'new@example.com', provider: 'github', subject: '42' });
    expect(await index.findIdentity('github', '42')).toBe(created.userId);
    expect(await index.resolve('other')).toBe(created.userId);
    expect(await index.resolve('new@example.com')).toBe(created.userId);
    expect(await index.getOAuthPending(handle, 'signup')).toBeNull();
  });

  it('unverified email: the normal code flow, then completion', async () => {
    const { handle } = await index.putOAuthPending({
      kind: 'signup', provider: 'github', subject: '43', email: 'maybe@example.com', emailVerified: false,
    });
    expect(await index.completeOAuthSignup(handle)).toEqual({ ok: false, reason: 'not_verified' });
    expect(await index.startOAuthSignup(handle, { username: 'maybe', email: 'typed@example.com' })).toEqual({ ok: true, verified: false });
    expect(fake.mail.at(-1)?.to).toBe('typed@example.com');
    expect(await index.verifyOAuthSignup(handle, '000000')).toMatchObject({ ok: false });
    expect(await index.verifyOAuthSignup(handle, lastCode(fake.mail))).toEqual({ ok: true });
    const created = await index.completeOAuthSignup(handle);
    expect(created).toMatchObject({ ok: true, email: 'typed@example.com', providerEmail: 'maybe@example.com' });
    expect(await index.findIdentity('github', '43')).toBe(created.userId);
  });

  it('an identity taken meanwhile fails the whole signup (nothing claimed)', async () => {
    const { handle } = await index.putOAuthPending({
      kind: 'signup', provider: 'google', subject: 'g1', email: 'x@example.com', emailVerified: true,
    });
    await index.startOAuthSignup(handle, { username: 'xavier' });
    await index.claimIdentity({ provider: 'google', subject: 'g1', userId: 'usr_someone' });
    expect(await index.completeOAuthSignup(handle)).toEqual({ ok: false, reason: 'conflict' });
    expect(await index.resolve('xavier')).toBeNull();
    expect(await index.resolve('x@example.com')).toBeNull();
  });

  it('a taken username or registered email is refused for a verified signup', async () => {
    await account('usr_a', 'alice', 'alice@example.com');
    const { handle } = await index.putOAuthPending({
      kind: 'signup', provider: 'github', subject: '9', email: 'alice@example.com', emailVerified: true,
    });
    expect(await index.startOAuthSignup(handle, { username: 'alice' })).toMatchObject({ ok: false, reason: 'username_taken' });
    expect(await index.startOAuthSignup(handle, { username: 'alice2' })).toMatchObject({ ok: false, reason: 'email_taken' });
    expect(await index.startOAuthSignup('bogus', { username: 'alice3' })).toMatchObject({ ok: false, reason: 'not_found' });
  });
});

describe('User oauth credentials', () => {
  it('add, list, refuse duplicates, unlink with the last-method guard', async () => {
    const user = await account('usr_a', 'alice', 'alice@example.com');
    const added = await user.addOAuthCredential({ provider: 'github', subject: '1', email: 'a@gh.example', label: 'GitHub (alice)' });
    expect(added).toMatchObject({ ok: true, credential: { provider: 'github', subject: '1', label: 'GitHub (alice)' } });
    expect(await user.addOAuthCredential({ provider: 'github', subject: '1' })).toEqual({ ok: false, reason: 'duplicate' });
    expect(await user.listOAuthCredentials()).toHaveLength(1);

    expect(await user.unlinkOAuth(added.credential.id)).toEqual({ ok: false, reason: 'last_method' });
    expect(await user.unlinkOAuth('cred_nope')).toEqual({ ok: false, reason: 'not_found' });
    await user.setPassword('v2$pw');
    expect(await user.unlinkOAuth(added.credential.id)).toEqual({ ok: true, provider: 'github', subject: '1' });
    expect(await user.listOAuthCredentials()).toEqual([]);
  });

  it('loginWithOAuth needs the credential, records use, and respects disabled accounts', async () => {
    const user = await account('usr_a', 'alice', 'alice@example.com');
    expect(await user.loginWithOAuth('github', '1')).toEqual({ ok: false, reason: 'invalid' });
    await user.addOAuthCredential({ provider: 'github', subject: '1' });
    const ok = await user.loginWithOAuth('github', '1', { ip: '1.2.3.4' });
    expect(ok.ok).toBe(true);
    expect(ok.session.claims.amr).toEqual(['oauth:github']);
    expect((await user.listOAuthCredentials())[0].lastUsedAt).toBe(START);

    await user.setDisabled(true, 'usr_admin');
    expect(await user.loginWithOAuth('github', '1')).toEqual({ ok: false, reason: 'disabled' });
  });
});
