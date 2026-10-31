import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { config } from '../../src/config';
import { sha256Base64url } from '../../src/crypto/hash';
import { newId } from '../../src/crypto/ids';
import { lastCode, makeFakeEnv, type FakeEnv } from './fake-env';

vi.mock('cloudflare:workers', async () => ({
  DurableObject: (await import('./fake-storage')).FakeDurableObject,
}));
vi.mock('../../src/crypto/password', async () => (await import('./fake-env')).fakePasswordModule());

const { User } = await import('../../src/do/user');
const { UserIndex } = await import('../../src/do/user-index');

type UserDO = InstanceType<typeof User>;
type IndexDO = InstanceType<typeof UserIndex>;

const NOW = 1_800_000_000_000;

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

function indexRow(email: string) {
  return fake.index.instances.get('index')!.fake.db.prepare('SELECT * FROM emails WHERE email_norm = ?').all(email)[0];
}

/** Add + verify in one go. */
async function addVerified(user: UserDO, email: string) {
  const start = await user.startAddEmail(email);
  expect(start).toMatchObject({ ok: true });
  return user.verifyAddEmail(email, lastCode(fake.mail));
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

describe('adding an email', () => {
  it('pending code (hashed) → verify → claimed in the index, alerts primary + new address', async () => {
    const { userId, user, db } = await account();
    const start = await user.startAddEmail(' New@Example.com ');
    expect(start).toEqual({ ok: true, email: 'new@example.com', expiresAt: NOW + config.CODE_TTL });
    expect(fake.mail).toHaveLength(1);
    expect(fake.mail[0]).toMatchObject({ to: 'new@example.com', subject: expect.stringMatching(/Confirm your new/) });
    const code = lastCode(fake.mail);
    const pending = db.prepare('SELECT * FROM pending_emails').all()[0]!;
    expect(pending).toMatchObject({ email: 'new@example.com', attempts: 0, expires_at: NOW + config.CODE_TTL });
    expect(pending.code_hash).toBe(await sha256Base64url(code));
    expect((await user.getAccount()).pendingEmails).toEqual([{ email: 'new@example.com', expiresAt: NOW + config.CODE_TTL }]);
    expect(await index.resolve('new@example.com')).toBeNull();

    fake.mail.length = 0;
    expect(await user.verifyAddEmail('new@example.com', code)).toEqual({ ok: true, email: 'new@example.com' });
    expect(await index.resolve('new@example.com')).toBe(userId);
    const info = await user.getAccount();
    expect(info.emails.map((e) => [e.email, e.primary])).toEqual([['brad@example.com', true], ['new@example.com', false]]);
    expect(info.pendingEmails).toEqual([]);
    expect(fake.mail.map((m) => m.to).sort()).toEqual(['brad@example.com', 'new@example.com']);
    expect(fake.mail.every((m) => /was added/.test(m.subject))).toBe(true);
    const events = db.prepare('SELECT event FROM audit_log').all().map((r) => r.event);
    expect(events).toEqual(expect.arrayContaining(['email.add_started', 'email.added', 'alert.email_added']));
  });

  it('rejects invalid and already-added addresses', async () => {
    const { user } = await account();
    expect(await user.startAddEmail('nope')).toEqual({ ok: false, reason: 'invalid_email' });
    expect(await user.startAddEmail('BRAD@example.com')).toEqual({ ok: false, reason: 'already_added' });
    expect(fake.mail).toHaveLength(0);
  });

  it('counts wrong codes; CODE_MAX_ATTEMPTS and CODE_TTL end the code', async () => {
    const { user } = await account();
    await user.startAddEmail('a@example.com');
    const code = lastCode(fake.mail);
    const wrong = code === '000000' ? '111111' : '000000';
    for (let i = 1; i < config.CODE_MAX_ATTEMPTS; i++) {
      expect(await user.verifyAddEmail('a@example.com', wrong)).toEqual({ ok: false, reason: 'invalid' });
    }
    expect(await user.verifyAddEmail('a@example.com', wrong)).toEqual({ ok: false, reason: 'too_many_attempts' });
    expect(await user.verifyAddEmail('a@example.com', code)).toEqual({ ok: false, reason: 'too_many_attempts' });

    await user.startAddEmail('a@example.com'); // resend resets
    vi.setSystemTime(NOW + config.CODE_TTL);
    expect(await user.verifyAddEmail('a@example.com', lastCode(fake.mail))).toEqual({ ok: false, reason: 'expired' });
    expect(await user.verifyAddEmail('never@example.com', code)).toEqual({ ok: false, reason: 'invalid' });
  });

  it("someone else's address: same response and code at add, refused at verify", async () => {
    const other = await account('other', 'taken@example.com');
    const { user } = await account();
    const start = await user.startAddEmail('taken@example.com');
    expect(start).toEqual({ ok: true, email: 'taken@example.com', expiresAt: NOW + config.CODE_TTL });
    expect(fake.mail.at(-1)!.subject).toMatch(/Confirm your new/);
    expect(await user.verifyAddEmail('taken@example.com', lastCode(fake.mail))).toEqual({ ok: false, reason: 'unavailable' });
    expect((await user.getAccount()).emails).toHaveLength(1);
    expect(await index.resolve('taken@example.com')).toBe(other.userId);
  });

  it('MAX_PENDING_EMAILS caps new pending addresses; resends are fine', async () => {
    const { user } = await account();
    for (let i = 0; i < config.MAX_PENDING_EMAILS; i++) {
      expect(await user.startAddEmail(`p${i}@example.com`)).toMatchObject({ ok: true });
    }
    expect(await user.startAddEmail('one-more@example.com')).toEqual({ ok: false, reason: 'too_many_pending' });
    expect(await user.startAddEmail('p0@example.com')).toMatchObject({ ok: true });
    // Expired pending rows stop counting.
    vi.setSystemTime(NOW + config.CODE_TTL);
    expect(await user.startAddEmail('one-more@example.com')).toMatchObject({ ok: true });
  });

  it('ACTION_LIMITS.verification_send limits code sends', async () => {
    const { user } = await account();
    const [max, windowMs] = config.ACTION_LIMITS.verification_send!;
    for (let i = 0; i < max; i++) expect(await user.startAddEmail('a@example.com')).toMatchObject({ ok: true });
    expect(await user.startAddEmail('a@example.com')).toEqual({ ok: false, reason: 'rate_limited', retryAfterMs: windowMs });
    expect(fake.mail).toHaveLength(max);
  });

  it('ACTION_LIMITS.email_add limits new addresses', async () => {
    const { user, db } = await account();
    const [max] = config.ACTION_LIMITS.email_add!;
    for (let i = 0; i < max; i++) db.prepare("INSERT INTO action_limits (action, at) VALUES ('email_add', ?)").run(NOW - 1000);
    expect(await user.startAddEmail('a@example.com')).toMatchObject({ ok: false, reason: 'rate_limited' });
  });

  it('MAX_EMAILS_PER_ACCOUNT counts verified addresses and is enforced at verification', async () => {
    const { user } = await account();
    for (let i = 2; i < config.MAX_EMAILS_PER_ACCOUNT; i++) {
      expect(await addVerified(user, `v${i}@example.com`)).toMatchObject({ ok: true });
    }
    // One slot left, two pending.
    await user.startAddEmail('last1@example.com');
    const code1 = lastCode(fake.mail);
    await user.startAddEmail('last2@example.com');
    const code2 = lastCode(fake.mail);
    expect(await user.verifyAddEmail('last1@example.com', code1)).toMatchObject({ ok: true });
    expect(await user.verifyAddEmail('last2@example.com', code2)).toEqual({ ok: false, reason: 'too_many_emails' });
    expect(await index.resolve('last2@example.com')).toBeNull();
    expect((await user.getAccount()).emails).toHaveLength(config.MAX_EMAILS_PER_ACCOUNT);
    expect(await user.startAddEmail('more@example.com')).toEqual({ ok: false, reason: 'too_many_emails' });
  });
});

describe('primary and removal', () => {
  it('setPrimaryEmail alerts every verified address and updates claims', async () => {
    const { user } = await account();
    await addVerified(user, 'b2@example.com');
    await addVerified(user, 'b3@example.com');
    const { sessionId } = await user.createSession({ amr: ['pwd'] });
    fake.mail.length = 0;
    expect(await user.setPrimaryEmail('B2@example.com')).toEqual({ ok: true, changed: true });
    expect((await user.getClaims(sessionId))!.email).toBe('b2@example.com');
    expect(fake.mail.map((m) => m.to).sort()).toEqual(['b2@example.com', 'b3@example.com', 'brad@example.com']);
    expect(fake.mail.every((m) => /primary email address changed/.test(m.subject))).toBe(true);
    fake.mail.length = 0;
    expect(await user.setPrimaryEmail('b2@example.com')).toEqual({ ok: true, changed: false });
    expect(fake.mail).toHaveLength(0);
    expect(await user.setPrimaryEmail('nope@example.com')).toEqual({ ok: false, reason: 'not_found' });
  });

  it("can't remove the last address; the primary needs a valid new one", async () => {
    const { user } = await account();
    expect(await user.removeEmail('brad@example.com')).toEqual({ ok: false, reason: 'last_email' });
    await addVerified(user, 'b2@example.com');
    expect(await user.removeEmail('nope@example.com')).toEqual({ ok: false, reason: 'not_found' });
    expect(await user.removeEmail('brad@example.com')).toEqual({ ok: false, reason: 'primary_required' });
    expect(await user.removeEmail('brad@example.com', 'brad@example.com')).toEqual({ ok: false, reason: 'invalid_new_primary' });
    expect(await user.removeEmail('brad@example.com', 'x@example.com')).toEqual({ ok: false, reason: 'invalid_new_primary' });
  });

  it('removal holds the address for EMAIL_HOLD and alerts primary + removed address', async () => {
    const { userId, user } = await account();
    await addVerified(user, 'b2@example.com');
    fake.mail.length = 0;
    expect(await user.removeEmail('b2@example.com')).toEqual({ ok: true, primaryChanged: false });
    expect(indexRow('b2@example.com')).toMatchObject({ user_id: userId, status: 'held', expires_at: NOW + config.EMAIL_HOLD });
    expect(await index.resolve('b2@example.com')).toBeNull();
    expect(fake.mail.map((m) => m.to).sort()).toEqual(['b2@example.com', 'brad@example.com']);
    expect(fake.mail.every((m) => /was removed/.test(m.subject))).toBe(true);

    // During the hold: nobody else can claim it, the owner can.
    const other = await account('other', 'other@example.com');
    await other.user.startAddEmail('b2@example.com');
    expect(await other.user.verifyAddEmail('b2@example.com', lastCode(fake.mail))).toEqual({ ok: false, reason: 'unavailable' });
    expect(await addVerified(user, 'b2@example.com')).toMatchObject({ ok: true });
    await user.removeEmail('b2@example.com');

    // After the hold the sweep frees it.
    vi.setSystemTime(NOW + config.EMAIL_HOLD);
    await index.alarm();
    expect(indexRow('b2@example.com')).toBeUndefined();
    expect(await addVerified(other.user, 'b2@example.com')).toMatchObject({ ok: true });
    expect(await index.resolve('b2@example.com')).toBe(other.userId);
  });

  it('removing the primary switches primary, alerts all remaining about it', async () => {
    const { user } = await account();
    await addVerified(user, 'b2@example.com');
    await addVerified(user, 'b3@example.com');
    fake.mail.length = 0;
    expect(await user.removeEmail('brad@example.com', 'b3@example.com')).toEqual({ ok: true, primaryChanged: true });
    const info = await user.getAccount();
    expect(info.emails.find((e) => e.primary)!.email).toBe('b3@example.com');
    const removed = fake.mail.filter((m) => /was removed/.test(m.subject)).map((m) => m.to).sort();
    expect(removed).toEqual(['b3@example.com', 'brad@example.com']);
    const primary = fake.mail.filter((m) => /primary email/.test(m.subject)).map((m) => m.to).sort();
    expect(primary).toEqual(['b2@example.com', 'b3@example.com']);
  });
});

describe('UserIndex email claims', () => {
  it('claimEmail is idempotent for the owner and refuses others; release undoes it', async () => {
    const a = await account('alice', 'alice@example.com');
    expect(await index.claimEmail(a.userId, 'Shared@Example.com')).toEqual({ ok: true });
    expect(await index.claimEmail(a.userId, 'shared@example.com')).toEqual({ ok: true });
    expect(await index.claimEmail('usr_OTHER', 'shared@example.com')).toEqual({ ok: false, reason: 'taken' });
    expect(await index.releaseEmail('usr_OTHER', 'shared@example.com')).toBe(false);
    expect(await index.releaseEmail(a.userId, 'shared@example.com')).toBe(true);
    expect(await index.claimEmail('usr_OTHER', 'shared@example.com')).toEqual({ ok: true });
  });

  it('holdEmail only touches the owner\'s active row and schedules the sweep', async () => {
    const a = await account('alice', 'alice@example.com');
    expect(await index.holdEmail('usr_OTHER', 'alice@example.com')).toBe(false);
    expect(await index.holdEmail(a.userId, 'alice@example.com')).toBe(true);
    expect(fake.index.instances.get('index')!.fake.getAlarm()).toBe(NOW + config.EMAIL_HOLD);
  });
});
