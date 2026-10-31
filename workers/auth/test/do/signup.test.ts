import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { config } from '../../src/config';
import { lastCode, makeFakeEnv } from './fake-env';

vi.mock('cloudflare:workers', async () => ({
  DurableObject: (await import('./fake-storage')).FakeDurableObject,
}));
vi.mock('../../src/crypto/password', async () => (await import('./fake-env')).fakePasswordModule());

const { User } = await import('../../src/do/user');
const { UserIndex } = await import('../../src/do/user-index');

const NOW = 1_800_000_000_000;

function setup() {
  const fake = makeFakeEnv({ User, UserIndex });
  const index = fake.env.USER_INDEX.get(fake.env.USER_INDEX.idFromName('index')) as unknown as InstanceType<typeof UserIndex>;
  const { db, getAlarm } = fake.index.instances.get('index')!.fake;
  return { ...fake, index, db, getAlarm };
}

function count(db: ReturnType<typeof setup>['db'], table: string): number {
  return Number(db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).all()[0]!.n);
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(NOW);
});
afterEach(() => {
  vi.useRealTimers();
});

describe('UserIndex signup', () => {
  it('happy path: start → verify → complete creates the account', async () => {
    const { index, mail, db, getAlarm, users } = setup();
    const start = await index.startSignup({ username: 'Brad', email: ' Brad@Example.com ', ip: '1.2.3.4' });
    expect(start).toEqual({ ok: true, signupId: expect.stringMatching(/^sig_/) });
    if (!start.ok) throw new Error();

    expect(mail).toHaveLength(1);
    expect(mail[0]!.to).toBe('Brad@Example.com');
    expect(mail[0]!.subject).toMatch(/verification code/);
    const handle = db.prepare('SELECT * FROM handles').all()[0]!;
    expect(handle).toMatchObject({ username_norm: 'brad', status: 'pending', user_id: null, expires_at: NOW + config.SIGNUP_TTL });
    expect(getAlarm()).toBe(NOW + config.SIGNUP_TTL);
    expect(await index.resolve('brad')).toBeNull();

    expect(await index.completeSignup(start.signupId)).toEqual({ ok: false, reason: 'not_verified' });
    expect(await index.getVerifiedSignup(start.signupId)).toBeNull();
    expect(await index.verifySignup(start.signupId, lastCode(mail))).toEqual({ ok: true });
    const verified = await index.getVerifiedSignup(start.signupId);
    expect(verified).toMatchObject({ username: 'Brad', email: 'Brad@Example.com', userId: expect.stringMatching(/^usr_/) });

    const done = await index.completeSignup(start.signupId);
    expect(done).toEqual({ ok: true, userId: verified!.userId, username: 'Brad', email: 'brad@example.com' });
    expect(await index.resolve('BRAD')).toBe(verified!.userId);
    expect(await index.resolve('brad@example.com')).toBe(verified!.userId);
    expect(count(db, 'pending_signups')).toBe(0);

    const user = users.instances.get(verified!.userId)!.instance;
    const session = await user.createSession({ amr: ['pwd'] });
    expect(session.claims).toMatchObject({ sub: verified!.userId, preferred_username: 'Brad', email: 'brad@example.com' });

    // Completing twice fails.
    expect(await index.completeSignup(start.signupId)).toEqual({ ok: false, reason: 'invalid' });
  });

  it('rejects invalid usernames and emails without side effects', async () => {
    const { index, mail, db } = setup();
    expect(await index.startSignup({ username: 'ab', email: 'a@b.io' })).toEqual({ ok: false, reason: 'invalid_username' });
    expect(await index.startSignup({ username: 'admin', email: 'a@b.io' })).toEqual({ ok: false, reason: 'invalid_username' });
    expect(await index.startSignup({ username: 'brad', email: 'nope' })).toEqual({ ok: false, reason: 'invalid_email' });
    expect(mail).toHaveLength(0);
    expect(count(db, 'handles')).toBe(0);
  });

  it('counts wrong codes and stops at CODE_MAX_ATTEMPTS', async () => {
    const { index, mail } = setup();
    const start = await index.startSignup({ username: 'brad', email: 'b@example.com' });
    if (!start.ok) throw new Error();
    const code = lastCode(mail);
    const wrong = code === '000000' ? '111111' : '000000';
    for (let i = 1; i < config.CODE_MAX_ATTEMPTS; i++) {
      expect(await index.verifySignup(start.signupId, wrong)).toEqual({ ok: false, reason: 'invalid' });
    }
    expect(await index.verifySignup(start.signupId, wrong)).toEqual({ ok: false, reason: 'too_many_attempts' });
    expect(await index.verifySignup(start.signupId, code)).toEqual({ ok: false, reason: 'too_many_attempts' });
    expect(await index.verifySignup('sig_unknown', code)).toEqual({ ok: false, reason: 'invalid' });
  });

  it('expires codes after CODE_TTL and signups after SIGNUP_TTL', async () => {
    const { index, mail } = setup();
    const start = await index.startSignup({ username: 'brad', email: 'b@example.com' });
    if (!start.ok) throw new Error();
    const code = lastCode(mail);
    vi.setSystemTime(NOW + config.CODE_TTL);
    expect(await index.verifySignup(start.signupId, code)).toEqual({ ok: false, reason: 'expired' });

    // A resend gives a fresh code (and signupId) within the same reservation.
    const again = await index.startSignup({ username: 'brad', email: 'b@example.com' });
    if (!again.ok) throw new Error();
    expect(again.signupId).not.toBe(start.signupId);
    expect(await index.verifySignup(again.signupId, lastCode(mail))).toEqual({ ok: true });

    vi.setSystemTime(NOW + config.SIGNUP_TTL);
    expect(await index.completeSignup(again.signupId)).toEqual({ ok: false, reason: 'invalid' });
    expect(await index.verifySignup(again.signupId, lastCode(mail))).toEqual({ ok: false, reason: 'expired' });
  });

  it('resend rotates the signupId and invalidates the old code', async () => {
    const { index, mail } = setup();
    const first = await index.startSignup({ username: 'brad', email: 'b@example.com' });
    const oldCode = lastCode(mail);
    const second = await index.startSignup({ username: 'BRAD', email: 'B@example.com' });
    if (!first.ok || !second.ok) throw new Error();
    expect(mail).toHaveLength(2);
    expect(await index.verifySignup(first.signupId, oldCode)).toEqual({ ok: false, reason: 'invalid' });
    const newCode = lastCode(mail);
    if (newCode !== oldCode) {
      expect(await index.verifySignup(second.signupId, oldCode)).toEqual({ ok: false, reason: 'invalid' });
    }
    expect(await index.verifySignup(second.signupId, newCode)).toEqual({ ok: true });
  });

  it('username taken: active, held, or pending for another email', async () => {
    const { index, db, mail } = setup();
    await index.registerAccount({ userId: 'usr_A', username: 'taken', email: 'a@example.com' });
    expect(await index.startSignup({ username: 'Taken', email: 'x@example.com' }))
      .toEqual({ ok: false, reason: 'username_taken' });
    db.exec(`INSERT INTO handles VALUES ('heldname', 'usr_A', 'held', ${NOW + 1000})`);
    expect(await index.startSignup({ username: 'heldname', email: 'x@example.com' }))
      .toEqual({ ok: false, reason: 'username_taken' });
    expect((await index.startSignup({ username: 'brad', email: 'b@example.com' })).ok).toBe(true);
    expect(await index.startSignup({ username: 'brad', email: 'other@example.com' }))
      .toEqual({ ok: false, reason: 'username_taken' });
    expect(mail).toHaveLength(1);

    // Expired reservations are free again.
    vi.setSystemTime(NOW + config.SIGNUP_TTL);
    expect((await index.startSignup({ username: 'brad', email: 'other@example.com' })).ok).toBe(true);
    expect((await index.startSignup({ username: 'heldname', email: 'h@example.com' })).ok).toBe(true);
  });

  it('registered email: same response shape, notice instead of a code, never verifies', async () => {
    const { index, mail } = setup();
    await index.registerAccount({ userId: 'usr_A', username: 'old', email: 'b@example.com' });
    const fresh = await index.startSignup({ username: 'fresh', email: 'new@example.com' });
    const result = await index.startSignup({ username: 'newname', email: 'B@Example.com' });
    expect(Object.keys(result).sort()).toEqual(Object.keys(fresh).sort());
    expect(result).toEqual({ ok: true, signupId: expect.stringMatching(/^sig_/) });
    if (!result.ok) throw new Error();

    const notice = mail.at(-1)!;
    expect(notice.to).toBe('B@Example.com');
    expect(notice.subject).toMatch(/already have/);
    expect(notice.text).toContain('https://auth.bcnelson.dev/login');
    expect(notice.text).toContain('https://auth.bcnelson.dev/password/forgot');
    expect(notice.text).not.toMatch(/\b\d{6}\b/);
    for (const code of ['000000', '123456', '999999']) {
      expect((await index.verifySignup(result.signupId, code)).ok).toBe(false);
    }
  });

  it('fails generically when the email is claimed before completion', async () => {
    const { index, mail, users } = setup();
    const a = await index.startSignup({ username: 'first', email: 'same@example.com' });
    const codeA = lastCode(mail);
    const b = await index.startSignup({ username: 'second', email: 'same@example.com' });
    const codeB = lastCode(mail);
    if (!a.ok || !b.ok) throw new Error();
    await index.verifySignup(a.signupId, codeA);
    await index.verifySignup(b.signupId, codeB);
    expect((await index.completeSignup(a.signupId)).ok).toBe(true);
    expect(await index.completeSignup(b.signupId)).toEqual({ ok: false, reason: 'conflict' });
    expect(await index.resolve('second')).toBeNull();
    expect(users.instances.size).toBe(1);
  });

  it('re-checks inside the transaction after creating the User DO', async () => {
    const { index, mail, env } = setup();
    const a = await index.startSignup({ username: 'first', email: 'race@example.com' });
    if (!a.ok) throw new Error();
    await index.verifySignup(a.signupId, lastCode(mail));
    const verified = (await index.getVerifiedSignup(a.signupId))!;
    // Another account claims the email while initProfile is in flight.
    const real = env.USER.get.bind(env.USER) as unknown as (id: string) => any;
    (env.USER as unknown as { get: unknown }).get = (id: string) => {
      const user = real(id);
      return {
        initProfile: async (input: unknown) => {
          await user.initProfile(input);
          await index.registerAccount({ userId: 'usr_OTHER', username: 'other', email: 'race@example.com' });
        },
      };
    };
    expect(await index.completeSignup(a.signupId)).toEqual({ ok: false, reason: 'conflict' });
    expect(await index.resolve('first')).toBeNull();
    expect(await index.resolve('race@example.com')).toBe('usr_OTHER');
    expect(verified.userId).toMatch(/^usr_/);
  });

  it('limits sends per email and per IP', async () => {
    const { index } = setup();
    const [perEmail, window] = config.ACTION_LIMITS.verification_send!;
    for (let i = 0; i < perEmail; i++) {
      expect((await index.startSignup({ username: 'brad', email: 'b@example.com' })).ok).toBe(true);
    }
    const limited = await index.startSignup({ username: 'brad', email: 'b@example.com' });
    expect(limited).toEqual({ ok: false, reason: 'rate_limited', retryAfterMs: window });

    const [perIp] = config.SIGNUP_SENDS_PER_IP;
    for (let i = 0; i < perIp; i++) {
      expect((await index.startSignup({ username: `user${i}`, email: `u${i}@example.com`, ip: '9.9.9.9' })).ok).toBe(true);
    }
    expect(await index.startSignup({ username: 'another', email: 'another@example.com', ip: '9.9.9.9' }))
      .toMatchObject({ ok: false, reason: 'rate_limited' });
    // A rate-limited start reserves nothing.
    expect(await index.isUsernameAvailable('another')).toBe(true);
  });

  it('still answers ok when the email fails to send', async () => {
    const { index, failMail } = setup();
    failMail.value = true;
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect((await index.startSignup({ username: 'brad', email: 'b@example.com' })).ok).toBe(true);
    spy.mockRestore();
  });

  it('sweep removes expired signups, reservations and send counters', async () => {
    const { index, db, getAlarm } = setup();
    await index.startSignup({ username: 'brad', email: 'b@example.com', ip: '1.1.1.1' });
    expect(count(db, 'send_limits')).toBe(2);
    vi.setSystemTime(NOW + config.SIGNUP_TTL);
    await index.alarm();
    expect(count(db, 'handles')).toBe(0);
    expect(count(db, 'pending_signups')).toBe(0);
    expect(count(db, 'send_limits')).toBe(2);
    const [, window] = config.ACTION_LIMITS.verification_send!;
    expect(getAlarm()).toBe(NOW + Math.min(window, config.SIGNUP_SENDS_PER_IP[1]));
    vi.setSystemTime(NOW + Math.max(window, config.SIGNUP_SENDS_PER_IP[1]));
    await index.alarm();
    expect(count(db, 'send_limits')).toBe(0);
  });
});
