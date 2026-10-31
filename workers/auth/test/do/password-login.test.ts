import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { config } from '../../src/config';
import type { PasswordLoginContext } from '../../src/types';
import { dummyCalls, makeFakeEnv } from './fake-env';

vi.mock('cloudflare:workers', async () => ({
  DurableObject: (await import('./fake-storage')).FakeDurableObject,
}));
vi.mock('../../src/crypto/password', async () => (await import('./fake-env')).fakePasswordModule());

const { User } = await import('../../src/do/user');
const { UserIndex } = await import('../../src/do/user-index');

const NOW = 1_800_000_000_000;
const PLAIN: PasswordLoginContext = { amr: ['pwd'], ip: '1.2.3.4', userAgent: 'test', turnstileOk: false };
const WITH_TURNSTILE: PasswordLoginContext = { ...PLAIN, turnstileOk: true };

async function setup(hash: string | null = 'v2$correct-horse') {
  const fake = makeFakeEnv({ User, UserIndex });
  const user = fake.env.USER.get(fake.env.USER.idFromName('usr_TEST')) as unknown as InstanceType<typeof User>;
  await user.initProfile({ userId: 'usr_TEST', username: 'Brad', email: 'brad@example.com' });
  if (hash) await user.setPassword(hash);
  const { db } = fake.users.instances.get('usr_TEST')!.fake;
  const attempts = () => db.prepare('SELECT * FROM login_attempts').all()[0] ?? null;
  const credential = () => db.prepare("SELECT * FROM credentials WHERE type = 'password'").all()[0]!;
  const audit = () => db.prepare('SELECT event FROM audit_log ORDER BY rowid').all().map((r) => r.event);
  return { ...fake, user, db, attempts, credential, audit };
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(NOW);
});
afterEach(() => {
  vi.useRealTimers();
});

describe('User password credential', () => {
  it('logs in with the right password and creates a session', async () => {
    const { user, attempts, credential, audit } = await setup();
    const result = await user.loginWithPassword('correct-horse', PLAIN);
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error();
    expect(result.session.claims).toMatchObject({ sub: 'usr_TEST', amr: ['pwd'], email: 'brad@example.com' });
    expect(await user.listSessions()).toHaveLength(1);
    expect((await user.listSessions())[0]).toMatchObject({ ip: '1.2.3.4', userAgent: 'test' });
    expect(attempts()).toBeNull();
    expect(credential().last_used_at).toBe(NOW);
    expect(audit()).toContain('login.password');
  });

  it('rejects a wrong password and records the failure', async () => {
    const { user, attempts, audit } = await setup();
    expect(await user.loginWithPassword('wrong', PLAIN)).toEqual({ ok: false, reason: 'invalid' });
    expect(attempts()).toMatchObject({ method: 'password', failures: 1, last_failure_at: NOW, locked_until: null });
    expect(await user.listSessions()).toHaveLength(0);
    expect(audit()).toContain('login.password_failed');
  });

  it('without a password credential: dummy verify, invalid', async () => {
    const { user, attempts } = await setup(null);
    const before = dummyCalls.count;
    expect(await user.loginWithPassword('anything', PLAIN)).toEqual({ ok: false, reason: 'invalid' });
    expect(dummyCalls.count).toBe(before + 1);
    expect(attempts()).toMatchObject({ failures: 1 });
  });

  it('backoff: turnstile after 3 failures, lock after 5, success resets', async () => {
    const { user, attempts } = await setup();
    for (let i = 0; i < config.TURNSTILE_AFTER_FAILURES; i++) {
      expect((await user.loginWithPassword('wrong', PLAIN)).ok).toBe(false);
    }
    // Needs Turnstile now; without it the password isn't even checked or counted.
    expect(await user.loginWithPassword('correct-horse', PLAIN)).toEqual({ ok: false, reason: 'turnstile_required' });
    expect(attempts()).toMatchObject({ failures: config.TURNSTILE_AFTER_FAILURES });

    for (let i = config.TURNSTILE_AFTER_FAILURES; i < config.BACKOFF_AFTER_FAILURES; i++) {
      expect(await user.loginWithPassword('wrong', WITH_TURNSTILE)).toEqual({ ok: false, reason: 'invalid' });
    }
    expect(attempts()).toMatchObject({ locked_until: NOW + config.BACKOFF_BASE });
    expect(await user.loginWithPassword('correct-horse', WITH_TURNSTILE))
      .toEqual({ ok: false, reason: 'locked', retryAfterMs: config.BACKOFF_BASE });

    vi.setSystemTime(NOW + config.BACKOFF_BASE);
    expect(await user.loginWithPassword('correct-horse', PLAIN)).toEqual({ ok: false, reason: 'turnstile_required' });
    expect((await user.loginWithPassword('correct-horse', WITH_TURNSTILE)).ok).toBe(true);
    expect(attempts()).toBeNull();
    expect((await user.loginWithPassword('correct-horse', PLAIN)).ok).toBe(true);
  });

  it('sends the failure alert exactly once, at ALERT_AFTER_FAILURES', async () => {
    const { user, mail, attempts, audit } = await setup();
    let now = NOW;
    for (let i = 0; i < config.ALERT_AFTER_FAILURES + 2; i++) {
      const result = await user.loginWithPassword('wrong', WITH_TURNSTILE);
      expect(result).toEqual({ ok: false, reason: 'invalid' });
      // Step past each lock.
      now = Math.max(now, (attempts()?.locked_until as number | null) ?? now);
      vi.setSystemTime(now);
    }
    const alerts = mail.filter((m) => /Failed sign-in/.test(m.subject));
    expect(alerts).toHaveLength(1);
    expect(alerts[0]!.to).toBe('brad@example.com');
    expect(alerts[0]!.text).toContain(`${config.ALERT_AFTER_FAILURES} failed password attempts`);
    expect(audit().filter((e) => e === 'alert.login_failures')).toHaveLength(1);
  });

  it('rehashes an outdated hash on successful login', async () => {
    const { user, credential, audit, db } = await setup('v1$correct-horse');
    expect((await user.loginWithPassword('correct-horse', PLAIN)).ok).toBe(true);
    expect(JSON.parse(credential().data as string)).toEqual({ hash: 'v2$correct-horse' });
    const detail = db.prepare("SELECT detail FROM audit_log WHERE event = 'login.password'").all()[0]!.detail;
    expect(JSON.parse(detail as string)).toMatchObject({ rehashed: true });
    expect(audit()).toContain('password.set');
  });

  it('setPassword replaces the hash, keeps one credential, clears backoff', async () => {
    const { user, db, attempts, audit } = await setup();
    await user.loginWithPassword('wrong', PLAIN);
    await user.setPassword('v2$new-password');
    expect(attempts()).toBeNull();
    expect(db.prepare("SELECT COUNT(*) AS n FROM credentials WHERE type = 'password'").all()[0]!.n).toBe(1);
    expect((await user.loginWithPassword('correct-horse', PLAIN)).ok).toBe(false);
    expect((await user.loginWithPassword('new-password', PLAIN)).ok).toBe(true);
    expect(audit()).toContain('password.changed');
    await expect(user.setPassword('')).rejects.toThrow(/invalid hash/);
  });
});

describe('User roles', () => {
  it('ensureRole adds a configured role once and it reaches the claims', async () => {
    const { user, audit } = await setup();
    expect(await user.ensureRole('admin')).toBe(true);
    expect(await user.ensureRole('admin')).toBe(false);
    await expect(user.ensureRole('superuser')).rejects.toThrow(/Unknown role/);
    const session = await user.createSession({ amr: ['pwd'] });
    expect(session.claims.roles).toEqual(['admin']);
    expect(audit().filter((e) => e === 'role.added')).toHaveLength(1);
  });
});
