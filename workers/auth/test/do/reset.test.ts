import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { config } from '../../src/config';
import { parseResetToken, formatResetToken } from '../../src/do/user/reset';
import type { PasswordLoginContext } from '../../src/types';
import { makeFakeEnv, type SentMail } from './fake-env';

vi.mock('cloudflare:workers', async () => ({
  DurableObject: (await import('./fake-storage')).FakeDurableObject,
}));
vi.mock('../../src/crypto/password', async () => (await import('./fake-env')).fakePasswordModule());

const { User } = await import('../../src/do/user');
const { UserIndex } = await import('../../src/do/user-index');

const NOW = 1_800_000_000_000;
const LOGIN: PasswordLoginContext = { amr: ['pwd'], ip: '1.2.3.4', userAgent: 'test', turnstileOk: true };

async function setup(hash: string | null = 'v2$old-password') {
  const fake = makeFakeEnv({ User, UserIndex });
  const user = fake.env.USER.get(fake.env.USER.idFromName('usr_TEST')) as unknown as InstanceType<typeof User>;
  await user.initProfile({ userId: 'usr_TEST', username: 'Brad', email: 'brad@example.com' });
  if (hash) await user.setPassword(hash);
  const { db } = fake.users.instances.get('usr_TEST')!.fake;
  const tokens = () => db.prepare('SELECT * FROM tokens').all();
  const audit = () => db.prepare('SELECT event FROM audit_log ORDER BY rowid').all().map((r) => r.event);
  const passwordRows = () => db.prepare("SELECT * FROM credentials WHERE type = 'password'").all();
  return { ...fake, user, db, tokens, audit, passwordRows };
}

/** The secret from the reset link in the most recent mail. */
function lastSecret(mail: SentMail[]): string {
  const match = /token=([^\s]+)/.exec(mail.at(-1)?.text ?? '');
  if (!match) throw new Error('no reset link in last mail');
  const token = decodeURIComponent(match[1]!);
  const [prefix, userId, secret] = token.split('.');
  expect(prefix).toBe('pr1');
  expect(userId).toBe('usr_TEST');
  return secret!;
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(NOW);
});
afterEach(() => {
  vi.useRealTimers();
});

describe('reset token format', () => {
  it('round-trips and rejects anything else', () => {
    const userId = 'usr_01HZY3T9Q8N6VXK2M4R7B5C0DE';
    const secret = 'a'.repeat(43);
    const token = formatResetToken({ userId, secret });
    expect(token).toBe(`pr1.${userId}.${secret}`);
    expect(parseResetToken(token)).toEqual({ userId, secret });
    for (const bad of ['', 'pr1', `pr2.${userId}.${secret}`, `pr1.usr_x.${secret}`, `pr1.${userId}.short`,
      `pr1.${userId}.${secret}.extra`, `rt1.${userId}.${secret}`, `pr1.${userId}.${'a'.repeat(42)}!`]) {
      expect(parseResetToken(bad)).toBeNull();
    }
  });
});

describe('User.requestPasswordReset', () => {
  it('stores a hashed single-use token and mails the link to that address only', async () => {
    const { user, mail, tokens, audit } = await setup();
    expect(await user.requestPasswordReset('Brad@Example.com')).toEqual({ sent: true });
    expect(mail).toHaveLength(1);
    expect(mail[0]!.to).toBe('brad@example.com');
    expect(mail[0]!.subject).toMatch(/Reset your/);
    expect(mail[0]!.text).toContain('https://auth.bcnelson.dev/password/reset?token=pr1.usr_TEST.');
    const secret = lastSecret(mail);
    const rows = tokens();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ purpose: 'password_reset', email: 'brad@example.com', expires_at: NOW + config.RESET_TTL, used_at: null });
    expect(rows[0]!.token_hash).not.toContain(secret);
    expect(audit()).toContain('password_reset.requested');
  });

  it('only for a verified address on this account', async () => {
    const { user, mail, tokens } = await setup();
    expect(await user.requestPasswordReset('other@example.com')).toEqual({ sent: false, reason: 'unknown_email' });
    expect(mail).toHaveLength(0);
    expect(tokens()).toHaveLength(0);
  });

  it('enforces ACTION_LIMITS.password_reset', async () => {
    const { user, mail, audit } = await setup();
    const [max, windowMs] = config.ACTION_LIMITS.password_reset!;
    for (let i = 0; i < max; i++) expect(await user.requestPasswordReset('brad@example.com')).toEqual({ sent: true });
    expect(await user.requestPasswordReset('brad@example.com')).toEqual({ sent: false, reason: 'rate_limited' });
    expect(mail).toHaveLength(max);
    expect(audit()).toContain('password_reset.limited');
    vi.setSystemTime(NOW + windowMs + 1);
    expect(await user.requestPasswordReset('brad@example.com')).toEqual({ sent: true });
  });

  it('reports a mail failure without throwing', async () => {
    const { user, failMail } = await setup();
    failMail.value = true;
    expect(await user.requestPasswordReset('brad@example.com')).toEqual({ sent: false, reason: 'send_failed' });
  });
});

describe('User.resetPassword', () => {
  it('sets the password, uses the token, revokes all sessions, clears backoff, alerts every address', async () => {
    const { user, mail, db, tokens, audit, passwordRows } = await setup();
    db.prepare('INSERT INTO emails (email, verified_at, is_primary) VALUES (?, ?, 0)').run('alt@example.com', NOW);
    await user.loginWithPassword('old-password', LOGIN);
    await user.loginWithPassword('old-password', LOGIN);
    await user.loginWithPassword('wrong', LOGIN);
    expect(db.prepare('SELECT * FROM login_attempts').all()).toHaveLength(1);
    expect(await user.listSessions()).toHaveLength(2);

    await user.requestPasswordReset('brad@example.com');
    const secret = lastSecret(mail);
    await user.requestPasswordReset('alt@example.com'); // another outstanding link
    mail.length = 0;

    expect(await user.checkResetToken(secret)).toEqual({ ok: true });
    expect(await user.resetPassword(secret, 'v2$new-password')).toEqual({ ok: true });

    expect(passwordRows()).toHaveLength(1);
    expect(JSON.parse(passwordRows()[0]!.data as string)).toEqual({ hash: 'v2$new-password' });
    expect(await user.listSessions()).toHaveLength(0);
    expect(db.prepare('SELECT * FROM login_attempts').all()).toHaveLength(0);
    expect(tokens().every((t) => t.used_at === NOW)).toBe(true);
    expect(mail.map((m) => m.to).sort()).toEqual(['alt@example.com', 'brad@example.com']);
    expect(mail.every((m) => /password was changed/.test(m.subject))).toBe(true);
    expect(audit()).toEqual(expect.arrayContaining(['password.changed', 'password_reset.completed']));

    expect((await user.loginWithPassword('old-password', LOGIN)).ok).toBe(false);
    expect((await user.loginWithPassword('new-password', LOGIN)).ok).toBe(true);
  });

  it('a token works once; other outstanding links die with it', async () => {
    const { user, mail } = await setup();
    await user.requestPasswordReset('brad@example.com');
    const first = lastSecret(mail);
    await user.requestPasswordReset('brad@example.com');
    const second = lastSecret(mail);
    expect(await user.resetPassword(second, 'v2$new-password')).toEqual({ ok: true });
    expect(await user.resetPassword(second, 'v2$again-password')).toEqual({ ok: false, reason: 'used' });
    expect(await user.resetPassword(first, 'v2$again-password')).toEqual({ ok: false, reason: 'used' });
    expect(await user.checkResetToken(first)).toEqual({ ok: false, reason: 'used' });
  });

  it('expires after RESET_TTL', async () => {
    const { user, mail, passwordRows } = await setup();
    await user.requestPasswordReset('brad@example.com');
    const secret = lastSecret(mail);
    vi.setSystemTime(NOW + config.RESET_TTL);
    expect(await user.checkResetToken(secret)).toEqual({ ok: false, reason: 'expired' });
    expect(await user.resetPassword(secret, 'v2$new-password')).toEqual({ ok: false, reason: 'expired' });
    expect(JSON.parse(passwordRows()[0]!.data as string)).toEqual({ hash: 'v2$old-password' });
  });

  it('rejects forged or foreign secrets without side effects', async () => {
    const { user, mail, audit } = await setup();
    await user.loginWithPassword('old-password', LOGIN);
    await user.requestPasswordReset('brad@example.com');
    const secret = lastSecret(mail);
    const forged = secret.slice(0, -1) + (secret.endsWith('A') ? 'B' : 'A');
    expect(await user.resetPassword(forged, 'v2$new-password')).toEqual({ ok: false, reason: 'invalid' });
    expect(await user.resetPassword('', 'v2$new-password')).toEqual({ ok: false, reason: 'invalid' });
    expect(await user.listSessions()).toHaveLength(1);
    expect(audit()).toContain('password_reset.rejected');
    // The real one still works.
    expect(await user.resetPassword(secret, 'v2$new-password')).toEqual({ ok: true });
  });

  it('a token for an address since removed from the account is invalid', async () => {
    const { user, mail, db } = await setup();
    db.prepare('INSERT INTO emails (email, verified_at, is_primary) VALUES (?, ?, 0)').run('alt@example.com', NOW);
    await user.requestPasswordReset('alt@example.com');
    const secret = lastSecret(mail);
    db.prepare("DELETE FROM emails WHERE email = 'alt@example.com'").run();
    expect(await user.resetPassword(secret, 'v2$new-password')).toEqual({ ok: false, reason: 'invalid' });
  });

  it('gives a passkey-only user a password credential', async () => {
    const { user, mail, passwordRows, audit } = await setup(null);
    expect(passwordRows()).toHaveLength(0);
    await user.requestPasswordReset('brad@example.com');
    expect(await user.resetPassword(lastSecret(mail), 'v2$new-password')).toEqual({ ok: true });
    expect(passwordRows()).toHaveLength(1);
    expect(audit()).toContain('password.set');
    expect((await user.loginWithPassword('new-password', LOGIN)).ok).toBe(true);
  });
});
