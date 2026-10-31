import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { verifyRegistrationResponse } from '@simplewebauthn/server';
import { isoBase64URL } from '@simplewebauthn/server/helpers';
import { config } from '../../src/config';
import type { Env } from '../../src/env';
import type { NewPasskey } from '../../src/do/user/passkeys';
import { fakeState } from './fake-storage';
import { SoftAuthenticator, randomChallenge, userHandleFor } from './passkeys-authenticator';

vi.mock('cloudflare:workers', async () => ({
  DurableObject: (await import('./fake-storage')).FakeDurableObject,
}));

const { User } = await import('../../src/do/user');
const { UserIndex } = await import('../../src/do/user-index');

const START = 1_800_000_000_000;
const ORIGIN = 'https://auth.bcnelson.dev';
const RP_ID = 'bcnelson.dev';
const USER_ID = 'usr_01JTESTTESTTESTTESTTESTTE';

async function makeUser(withProfile = true) {
  const fake = fakeState();
  const user = new User(fake.state as unknown as DurableObjectState, {} as Env);
  if (withProfile) await user.initProfile({ userId: USER_ID, username: 'Brad', email: 'brad@example.com' });
  return { user, ...fake };
}

function makeIndex() {
  const fake = fakeState();
  const index = new UserIndex(fake.state as unknown as DurableObjectState, {} as Env);
  return { index, ...fake };
}

/** Register `auth` with real verification, as routes/passkey.ts does, and return what it stores. */
async function registered(auth: SoftAuthenticator, label?: string): Promise<NewPasskey> {
  const challenge = randomChallenge();
  const response = await auth.register({ challenge, user: { id: userHandleFor(USER_ID) } });
  const result = await verifyRegistrationResponse({
    response, expectedChallenge: challenge, expectedOrigin: ORIGIN, expectedRPID: RP_ID,
  });
  if (!result.verified) throw new Error('registration did not verify');
  const info = result.registrationInfo;
  return {
    credentialId: info.credential.id,
    publicKey: isoBase64URL.fromBuffer(info.credential.publicKey),
    counter: info.credential.counter,
    transports: info.credential.transports ?? [],
    aaguid: info.aaguid,
    backedUp: info.credentialBackedUp,
    deviceType: info.credentialDeviceType,
    label,
  };
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(START);
});
afterEach(() => {
  vi.useRealTimers();
});

describe('User DO passkeys', () => {
  it('stores a registration with a default label and lists it', async () => {
    const { user, db } = await makeUser();
    const auth = new SoftAuthenticator({ synced: true, aaguid: 'icloud' });
    const result = await user.addPasskey(await registered(auth));
    expect(result).toMatchObject({ ok: true, passkey: { label: 'iCloud Keychain', backedUp: true, deviceType: 'multiDevice' } });

    const row = db.prepare("SELECT * FROM credentials WHERE type = 'passkey'").all()[0] as { id: string; data: string };
    expect(JSON.parse(row.data)).toMatchObject({
      credentialId: auth.id, counter: 0, transports: ['internal', 'hybrid'],
      aaguid: 'fbfc3007-154e-4ecc-8c0b-6e020557d7bd', backedUp: true, deviceType: 'multiDevice',
    });
    expect(db.prepare('SELECT * FROM passkey_ids').all()).toEqual([{ credential_id: auth.id, cred_id: row.id }]);

    expect(await user.listPasskeys()).toEqual([{
      id: row.id, label: 'iCloud Keychain', createdAt: START, lastUsedAt: null, backedUp: true, deviceType: 'multiDevice',
    }]);
    expect(await user.passkeyDescriptors()).toEqual([{ id: auth.id, transports: ['internal', 'hybrid'] }]);
  });

  it('uses "Passkey" for unknown authenticators, keeps a given label, refuses duplicates', async () => {
    const { user } = await makeUser();
    const auth = new SoftAuthenticator();
    const passkey = await registered(auth);
    expect(await user.addPasskey(passkey)).toMatchObject({ ok: true, passkey: { label: config.PASSKEY_DEFAULT_LABEL } });
    expect(await user.addPasskey(passkey)).toEqual({ ok: false, reason: 'duplicate' });
    const other = await registered(new SoftAuthenticator(), '  My   laptop ');
    expect(await user.addPasskey(other)).toMatchObject({ ok: true, passkey: { label: 'My laptop' } });
  });

  it('refuses without a profile', async () => {
    const { user } = await makeUser(false);
    expect(await user.addPasskey(await registered(new SoftAuthenticator()))).toEqual({ ok: false, reason: 'no_profile' });
  });

  it('verifies a login, updates counter and last_used_at, starts an hwk session (no password backoff)', async () => {
    const { user, db } = await makeUser();
    const auth = new SoftAuthenticator();
    await user.addPasskey(await registered(auth));
    // Password backoff in force must not matter.
    db.prepare("INSERT INTO login_attempts (method, failures, locked_until) VALUES ('password', 9, ?)").run(START + 60_000);

    vi.setSystemTime(START + 1000);
    const challenge = randomChallenge();
    const result = await user.verifyPasskeyLogin(await auth.assert({ challenge }), challenge, [ORIGIN], RP_ID, { ip: '1.2.3.4' });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.session.claims).toMatchObject({ sub: USER_ID, amr: ['hwk'] });

    const row = db.prepare("SELECT data, last_used_at FROM credentials WHERE type = 'passkey'").all()[0] as { data: string; last_used_at: number };
    expect(JSON.parse(row.data).counter).toBe(1);
    expect(row.last_used_at).toBe(START + 1000);
    expect((await user.listPasskeys())[0]!.lastUsedAt).toBe(START + 1000);

    // A replayed/cloned counter is refused.
    const again = randomChallenge();
    expect(await user.verifyPasskeyLogin(await auth.assert({ challenge: again }, { counter: 1 }), again, ORIGIN, RP_ID))
      .toEqual({ ok: false, reason: 'invalid' });
    const next = randomChallenge();
    expect((await user.verifyPasskeyLogin(await auth.assert({ challenge: next }), next, ORIGIN, RP_ID)).ok).toBe(true);
  });

  it('rejects unknown credentials, wrong challenge, wrong origin and wrong RP ID alike', async () => {
    const { user } = await makeUser();
    const auth = new SoftAuthenticator();
    await user.addPasskey(await registered(auth));
    const stranger = new SoftAuthenticator();
    await registered(stranger);

    const c1 = randomChallenge();
    expect(await user.verifyPasskeyLogin(await stranger.assert({ challenge: c1 }), c1, ORIGIN, RP_ID))
      .toEqual({ ok: false, reason: 'invalid' });
    const c2 = randomChallenge();
    expect(await user.verifyPasskeyLogin(await auth.assert({ challenge: c2 }), randomChallenge(), ORIGIN, RP_ID))
      .toEqual({ ok: false, reason: 'invalid' });
    const c3 = randomChallenge();
    expect(await user.verifyPasskeyLogin(await auth.assert({ challenge: c3 }, { origin: 'https://evil.example' }), c3, ORIGIN, RP_ID))
      .toEqual({ ok: false, reason: 'invalid' });
    const c4 = randomChallenge();
    expect(await user.verifyPasskeyLogin(await auth.assert({ challenge: c4 }), c4, ORIGIN, 'other.example'))
      .toEqual({ ok: false, reason: 'invalid' });
  });

  it('renames with validation', async () => {
    const { user } = await makeUser();
    const added = await user.addPasskey(await registered(new SoftAuthenticator()));
    if (!added.ok) throw new Error('add failed');
    expect(await user.renamePasskey(added.passkey.id, ' Work phone ')).toEqual({ ok: true });
    expect((await user.listPasskeys())[0]!.label).toBe('Work phone');
    expect(await user.renamePasskey(added.passkey.id, '   ')).toEqual({ ok: false, reason: 'invalid_label' });
    expect(await user.renamePasskey(added.passkey.id, 'x'.repeat(config.PASSKEY_LABEL_MAX_LENGTH + 1)))
      .toEqual({ ok: false, reason: 'invalid_label' });
    expect(await user.renamePasskey(added.passkey.id, 'bad\u0000name')).toEqual({ ok: false, reason: 'invalid_label' });
    expect(await user.renamePasskey('cred_NOPE', 'x')).toEqual({ ok: false, reason: 'not_found' });
  });

  it('refuses to delete the last login method', async () => {
    const { user, db } = await makeUser();
    const auth = new SoftAuthenticator();
    const first = await user.addPasskey(await registered(auth));
    const second = await user.addPasskey(await registered(new SoftAuthenticator()));
    if (!first.ok || !second.ok) throw new Error('add failed');

    expect(await user.deletePasskey(first.passkey.id)).toEqual({ ok: true });
    expect(db.prepare('SELECT * FROM passkey_ids WHERE cred_id = ?').all(first.passkey.id)).toHaveLength(0);
    // The deleted passkey can't sign in anymore.
    const challenge = randomChallenge();
    expect(await user.verifyPasskeyLogin(await auth.assert({ challenge }), challenge, ORIGIN, RP_ID))
      .toEqual({ ok: false, reason: 'invalid' });

    expect(await user.deletePasskey(second.passkey.id)).toEqual({ ok: false, reason: 'last_method' });
    await user.setPassword('v2$hunter22');
    expect(await user.deletePasskey(second.passkey.id)).toEqual({ ok: true });
    expect(await user.listPasskeys()).toEqual([]);
    expect(await user.deletePasskey(second.passkey.id)).toEqual({ ok: false, reason: 'not_found' });
  });

  it('caps passkeys per account', async () => {
    const { user, db } = await makeUser();
    const passkey = await registered(new SoftAuthenticator());
    for (let i = 0; i < config.MAX_PASSKEYS_PER_ACCOUNT; i++) {
      db.prepare("INSERT INTO credentials (id, type, data, created_at) VALUES (?, 'passkey', ?, 0)")
        .run(`cred_${i}`, JSON.stringify({ ...passkey, credentialId: `x${i}` }));
    }
    expect(await user.addPasskey(passkey)).toEqual({ ok: false, reason: 'too_many' });
  });
});

describe('UserIndex challenges', () => {
  it('are single use and purpose-bound, with data', async () => {
    const { index } = makeIndex();
    await index.putChallenge('register:signup', 'ch-a', { signupId: 'sig_1', userId: 'usr_1' });
    expect(await index.consumeChallenge('ch-a', 'login')).toBeNull();
    expect(await index.consumeChallenge('ch-a', 'register:signup')).toEqual({
      purpose: 'register:signup', data: { signupId: 'sig_1', userId: 'usr_1' }, expiresAt: START + config.WEBAUTHN_CHALLENGE_TTL,
    });
    expect(await index.consumeChallenge('ch-a', 'register:signup')).toBeNull();
    await index.putChallenge('login', 'ch-b');
    expect(await index.consumeChallenge('ch-b', 'login')).toMatchObject({ data: null });
    expect(await index.consumeChallenge('nope', 'login')).toBeNull();
  });

  it('expire after WEBAUTHN_CHALLENGE_TTL and are swept', async () => {
    const { index, db, getAlarm } = makeIndex();
    await index.putChallenge('login', 'ch-old');
    expect(getAlarm()).toBe(START + config.WEBAUTHN_CHALLENGE_TTL);
    vi.setSystemTime(START + config.WEBAUTHN_CHALLENGE_TTL);
    expect(await index.consumeChallenge('ch-old', 'login')).toBeNull();

    await index.putChallenge('login', 'ch-1');
    vi.setSystemTime(START + 2 * config.WEBAUTHN_CHALLENGE_TTL);
    await index.alarm();
    expect(db.prepare('SELECT challenge FROM challenges').all()).toHaveLength(0);
  });

  it('isActiveUser only for finished accounts', async () => {
    const { index } = makeIndex();
    await index.registerAccount({ userId: 'usr_A', username: 'brad', email: 'b@example.com' });
    expect(await index.isActiveUser('usr_A')).toBe(true);
    expect(await index.isActiveUser('usr_B')).toBe(false);
  });
});
