/**
 * Passkey credentials (design §4.2, §6.3). Each passkey is a `credentials`
 * row of type `passkey` whose `data` is PasskeyData; `passkey_ids` maps the
 * WebAuthn credential ID to that row for login lookups.
 *
 * Registration is verified by the Worker (routes/passkey.ts) because during
 * signup the User DO doesn't exist yet; this module stores the result.
 * Login assertions are verified here, next to the stored public key and
 * counter. Passkey login is not subject to password backoff.
 */

import { verifyAuthenticationResponse, type AuthenticationResponseJSON } from '@simplewebauthn/server';
import { isoBase64URL } from '@simplewebauthn/server/helpers';
import { config } from '../../config';
import { newId } from '../../crypto/ids';
import type { CreatedSession } from '../../types';
import type { UserContext } from './context';

/** credentials.data for type 'passkey'. */
export interface PasskeyData {
  /** WebAuthn credential ID, base64url. */
  credentialId: string;
  /** COSE public key, base64url. */
  publicKey: string;
  counter: number;
  transports: string[];
  aaguid: string;
  backedUp: boolean;
  deviceType: 'singleDevice' | 'multiDevice';
}

/** A verified registration to store; `label` defaults from the AAGUID. */
export type NewPasskey = PasskeyData & { label?: string };

/** A passkey as shown on the profile page. Times are epoch ms. */
export interface PasskeyInfo {
  id: string;
  label: string;
  createdAt: number;
  lastUsedAt: number | null;
  backedUp: boolean;
  deviceType: 'singleDevice' | 'multiDevice';
}

/** For excludeCredentials when registering another passkey. */
export interface PasskeyDescriptor {
  id: string;
  transports: string[];
}

export type AddPasskeyResult =
  | { ok: true; passkey: PasskeyInfo }
  | { ok: false; reason: 'duplicate' | 'too_many' | 'no_profile' };

export type PasskeyChangeResult =
  | { ok: true }
  | { ok: false; reason: 'not_found' | 'invalid_label' | 'last_method' };

export type PasskeyLoginResult = { ok: true; session: CreatedSession } | { ok: false; reason: 'invalid' };

/** Request details for the session a passkey login creates. */
export interface PasskeyLoginContext {
  ip?: string;
  userAgent?: string;
}

/** Credential types that can sign someone in; deleting the last one is refused. */
const LOGIN_CREDENTIAL_TYPES = ['password', 'passkey', 'oauth'];

/** Friendly names for common authenticators by AAGUID (community passkey-authenticator-aaguids list). */
const AAGUID_NAMES: Record<string, string> = {
  'fbfc3007-154e-4ecc-8c0b-6e020557d7bd': 'iCloud Keychain',
  'dd4ec289-e01d-41c9-bb89-70fa845d4bf2': 'iCloud Keychain',
  'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4': 'Google Password Manager',
  'adce0002-35bc-c60a-648b-0b25f1f05503': 'Chrome on Mac',
  '08987058-cadc-4b81-b6e1-30de50dcbe96': 'Windows Hello',
  '9ddd1817-af5a-4672-a2b9-3e3dd95000a9': 'Windows Hello',
  '6028b017-b1d4-4c02-b4b3-afcdafc96bb2': 'Windows Hello',
  'bada5566-a7aa-401f-bd96-45619a55120d': '1Password',
  'd548826e-79b4-db40-a3d8-11116f7e8349': 'Bitwarden',
  '531126d6-e717-415c-9320-3d9aa6981239': 'Dashlane',
  'b84e4048-15dc-4dd0-8640-f4f60813c8af': 'NordPass',
  '0ea242b4-43c4-4a1b-8b17-dd6d0b6baec6': 'Keeper',
  '53414d53-554e-4700-0000-000000000000': 'Samsung Pass',
  'cb69481e-8ff7-4039-93ec-0a2729a154a8': 'YubiKey 5',
  'ee882879-721c-4913-9775-3dfcce97072a': 'YubiKey 5',
  'fa2b99dc-9e39-4257-8f92-4a30d23c4118': 'YubiKey 5',
  '2fc0579f-8113-47ea-b116-bb5a8db9202a': 'YubiKey 5',
};

type CredentialRow = {
  id: string;
  label: string | null;
  data: string;
  created_at: number;
  last_used_at: number | null;
};

/** Default label for a new passkey. */
export function defaultPasskeyLabel(aaguid: string): string {
  return AAGUID_NAMES[aaguid.toLowerCase()] ?? config.PASSKEY_DEFAULT_LABEL;
}

/** Trimmed label, or null when empty, too long, or containing control characters. */
export function normalizePasskeyLabel(label: unknown): string | null {
  if (typeof label !== 'string') return null;
  const trimmed = label.trim().replace(/\s+/g, ' ');
  if (!trimmed || [...trimmed].length > config.PASSKEY_LABEL_MAX_LENGTH) return null;
  if (/[\p{Cc}\p{Cf}]/u.test(trimmed)) return null;
  return trimmed;
}

/** Store a verified registration. Refuses a credential ID that is already registered. */
export function addPasskey(ctx: UserContext, input: NewPasskey): AddPasskeyResult {
  const { sql, now } = ctx;
  const data = passkeyData(input);
  if (!data) throw new Error('addPasskey: invalid passkey data');
  const label = normalizePasskeyLabel(input.label) ?? defaultPasskeyLabel(data.aaguid);
  return ctx.storage.transactionSync((): AddPasskeyResult => {
    const hasProfile = sql.exec<{ n: number }>('SELECT COUNT(*) AS n FROM profile').one().n > 0;
    if (!hasProfile) return { ok: false, reason: 'no_profile' };
    const exists = sql.exec('SELECT 1 FROM passkey_ids WHERE credential_id = ?', data.credentialId).toArray();
    if (exists.length > 0) return { ok: false, reason: 'duplicate' };
    if (countPasskeys(sql) >= config.MAX_PASSKEYS_PER_ACCOUNT) return { ok: false, reason: 'too_many' };
    const id = newId('cred');
    sql.exec(
      "INSERT INTO credentials (id, type, label, data, created_at) VALUES (?, 'passkey', ?, ?, ?)",
      id, label, JSON.stringify(data), now,
    );
    sql.exec('INSERT INTO passkey_ids (credential_id, cred_id) VALUES (?, ?)', data.credentialId, id);
    ctx.audit('passkey.added', { id, label, aaguid: data.aaguid });
    return {
      ok: true,
      passkey: { id, label, createdAt: now, lastUsedAt: null, backedUp: data.backedUp, deviceType: data.deviceType },
    };
  });
}

/** Passkeys, oldest first. */
export function listPasskeys(ctx: UserContext): PasskeyInfo[] {
  return passkeyRows(ctx.sql).flatMap((row) => {
    const data = parseData(row.data);
    if (!data) return [];
    return [{
      id: row.id,
      label: row.label ?? config.PASSKEY_DEFAULT_LABEL,
      createdAt: row.created_at,
      lastUsedAt: row.last_used_at,
      backedUp: data.backedUp,
      deviceType: data.deviceType,
    }];
  });
}

/** Existing passkeys as excludeCredentials entries. */
export function passkeyDescriptors(ctx: UserContext): PasskeyDescriptor[] {
  return passkeyRows(ctx.sql).flatMap((row) => {
    const data = parseData(row.data);
    return data ? [{ id: data.credentialId, transports: data.transports }] : [];
  });
}

export function renamePasskey(ctx: UserContext, id: string, label: string): PasskeyChangeResult {
  const clean = normalizePasskeyLabel(label);
  if (!clean) return { ok: false, reason: 'invalid_label' };
  const written = ctx.sql.exec(
    "UPDATE credentials SET label = ? WHERE id = ? AND type = 'passkey'", clean, id,
  ).rowsWritten;
  if (written === 0) return { ok: false, reason: 'not_found' };
  ctx.audit('passkey.renamed', { id, label: clean });
  return { ok: true };
}

/** Delete a passkey unless it is the account's last way to sign in. */
export function deletePasskey(ctx: UserContext, id: string): PasskeyChangeResult {
  const { sql } = ctx;
  return ctx.storage.transactionSync((): PasskeyChangeResult => {
    const row = sql.exec<{ data: string }>(
      "SELECT data FROM credentials WHERE id = ? AND type = 'passkey'", id,
    ).toArray()[0];
    if (!row) return { ok: false, reason: 'not_found' };
    const placeholders = LOGIN_CREDENTIAL_TYPES.map(() => '?').join(', ');
    const others = sql.exec<{ n: number }>(
      `SELECT COUNT(*) AS n FROM credentials WHERE id != ? AND type IN (${placeholders})`,
      id, ...LOGIN_CREDENTIAL_TYPES,
    ).one().n;
    if (others === 0) return { ok: false, reason: 'last_method' };
    sql.exec('DELETE FROM credentials WHERE id = ?', id);
    sql.exec('DELETE FROM passkey_ids WHERE cred_id = ?', id);
    ctx.audit('passkey.deleted', { id });
    return { ok: true };
  });
}

/**
 * Verify a login assertion against the stored passkey (`expectedChallenge`
 * has already been consumed by the caller), bump the counter and
 * last_used_at, and start an `hwk` session. Unknown credentials and failed
 * verifications are the same `invalid`.
 */
export async function verifyPasskeyLogin(
  ctx: UserContext,
  response: AuthenticationResponseJSON,
  expectedChallenge: string,
  expectedOrigin: string | string[],
  expectedRPID: string,
  login: PasskeyLoginContext = {},
): Promise<PasskeyLoginResult> {
  const { sql, now } = ctx;
  const credentialId = typeof response?.id === 'string' ? response.id : '';
  const found = findPasskey(sql, credentialId);
  if (!found) {
    ctx.audit('login.passkey_failed', { reason: 'unknown_credential', ip: login.ip ?? null });
    return { ok: false, reason: 'invalid' };
  }

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin,
      expectedRPID,
      credential: {
        id: found.data.credentialId,
        publicKey: isoBase64URL.toBuffer(found.data.publicKey),
        counter: found.data.counter,
        transports: found.data.transports,
      },
      requireUserVerification: false,
    });
  } catch (err) {
    ctx.audit('login.passkey_failed', { id: found.id, reason: String((err as Error)?.message ?? err).slice(0, 200), ip: login.ip ?? null });
    return { ok: false, reason: 'invalid' };
  }
  if (!verification.verified) {
    ctx.audit('login.passkey_failed', { id: found.id, reason: 'not_verified', ip: login.ip ?? null });
    return { ok: false, reason: 'invalid' };
  }

  // Re-read after the await; never move the counter backwards.
  const { newCounter, credentialBackedUp } = verification.authenticationInfo;
  const current = findPasskey(sql, credentialId);
  if (!current || current.id !== found.id) return { ok: false, reason: 'invalid' };
  const data: PasskeyData = {
    ...current.data,
    counter: Math.max(current.data.counter, newCounter),
    backedUp: credentialBackedUp,
  };
  sql.exec('UPDATE credentials SET data = ?, last_used_at = ? WHERE id = ?', JSON.stringify(data), now, current.id);
  ctx.audit('login.passkey', { id: current.id, ip: login.ip ?? null });
  const session = await ctx.createSession({ amr: ['hwk'], userAgent: login.userAgent, ip: login.ip });
  return { ok: true, session };
}

// --- internals ---------------------------------------------------------------

function countPasskeys(sql: SqlStorage): number {
  return sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM credentials WHERE type = 'passkey'").one().n;
}

function passkeyRows(sql: SqlStorage): CredentialRow[] {
  return sql.exec<CredentialRow>(
    `SELECT id, label, data, created_at, last_used_at FROM credentials
     WHERE type = 'passkey' ORDER BY created_at, id`,
  ).toArray();
}

function findPasskey(sql: SqlStorage, credentialId: string): { id: string; data: PasskeyData } | null {
  if (!credentialId) return null;
  const row = sql.exec<{ id: string; data: string }>(
    `SELECT c.id, c.data FROM passkey_ids p JOIN credentials c ON c.id = p.cred_id
     WHERE p.credential_id = ? AND c.type = 'passkey'`,
    credentialId,
  ).toArray()[0];
  if (!row) return null;
  const data = parseData(row.data);
  return data ? { id: row.id, data } : null;
}

function parseData(raw: string): PasskeyData | null {
  try {
    return passkeyData(JSON.parse(raw));
  } catch {
    return null;
  }
}

/** Validated PasskeyData fields of `value`, or null. */
function passkeyData(value: unknown): PasskeyData | null {
  if (typeof value !== 'object' || value === null) return null;
  const v = value as Record<string, unknown>;
  if (typeof v.credentialId !== 'string' || !v.credentialId || v.credentialId.length > 1024) return null;
  if (typeof v.publicKey !== 'string' || !v.publicKey || v.publicKey.length > 2048) return null;
  if (typeof v.counter !== 'number' || !Number.isInteger(v.counter) || v.counter < 0) return null;
  const transports = Array.isArray(v.transports) ? v.transports.filter((t): t is string => typeof t === 'string') : [];
  const deviceType = v.deviceType === 'multiDevice' ? 'multiDevice' : 'singleDevice';
  return {
    credentialId: v.credentialId,
    publicKey: v.publicKey,
    counter: v.counter,
    transports,
    aaguid: typeof v.aaguid === 'string' ? v.aaguid : '',
    backedUp: v.backedUp === true,
    deviceType,
  };
}
