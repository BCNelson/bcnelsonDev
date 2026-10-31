/**
 * Linked social accounts on a User DO (design §4.2, §6.7). Each is a
 * `credentials` row of type `oauth` with data `{ provider, subject, email }`.
 * The UserIndex `identities` table is the authoritative (provider, subject)
 * → user map and enforces uniqueness across accounts; this module keeps the
 * per-user copy the profile page shows and login checks.
 */

import { config } from '../../config';
import { newId } from '../../crypto/ids';
import type { CreatedSession } from '../../types';
import type { UserContext } from './context';

/** credentials.data for type 'oauth'. */
export interface OAuthCredentialData {
  provider: string;
  subject: string;
  /** The provider's email when linked (informational), or null. */
  email: string | null;
}

/** A linked account as shown on the profile page. Times are epoch ms. */
export interface OAuthCredentialInfo extends OAuthCredentialData {
  id: string;
  label: string;
  createdAt: number;
  lastUsedAt: number | null;
}

export type AddOAuthResult =
  | { ok: true; credential: OAuthCredentialInfo }
  | { ok: false; reason: 'duplicate' | 'too_many' | 'no_profile' };

export type UnlinkOAuthResult =
  | { ok: true; provider: string; subject: string }
  | { ok: false; reason: 'not_found' | 'last_method' };

export type OAuthLoginResult = { ok: true; session: CreatedSession } | { ok: false; reason: 'invalid' };

export interface OAuthLoginContext {
  ip?: string;
  userAgent?: string;
}

/**
 * Credential types that can sign someone in; removing the last one is
 * refused. Same rule (and list) as do/user/passkeys.ts deletePasskey.
 */
const LOGIN_CREDENTIAL_TYPES = ['password', 'passkey', 'oauth'];

const LABEL_MAX_LENGTH = 100;

type CredentialRow = { id: string; label: string | null; data: string; created_at: number; last_used_at: number | null };

/** Store a link the Worker already registered in the UserIndex. */
export function addOAuthCredential(
  ctx: UserContext,
  input: { provider: string; subject: string; email?: string | null; label?: string },
): AddOAuthResult {
  const { sql, now } = ctx;
  if (!input.provider || !input.subject) throw new Error('addOAuthCredential: provider and subject required');
  const data: OAuthCredentialData = { provider: input.provider, subject: input.subject, email: input.email ?? null };
  const label = (input.label ?? input.provider).slice(0, LABEL_MAX_LENGTH);
  return ctx.storage.transactionSync((): AddOAuthResult => {
    const hasProfile = sql.exec<{ n: number }>('SELECT COUNT(*) AS n FROM profile').one().n > 0;
    if (!hasProfile) return { ok: false, reason: 'no_profile' };
    const existing = oauthRows(sql);
    if (existing.some((r) => r.data.provider === data.provider && r.data.subject === data.subject)) {
      return { ok: false, reason: 'duplicate' };
    }
    if (existing.length >= config.MAX_OAUTH_IDENTITIES_PER_ACCOUNT) return { ok: false, reason: 'too_many' };
    const id = newId('cred');
    sql.exec(
      "INSERT INTO credentials (id, type, label, data, created_at) VALUES (?, 'oauth', ?, ?, ?)",
      id, label, JSON.stringify(data), now,
    );
    ctx.audit('oauth.linked', { id, provider: data.provider, subject: data.subject });
    return { ok: true, credential: { id, label, ...data, createdAt: now, lastUsedAt: null } };
  });
}

/** Linked accounts, oldest first. */
export function listOAuthCredentials(ctx: UserContext): OAuthCredentialInfo[] {
  return oauthRows(ctx.sql).map((r) => ({
    id: r.id,
    label: r.label ?? r.data.provider,
    ...r.data,
    createdAt: r.created_at,
    lastUsedAt: r.last_used_at,
  }));
}

/** Remove a linked account unless it is the last way to sign in. The caller releases the index identity. */
export function unlinkOAuth(ctx: UserContext, credentialId: string): UnlinkOAuthResult {
  const { sql } = ctx;
  return ctx.storage.transactionSync((): UnlinkOAuthResult => {
    const row = oauthRows(sql).find((r) => r.id === credentialId);
    if (!row) return { ok: false, reason: 'not_found' };
    const placeholders = LOGIN_CREDENTIAL_TYPES.map(() => '?').join(', ');
    const others = sql.exec<{ n: number }>(
      `SELECT COUNT(*) AS n FROM credentials WHERE id != ? AND type IN (${placeholders})`,
      credentialId, ...LOGIN_CREDENTIAL_TYPES,
    ).one().n;
    if (others === 0) return { ok: false, reason: 'last_method' };
    sql.exec('DELETE FROM credentials WHERE id = ?', credentialId);
    ctx.audit('oauth.unlinked', { id: credentialId, provider: row.data.provider, subject: row.data.subject });
    return { ok: true, provider: row.data.provider, subject: row.data.subject };
  });
}

/**
 * Sign in with a linked account the Worker resolved through the UserIndex.
 * The credential must exist here too. Starts an `oauth:<provider>` session;
 * createSession throws account_disabled for a disabled account.
 */
export async function loginWithOAuth(
  ctx: UserContext,
  provider: string,
  subject: string,
  login: OAuthLoginContext = {},
): Promise<OAuthLoginResult> {
  const row = oauthRows(ctx.sql).find((r) => r.data.provider === provider && r.data.subject === subject);
  if (!row) {
    ctx.audit('login.oauth_failed', { provider, reason: 'unknown_identity', ip: login.ip ?? null });
    return { ok: false, reason: 'invalid' };
  }
  const session = await ctx.createSession({ amr: [`oauth:${provider}`], userAgent: login.userAgent, ip: login.ip });
  ctx.sql.exec('UPDATE credentials SET last_used_at = ? WHERE id = ?', ctx.now, row.id);
  ctx.audit('login.oauth', { id: row.id, provider, ip: login.ip ?? null });
  return { ok: true, session };
}

// --- internals ---------------------------------------------------------------

function oauthRows(sql: SqlStorage): (Omit<CredentialRow, 'data'> & { data: OAuthCredentialData })[] {
  return sql.exec<CredentialRow>(
    "SELECT id, label, data, created_at, last_used_at FROM credentials WHERE type = 'oauth' ORDER BY created_at, id",
  ).toArray().flatMap((r) => {
    const data = parseData(r.data);
    return data ? [{ ...r, data }] : [];
  });
}

function parseData(raw: string): OAuthCredentialData | null {
  try {
    const v = JSON.parse(raw) as Record<string, unknown>;
    if (typeof v?.provider !== 'string' || typeof v.subject !== 'string') return null;
    return { provider: v.provider, subject: v.subject, email: typeof v.email === 'string' ? v.email : null };
  } catch {
    return null;
  }
}
