/**
 * Social login in the UserIndex (design §4.1 `identities`, §6.7).
 *
 * identities     (provider, provider_subject) → user_id; at most one account per
 *                provider identity, MAX_OAUTH_IDENTITIES_PER_ACCOUNT per account.
 * oauth_pending  the two states a callback can leave behind, each addressed by a
 *                random handle (stored as SHA-256) that the browser keeps in an
 *                HttpOnly cookie:
 *   - 'link':   the provider's verified email belongs to an existing account.
 *               Never auto-linked: the handle is consumed only by that same
 *               user after signing in (consumeOAuthLink).
 *   - 'signup': unknown identity, no matching account. The user picks a
 *               username; a verified provider email reserves the handle with an
 *               already-verified pending_signups row (no code), otherwise the
 *               normal email-code signup runs (startSignup/verifySignup).
 *               completeOAuthSignup finishes through completeSignup, which
 *               claims handle + email + identity in one transaction.
 * Rows expire (OAUTH_LINK_TTL / OAUTH_SIGNUP_TTL) and are swept by the alarm
 * (maintenance.ts EXPIRING).
 */

import { config } from '../../config';
import { sha256Base64url } from '../../crypto/hash';
import { newId, randomToken } from '../../crypto/ids';
import { normalizeEmail, validateEmail, validateUsername } from '../../identifiers';
import { isLive, type IndexContext } from './context';
import {
  completeSignup,
  startSignup,
  verifySignup,
  type VerifySignupResult,
} from './signup';

export type ClaimIdentityResult = { ok: true } | { ok: false; reason: 'taken' | 'too_many' };

export type EmailMatch = { kind: 'active'; userId: string } | { kind: 'held' } | { kind: 'free' };

export type OAuthPendingKind = 'signup' | 'link';

/** Optional provider profile bits kept with a pending record. */
export interface OAuthPendingData {
  name?: string;
  picture?: string;
  username?: string;
}

export interface OAuthPendingInput {
  kind: OAuthPendingKind;
  provider: string;
  subject: string;
  email?: string;
  emailVerified: boolean;
  /** kind 'link': the account the email matched. */
  userId?: string;
  data?: OAuthPendingData;
}

export interface OAuthPending {
  kind: OAuthPendingKind;
  provider: string;
  subject: string;
  email: string | null;
  emailVerified: boolean;
  userId: string | null;
  /** kind 'signup': the reserved signup, once a username was chosen. */
  signupId: string | null;
  /** kind 'signup': whether that signup is verified (code entered, or provider-verified). */
  signupVerified: boolean;
  /** kind 'signup': the username/email reserved, once chosen. */
  username: string | null;
  signupEmail: string | null;
  data: OAuthPendingData;
  expiresAt: number;
}

export type StartOAuthSignupResult =
  | { ok: true; verified: boolean }
  | {
    ok: false;
    reason: 'not_found' | 'invalid_username' | 'invalid_email' | 'username_taken' | 'email_taken' | 'rate_limited';
    retryAfterMs?: number;
  };

export type CompleteOAuthSignupResult =
  | {
    ok: true;
    userId: string;
    username: string;
    email: string;
    provider: string;
    subject: string;
    /** The provider's email (credential data), which may differ from the account email. */
    providerEmail: string | null;
    data: OAuthPendingData;
  }
  | { ok: false; reason: 'not_found' | 'not_verified' | 'conflict' };

type PendingRow = {
  id_hash: string;
  kind: OAuthPendingKind;
  provider: string;
  provider_subject: string;
  email: string | null;
  email_verified: number;
  user_id: string | null;
  signup_id: string | null;
  data: string | null;
  expires_at: number;
};

const MAX_HANDLE_LENGTH = 128;

// --- identities --------------------------------------------------------------

/** The account a provider identity belongs to, or null. */
export function findIdentity(ctx: IndexContext, provider: string, subject: string): string | null {
  return ctx.sql.exec<{ user_id: string }>(
    'SELECT user_id FROM identities WHERE provider = ? AND provider_subject = ?', provider, subject,
  ).toArray()[0]?.user_id ?? null;
}

/** Register an identity for `userId`. Idempotent for the same user; `taken` if another user has it. */
export function claimIdentity(
  ctx: IndexContext,
  input: { provider: string; subject: string; userId: string },
): ClaimIdentityResult {
  const { sql } = ctx;
  return ctx.storage.transactionSync((): ClaimIdentityResult => {
    const owner = findIdentity(ctx, input.provider, input.subject);
    if (owner === input.userId) return { ok: true };
    if (owner !== null) return { ok: false, reason: 'taken' };
    const count = sql.exec<{ n: number }>('SELECT COUNT(*) AS n FROM identities WHERE user_id = ?', input.userId).one().n;
    if (count >= config.MAX_OAUTH_IDENTITIES_PER_ACCOUNT) return { ok: false, reason: 'too_many' };
    sql.exec(
      'INSERT INTO identities (provider, provider_subject, user_id) VALUES (?, ?, ?)',
      input.provider, input.subject, input.userId,
    );
    return { ok: true };
  });
}

/** Remove `userId`'s identity (unlink, or undoing a claim). False if it isn't theirs. */
export function releaseIdentity(ctx: IndexContext, provider: string, subject: string, userId: string): boolean {
  return ctx.sql.exec(
    'DELETE FROM identities WHERE provider = ? AND provider_subject = ? AND user_id = ?', provider, subject, userId,
  ).rowsWritten > 0;
}

/** Identities registered for `userId`. */
export function listIdentities(ctx: IndexContext, userId: string): { provider: string; subject: string }[] {
  return ctx.sql.exec<{ provider: string; provider_subject: string }>(
    'SELECT provider, provider_subject FROM identities WHERE user_id = ? ORDER BY provider, provider_subject', userId,
  ).toArray().map((r) => ({ provider: r.provider, subject: r.provider_subject }));
}

/** Who (if anyone) owns this address: an active account, a post-removal hold, or nobody. */
export function emailMatch(ctx: IndexContext, email: string): EmailMatch {
  const row = ctx.sql.exec<{ user_id: string; status: string; expires_at: number | null }>(
    'SELECT user_id, status, expires_at FROM emails WHERE email_norm = ?', normalizeEmail(email),
  ).toArray()[0];
  if (!row || !isLive(row.status, row.expires_at, ctx.now)) return { kind: 'free' };
  return row.status === 'active' ? { kind: 'active', userId: row.user_id } : { kind: 'held' };
}

// --- pending records ---------------------------------------------------------

/** Store a pending link/signup; returns the bearer handle for the browser's cookie. */
export async function putOAuthPending(
  ctx: IndexContext,
  input: OAuthPendingInput,
): Promise<{ handle: string; expiresAt: number }> {
  if (input.kind === 'link' && !input.userId) throw new Error('putOAuthPending: link needs userId');
  const handle = randomToken(32);
  const idHash = await sha256Base64url(handle);
  const expiresAt = ctx.now + (input.kind === 'link' ? config.OAUTH_LINK_TTL : config.OAUTH_SIGNUP_TTL);
  ctx.sql.exec(
    `INSERT INTO oauth_pending (id_hash, kind, provider, provider_subject, email, email_verified,
       user_id, signup_id, data, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)`,
    idHash, input.kind, input.provider, input.subject, input.email ?? null, input.emailVerified ? 1 : 0,
    input.userId ?? null, JSON.stringify(input.data ?? {}), expiresAt,
  );
  await ctx.scheduleSweep(expiresAt);
  return { handle, expiresAt };
}

/** A live pending record of `kind`, or null. */
export async function getOAuthPending(
  ctx: IndexContext,
  handle: string,
  kind: OAuthPendingKind,
): Promise<OAuthPending | null> {
  const row = await pendingRow(ctx, handle, kind);
  return row ? toPending(ctx.sql, row) : null;
}

/**
 * Take a pending link if it is for `userId` (who has just signed in).
 * Another user's handle is left in place and gives null.
 */
export async function consumeOAuthLink(ctx: IndexContext, handle: string, userId: string): Promise<OAuthPending | null> {
  const row = await pendingRow(ctx, handle, 'link');
  if (!row || row.user_id !== userId) return null;
  ctx.sql.exec('DELETE FROM oauth_pending WHERE id_hash = ?', row.id_hash);
  return toPending(ctx.sql, row);
}

/** Drop a pending record (e.g. the user cancelled). */
export async function deleteOAuthPending(ctx: IndexContext, handle: string): Promise<void> {
  if (!handle || handle.length > MAX_HANDLE_LENGTH) return;
  ctx.sql.exec('DELETE FROM oauth_pending WHERE id_hash = ?', await sha256Base64url(handle));
}

// --- social signup -----------------------------------------------------------

/**
 * Reserve `username` for a pending social signup. With a provider-verified
 * email the reservation is already verified; otherwise `email` (default:
 * the provider's) gets the normal signup code (or the already-registered
 * notice). Choosing again releases the previous reservation first.
 */
export async function startOAuthSignup(
  ctx: IndexContext,
  handle: string,
  input: { username: string; email?: string; ip?: string },
): Promise<StartOAuthSignupResult> {
  const row = await pendingRow(ctx, handle, 'signup');
  if (!row) return { ok: false, reason: 'not_found' };
  const username = validateUsername(input.username);
  if (!username.ok) return { ok: false, reason: 'invalid_username' };

  if (row.email_verified === 1 && row.email) {
    const email = validateEmail(row.email);
    if (!email.ok) return { ok: false, reason: 'invalid_email' };
    const deadHash = await sha256Base64url(randomToken());
    const { sql } = ctx;
    const now = Date.now();
    const outcome = ctx.storage.transactionSync(() => {
      releaseReservation(sql, row.signup_id);
      const handleRow = sql.exec<{ status: string; expires_at: number | null }>(
        'SELECT status, expires_at FROM handles WHERE username_norm = ?', username.norm,
      ).toArray()[0];
      if (handleRow && isLive(handleRow.status, handleRow.expires_at, now)) return 'username_taken' as const;
      const emailRow = sql.exec<{ status: string; expires_at: number | null }>(
        'SELECT status, expires_at FROM emails WHERE email_norm = ?', email.norm,
      ).toArray()[0];
      if (emailRow && isLive(emailRow.status, emailRow.expires_at, now)) return 'email_taken' as const;
      const expiresAt = Math.min(row.expires_at, now + config.SIGNUP_TTL);
      const signupId = newId('sig');
      sql.exec('DELETE FROM pending_signups WHERE username_norm = ?', username.norm);
      sql.exec(
        `INSERT OR REPLACE INTO handles (username_norm, user_id, status, expires_at)
         VALUES (?, NULL, 'pending', ?)`,
        username.norm, expiresAt,
      );
      // Verified by the provider: no code exists (a random hash nothing matches).
      sql.exec(
        `INSERT INTO pending_signups (signup_id, username, username_norm, email, email_norm,
           code_hash, attempts, verified_at, expires_at, user_id, code_expires_at)
         VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)`,
        signupId, username.display, username.norm, email.display, email.norm,
        deadHash, now, expiresAt, newId('usr'), expiresAt,
      );
      sql.exec('UPDATE oauth_pending SET signup_id = ? WHERE id_hash = ?', signupId, row.id_hash);
      return { expiresAt };
    });
    if (typeof outcome === 'string') return { ok: false, reason: outcome };
    await ctx.scheduleSweep(outcome.expiresAt);
    return { ok: true, verified: true };
  }

  const emailInput = input.email ?? row.email ?? '';
  if (!validateEmail(emailInput).ok) return { ok: false, reason: 'invalid_email' };
  ctx.storage.transactionSync(() => releaseReservation(ctx.sql, row.signup_id));
  const started = await startSignup(ctx, { username: input.username, email: emailInput, ip: input.ip });
  if (!started.ok) return { ok: false, reason: started.reason, retryAfterMs: started.retryAfterMs };
  ctx.sql.exec('UPDATE oauth_pending SET signup_id = ? WHERE id_hash = ?', started.signupId, row.id_hash);
  return { ok: true, verified: false };
}

/** The email code step for an unverified social signup. */
export async function verifyOAuthSignup(
  ctx: IndexContext,
  handle: string,
  code: string,
): Promise<VerifySignupResult | { ok: false; reason: 'not_found' }> {
  const row = await pendingRow(ctx, handle, 'signup');
  if (!row?.signup_id) return { ok: false, reason: 'not_found' };
  return verifySignup(ctx, row.signup_id, code);
}

/**
 * Create the account: completeSignup with the identity claimed in the same
 * transaction as handle + email. The caller then attaches the oauth
 * credential to the new User DO.
 */
export async function completeOAuthSignup(ctx: IndexContext, handle: string): Promise<CompleteOAuthSignupResult> {
  const row = await pendingRow(ctx, handle, 'signup');
  if (!row) return { ok: false, reason: 'not_found' };
  if (!row.signup_id) return { ok: false, reason: 'not_verified' };
  const created = await completeSignup(ctx, row.signup_id, {
    identity: { provider: row.provider, subject: row.provider_subject },
  });
  if (!created.ok) return { ok: false, reason: created.reason === 'conflict' ? 'conflict' : created.reason === 'not_verified' ? 'not_verified' : 'not_found' };
  ctx.sql.exec('DELETE FROM oauth_pending WHERE id_hash = ?', row.id_hash);
  return {
    ok: true,
    userId: created.userId,
    username: created.username,
    email: created.email,
    provider: row.provider,
    subject: row.provider_subject,
    providerEmail: row.email,
    data: parseData(row.data),
  };
}

// --- internals ---------------------------------------------------------------

async function pendingRow(ctx: IndexContext, handle: string, kind: OAuthPendingKind): Promise<PendingRow | null> {
  if (!handle || handle.length > MAX_HANDLE_LENGTH) return null;
  const idHash = await sha256Base64url(handle);
  const row = ctx.sql.exec<PendingRow>('SELECT * FROM oauth_pending WHERE id_hash = ?', idHash).toArray()[0];
  if (!row || row.kind !== kind || row.expires_at <= Date.now()) return null;
  return row;
}

function toPending(sql: SqlStorage, row: PendingRow): OAuthPending {
  const signup = row.signup_id
    ? sql.exec<{ username: string; email: string; verified_at: number | null; expires_at: number }>(
      'SELECT username, email, verified_at, expires_at FROM pending_signups WHERE signup_id = ?', row.signup_id,
    ).toArray()[0]
    : undefined;
  const live = signup && signup.expires_at > Date.now() ? signup : undefined;
  return {
    kind: row.kind,
    provider: row.provider,
    subject: row.provider_subject,
    email: row.email,
    emailVerified: row.email_verified === 1,
    userId: row.user_id,
    signupId: live ? row.signup_id : null,
    signupVerified: live?.verified_at != null,
    username: live?.username ?? null,
    signupEmail: live?.email ?? null,
    data: parseData(row.data),
    expiresAt: row.expires_at,
  };
}

/** Free a previous username reservation of this social signup (never an account's handle). */
function releaseReservation(sql: SqlStorage, signupId: string | null): void {
  if (!signupId) return;
  const prior = sql.exec<{ username_norm: string }>(
    'SELECT username_norm FROM pending_signups WHERE signup_id = ?', signupId,
  ).toArray()[0];
  if (!prior) return;
  sql.exec('DELETE FROM pending_signups WHERE signup_id = ?', signupId);
  sql.exec(
    "DELETE FROM handles WHERE username_norm = ? AND status = 'pending' AND user_id IS NULL",
    prior.username_norm,
  );
}

function parseData(raw: string | null): OAuthPendingData {
  try {
    const v: unknown = raw ? JSON.parse(raw) : {};
    if (!v || typeof v !== 'object') return {};
    const r = v as Record<string, unknown>;
    const out: OAuthPendingData = {};
    if (typeof r.name === 'string') out.name = r.name;
    if (typeof r.picture === 'string') out.picture = r.picture;
    if (typeof r.username === 'string') out.username = r.username;
    return out;
  } catch {
    return {};
  }
}
