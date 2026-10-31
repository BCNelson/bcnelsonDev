/**
 * UserIndex Durable Object (design §4.1): a single instance
 * (`idFromName('index')`) holding username/email/identity lookups and
 * uniqueness, pending signups and WebAuthn challenges. An alarm sweeps
 * expired rows.
 */

import { DurableObject } from 'cloudflare:workers';
import type { Env } from '../env';
import { classifyIdentifier, normalizeEmail, normalizeUsername, validateUsername } from '../identifiers';
import { runMigrations } from './migrations';
import { USER_INDEX_MIGRATIONS } from './schema';
import type { IndexContext } from './index/context';
import {
  type CompleteSignupResult,
  type StartSignupResult,
  type VerifiedSignup,
  type VerifySignupResult,
  completeSignup,
  getVerifiedSignup,
  startSignup,
  verifySignup,
} from './index/signup';
import {
  type DirectoryEntry,
  type DirectoryPage,
  type DirectorySummary,
  type ListDirectoryOptions,
  countActiveAdmins,
  getDirectoryEntry,
  isKnownUser,
  listDirectory,
  missingDirectoryEntries,
  upsertDirectoryEntry,
} from './index/directory';
import { type ChallengeData, type ChallengeRecord, consumeChallenge, isActiveUser, putChallenge } from './index/challenges';
import { type ClaimEmailResult, claimEmail, holdEmail, releaseEmail } from './index/emails';
import { type RenameHandleResult, renameHandle } from './index/handles';
import {
  type ClientChangeResult,
  type CreateClientResult,
  createClient,
  getClient,
  listClients,
  setClientDisabled,
  setClientSecret,
  updateClient,
} from './index/clients';
import type { ClientFields, OAuthClientRecord } from '../oidc/clients';
import {
  type ClaimIdentityResult,
  type CompleteOAuthSignupResult,
  type EmailMatch,
  type OAuthPending,
  type OAuthPendingInput,
  type OAuthPendingKind,
  type StartOAuthSignupResult,
  claimIdentity,
  completeOAuthSignup,
  consumeOAuthLink,
  deleteOAuthPending,
  emailMatch,
  findIdentity,
  getOAuthPending,
  listIdentities,
  putOAuthPending,
  releaseIdentity,
  startOAuthSignup,
  verifyOAuthSignup,
} from './index/identities';

import { nextExpiry, sweepExpired } from './index/maintenance';

export class UserIndex extends DurableObject<Env> {
  private sql: SqlStorage;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    void ctx.blockConcurrencyWhile(async () => {
      runMigrations(ctx.storage, USER_INDEX_MIGRATIONS);
    });
  }

  // --- lookups -------------------------------------------------------------

  /** userId for a login identifier (username or email); active rows only. */
  async resolve(identifier: string): Promise<string | null> {
    const { kind, norm } = classifyIdentifier(identifier);
    const rows = kind === 'email'
      ? this.sql.exec<{ user_id: string }>(
        "SELECT user_id FROM emails WHERE email_norm = ? AND status = 'active'", norm,
      ).toArray()
      : this.sql.exec<{ user_id: string | null }>(
        "SELECT user_id FROM handles WHERE username_norm = ? AND status = 'active'", norm,
      ).toArray();
    return rows[0]?.user_id ?? null;
  }

  /**
   * Whether a normalized username can be claimed: valid, not reserved, and
   * not active, pending or held (expired pending/held rows count as free).
   */
  async isUsernameAvailable(norm: string): Promise<boolean> {
    if (!validateUsername(norm).ok) return false;
    const rows = this.sql.exec<{ status: string; expires_at: number | null }>(
      'SELECT status, expires_at FROM handles WHERE username_norm = ?', norm,
    ).toArray();
    const row = rows[0];
    if (!row) return true;
    if (row.status === 'active') return false;
    return row.expires_at !== null && row.expires_at <= Date.now();
  }

  // --- internal/dev --------------------------------------------------------

  /**
   * Internal/dev: register an active handle + email for an existing User DO
   * in one transaction. This is the final step signup completion will use.
   * Throws if either is already taken.
   */
  async registerAccount(input: { userId: string; username: string; email: string }): Promise<void> {
    const usernameNorm = normalizeUsername(input.username);
    const emailNorm = normalizeEmail(input.email);
    const now = Date.now();
    this.ctx.storage.transactionSync(() => {
      const handle = this.sql.exec<{ status: string; expires_at: number | null }>(
        'SELECT status, expires_at FROM handles WHERE username_norm = ?', usernameNorm,
      ).toArray()[0];
      if (handle && (handle.status === 'active' || (handle.expires_at ?? Infinity) > now)) {
        throw new Error('Username taken');
      }
      const email = this.sql.exec<{ status: string; expires_at: number | null }>(
        'SELECT status, expires_at FROM emails WHERE email_norm = ?', emailNorm,
      ).toArray()[0];
      if (email && (email.status === 'active' || (email.expires_at ?? Infinity) > now)) {
        throw new Error('Email taken');
      }
      this.sql.exec(
        `INSERT OR REPLACE INTO handles (username_norm, user_id, status, expires_at)
         VALUES (?, ?, 'active', NULL)`,
        usernameNorm, input.userId,
      );
      this.sql.exec(
        `INSERT OR REPLACE INTO emails (email_norm, user_id, status, expires_at)
         VALUES (?, ?, 'active', NULL)`,
        emailNorm, input.userId,
      );
    });
  }

  // --- signup --------------------------------------------------------------

  /** Design §6.1 step 1. Same `{ signupId }` whether or not the email is registered. */
  async startSignup(input: { username: string; email: string; ip?: string }): Promise<StartSignupResult> {
    return startSignup(this.context(), input);
  }

  /** Design §6.1 step 2. */
  async verifySignup(signupId: string, code: string): Promise<VerifySignupResult> {
    return verifySignup(this.context(), signupId, code);
  }

  /** A verified signup's userId/username/email, for registering a first credential (passkeys). */
  async getVerifiedSignup(signupId: string): Promise<VerifiedSignup | null> {
    return getVerifiedSignup(this.context(), signupId);
  }

  /** Design §6.1 step 3: create the User DO, then activate handle + email atomically. */
  async completeSignup(signupId: string): Promise<CompleteSignupResult> {
    return completeSignup(this.context(), signupId);
  }

  // --- profile -------------------------------------------------------------

  /** Rename: `to` becomes active for userId, `from` is held for USERNAME_HOLD. */
  async renameHandle(input: { userId: string; from: string; to: string }): Promise<RenameHandleResult> {
    return renameHandle(this.context(), input);
  }

  // --- emails --------------------------------------------------------------

  /** Claim a verified email for an existing user; fails if active/held for another user. */
  async claimEmail(userId: string, email: string): Promise<ClaimEmailResult> {
    return claimEmail(this.context(), userId, email);
  }

  /** After removal: hold this user's address for EMAIL_HOLD. */
  async holdEmail(userId: string, email: string): Promise<boolean> {
    return holdEmail(this.context(), userId, email);
  }

  /** Undo a claim (delete this user's active row). */
  async releaseEmail(userId: string, email: string): Promise<boolean> {
    return releaseEmail(this.context(), userId, email);
  }

  // --- passkeys ------------------------------------------------------------

  /** Store a single-use WebAuthn challenge for WEBAUTHN_CHALLENGE_TTL (swept by the alarm). */
  async putChallenge(purpose: string, challenge: string, data?: ChallengeData): Promise<{ expiresAt: number }> {
    return putChallenge(this.context(), purpose, challenge, data);
  }

  /** Delete-and-return a challenge for `purpose`; null if unknown, used, other purpose or expired. */
  async consumeChallenge(challenge: string, purpose: string): Promise<ChallengeRecord | null> {
    return consumeChallenge(this.context(), challenge, purpose);
  }

  /** True when `userId` has an active handle (a finished account). */
  async isActiveUser(userId: string): Promise<boolean> {
    return isActiveUser(this.context(), userId);
  }

  // --- roles / admin -------------------------------------------------------

  /** Store a User DO's directory summary (User side: do/user/admin.ts syncDirectory). */
  async upsertDirectoryEntry(summary: DirectorySummary): Promise<void> {
    upsertDirectoryEntry(this.sql, summary, Date.now());
  }

  /** One directory row, or null. */
  async getDirectoryEntry(userId: string): Promise<DirectoryEntry | null> {
    return getDirectoryEntry(this.context(), userId);
  }

  /** A page of the directory (cursor by user_id; q = username/email prefix). */
  async listDirectory(opts: ListDirectoryOptions = {}): Promise<DirectoryPage> {
    return listDirectory(this.context(), opts);
  }

  /** Active (not disabled) admins, optionally excluding one user. */
  async countActiveAdmins(excludeUserId?: string): Promise<number> {
    return countActiveAdmins(this.context(), excludeUserId);
  }

  /** True when `userId` is a real account (active handle or directory row). */
  async isKnownUser(userId: string): Promise<boolean> {
    return isKnownUser(this.context(), userId);
  }

  /** Accounts with an active handle but no directory row, for the backfill. */
  async missingDirectoryEntries(limit: number): Promise<{ userIds: string[]; remaining: number }> {
    return missingDirectoryEntries(this.context(), limit);
  }

  // --- oidc ----------------------------------------------------------------

  /** A registered OAuth client (with its secret hash), or null. */
  async getOAuthClient(clientId: string): Promise<OAuthClientRecord | null> {
    return getClient(this.context(), clientId);
  }

  async listOAuthClients(): Promise<OAuthClientRecord[]> {
    return listClients(this.context());
  }

  /** Register a client (fields validated by the Worker). */
  async createOAuthClient(
    input: ClientFields & { clientId: string; confidential: boolean; secretHash: string | null },
  ): Promise<CreateClientResult> {
    return createClient(this.context(), input);
  }

  async updateOAuthClient(clientId: string, fields: ClientFields): Promise<ClientChangeResult> {
    return updateClient(this.context(), clientId, fields);
  }

  async setOAuthClientSecret(clientId: string, secretHash: string): Promise<ClientChangeResult> {
    return setClientSecret(this.context(), clientId, secretHash);
  }

  async setOAuthClientDisabled(clientId: string, disabled: boolean): Promise<ClientChangeResult> {
    return setClientDisabled(this.context(), clientId, disabled);
  }

  // --- social login ----------------------------------------------------------

  /** userId for a provider identity, or null. */
  async findIdentity(provider: string, subject: string): Promise<string | null> {
    return findIdentity(this.context(), provider, subject);
  }

  /** Link an identity to `userId`; `taken` when another account has it. */
  async claimIdentity(input: { provider: string; subject: string; userId: string }): Promise<ClaimIdentityResult> {
    return claimIdentity(this.context(), input);
  }

  /** Unlink (or undo a claim); only `userId`'s own row. */
  async releaseIdentity(provider: string, subject: string, userId: string): Promise<boolean> {
    return releaseIdentity(this.context(), provider, subject, userId);
  }

  async listIdentities(userId: string): Promise<{ provider: string; subject: string }[]> {
    return listIdentities(this.context(), userId);
  }

  /** Whether an address belongs to an active account, is held, or is free. */
  async emailMatch(email: string): Promise<EmailMatch> {
    return emailMatch(this.context(), email);
  }

  /** Store a pending link/signup; returns the cookie handle. */
  async putOAuthPending(input: OAuthPendingInput): Promise<{ handle: string; expiresAt: number }> {
    return putOAuthPending(this.context(), input);
  }

  async getOAuthPending(handle: string, kind: OAuthPendingKind): Promise<OAuthPending | null> {
    return getOAuthPending(this.context(), handle, kind);
  }

  /** Take a pending link, only for the user it was offered to. */
  async consumeOAuthLink(handle: string, userId: string): Promise<OAuthPending | null> {
    return consumeOAuthLink(this.context(), handle, userId);
  }

  async deleteOAuthPending(handle: string): Promise<void> {
    return deleteOAuthPending(this.context(), handle);
  }

  /** Social signup: reserve a username (verified provider email → no code; else the email-code flow). */
  async startOAuthSignup(handle: string, input: { username: string; email?: string; ip?: string }): Promise<StartOAuthSignupResult> {
    return startOAuthSignup(this.context(), handle, input);
  }

  async verifyOAuthSignup(handle: string, code: string) {
    return verifyOAuthSignup(this.context(), handle, code);
  }

  /** Create the account; handle, email and identity are claimed in one transaction. */
  async completeOAuthSignup(handle: string): Promise<CompleteOAuthSignupResult> {
    return completeOAuthSignup(this.context(), handle);
  }

  // --- context ---------------------------------------------------------------

  /** Context for the feature modules in ./index/. */
  private context(): IndexContext {
    return {
      sql: this.sql,
      storage: this.ctx.storage,
      env: this.env,
      now: Date.now(),
      scheduleSweep: (at) => this.scheduleSweep(at),
    };
  }

  // --- expiry sweep --------------------------------------------------------

  /** Delete expired rows in every expiring table (index/maintenance.ts EXPIRING); reschedule. */
  override async alarm(): Promise<void> {
    sweepExpired(this.context());
    const next = nextExpiry(this.sql);
    if (next !== null) await this.ctx.storage.setAlarm(next);
  }

  /** Make sure the sweeper runs by `at`. Call whenever an expiring row is written. */
  private async scheduleSweep(at: number): Promise<void> {
    const current = await this.ctx.storage.getAlarm();
    if (current === null || current > at) await this.ctx.storage.setAlarm(at);
  }
}
