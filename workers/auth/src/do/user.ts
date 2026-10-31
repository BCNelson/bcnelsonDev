/**
 * User Durable Object (design §4.2): one per user, addressed by
 * `idFromName(userId)`. Owns profile, emails, credentials, sessions,
 * limits and the audit log. The DO knows its own userId from the profile
 * row (set by initProfile), never from ctx.id.name.
 */

import { DurableObject } from 'cloudflare:workers';
import { config } from '../config';
import { sha256Base64url } from '../crypto/hash';
import { newId, randomToken } from '../crypto/ids';
import type { Env } from '../env';
import { normalizeEmail } from '../identifiers';
import type {
  CreatedSession,
  PasswordLoginContext,
  PasswordLoginResult,
  RefreshResult,
  SessionContext,
  UserClaims,
} from '../types';
import { runMigrations } from './migrations';
import { USER_MIGRATIONS } from './schema';
import type { UserContext } from './user/context';
import { loginWithPassword, setPassword } from './user/password';
import { ensureRole } from './user/roles';
import {
  type AccountInfo,
  type ChangePasswordResult,
  type ChangeUsernameResult,
  type CredentialInfo,
  type ProfileUpdate,
  type UpdateProfileResult,
  changePassword,
  changeUsername,
  getAccount,
  listCredentials,
  updateProfile,
} from './user/profile';
import {
  type RemoveEmailResult,
  type SetPrimaryEmailResult,
  type StartAddEmailResult,
  type VerifyAddEmailResult,
  removeEmail,
  setPrimaryEmail,
  startAddEmail,
  verifyAddEmail,
} from './user/emails';
import type { AuthenticationResponseJSON } from '@simplewebauthn/server';
import {
  type AddPasskeyResult,
  type NewPasskey,
  type PasskeyChangeResult,
  type PasskeyDescriptor,
  type PasskeyInfo,
  type PasskeyLoginContext,
  type PasskeyLoginResult,
  addPasskey,
  deletePasskey,
  listPasskeys,
  passkeyDescriptors,
  renamePasskey,
  verifyPasskeyLogin,
} from './user/passkeys';
import { type PruneResult, prune, pruneIfDue } from './user/maintenance';
import {
  type AddOAuthResult,
  type OAuthCredentialInfo,
  type OAuthLoginContext,
  type OAuthLoginResult,
  type UnlinkOAuthResult,
  addOAuthCredential,
  listOAuthCredentials,
  loginWithOAuth,
  unlinkOAuth,
} from './user/oauth';
import {
  createCode,
  rebindSessionTokens,
  getGrant,
  listGrants,
  redeemCode,
  refreshGrant,
  revokeClient,
  saveGrant,
  startConsent,
  takeConsent,
  tokenClaims,
} from './user/oidc';
import type {
  AuthorizeRequest,
  CreateCodeInput,
  CreateCodeResult,
  OAuthGrantInfo,
  RedeemCodeInput,
  RedeemCodeResult,
  RefreshGrantInput,
  RefreshGrantResult,
} from '../oidc/types';
import {
  type RequestResetResult,
  type ResetPasswordResult,
  checkResetToken,
  requestPasswordReset,
  resetPassword,
} from './user/reset';
import {
  type AdminUserDetail,
  type SetDisabledResult,
  type SetRolesResult,
  adminDetail,
  assertNotDisabled,
  getRoles,
  isAccountDisabledError,
  readDisabledAt,
  revokeSessionsByAdmin,
  setDisabled,
  setRoles,
  syncDirectory,
  syncDirectorySafe,
} from './user/admin';
import {
  type ProfileRow,
  type SessionSecrets,
  buildClaims,
  decideRefresh,
  parseStringArray,
  rotatedSecrets,
} from './sessions';

type SessionRow = SessionSecrets & {
  id: string;
  created_at: number;
  last_seen_at: number;
  auth_time: number;
  amr: string;
  user_agent: string | null;
  ip: string | null;
};

/** A session as shown on the profile page. Times are epoch ms. */
export interface SessionInfo {
  id: string;
  createdAt: number;
  lastSeenAt: number;
  authTime: number;
  amr: string[];
  userAgent: string | null;
  ip: string | null;
  expiresAt: number;
}

export class User extends DurableObject<Env> {
  /** True once this instance has run (or confirmed) the schema migrations. */
  private migrated = false;

  /**
   * The schema is created lazily, on first SQL use, not in the constructor.
   * Tokens (rt1 / pr1 / ac1 / crt1) carry a userId the Worker routes on
   * before anything is verified, so a forged but well-formed token reaches a
   * User DO that may never have existed. The entry points those tokens hit
   * check `exists()` first (a read of sqlite_master, which writes nothing)
   * and answer "invalid" for a DO with no schema, so such requests never
   * persist storage. Everything else goes through `this.sql`, which migrates
   * on first use (initProfile at signup is the first real write).
   * Migrations are synchronous, so running them inside a method (no await)
   * is as atomic as running them in blockConcurrencyWhile.
   */
  private get sql(): SqlStorage {
    if (!this.migrated) {
      runMigrations(this.ctx.storage, USER_MIGRATIONS);
      this.migrated = true;
    }
    return this.ctx.storage.sql;
  }

  /** True when this DO has a schema (was ever initialised). Writes nothing. */
  private exists(): boolean {
    if (this.migrated) return true;
    const found = this.ctx.storage.sql.exec(
      "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = '_migrations'",
    ).toArray().length > 0;
    return found;
  }

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
  }

  // --- profile ---------------------------------------------------------

  /**
   * Internal/dev: create the profile and its verified primary email. Used by
   * tests and by signup completion. Throws if a profile already exists.
   */
  async initProfile(input: { userId: string; username: string; email: string }): Promise<void> {
    const now = Date.now();
    this.ctx.storage.transactionSync(() => {
      if (this.profile()) throw new Error('Profile already exists');
      this.sql.exec(
        'INSERT INTO profile (user_id, username, created_at) VALUES (?, ?, ?)',
        input.userId, input.username, now,
      );
      this.sql.exec(
        'INSERT INTO emails (email, verified_at, is_primary) VALUES (?, ?, 1)',
        normalizeEmail(input.email), now,
      );
      this.writeAudit('profile.created', { username: input.username }, now);
    });
  }

  /** Profile page / GET /api/me: profile, emails, pending emails, sessions, credential summaries. */
  async getAccount(): Promise<AccountInfo> {
    return getAccount(this.context(), await this.listSessions());
  }

  /** Display name / avatar URL; absent fields unchanged, '' or null clears. */
  async updateProfile(update: ProfileUpdate): Promise<UpdateProfileResult> {
    return updateProfile(this.context(), update);
  }

  /** Rename (cooldown, UserIndex.renameHandle with a hold on the old handle). */
  async changeUsername(username: string): Promise<ChangeUsernameResult> {
    return changeUsername(this.context(), username);
  }

  /** Credential summaries (id, type, label, times); never `data`. */
  async listCredentials(): Promise<CredentialInfo[]> {
    return listCredentials(this.sql);
  }

  /**
   * Profile-page password set/change: checks `currentPassword` when one is
   * set, stores `hash`, revokes every session but `keepSessionId`, alerts.
   */
  async changePassword(input: { currentPassword?: string; hash: string; keepSessionId?: string }): Promise<ChangePasswordResult> {
    return changePassword(this.context(), input);
  }

  // --- emails ------------------------------------------------------------

  /** Start adding an address: limits, pending row, code mailed to it. */
  async startAddEmail(email: string): Promise<StartAddEmailResult> {
    return startAddEmail(this.context(), email);
  }

  /** Check the code, claim the address in the UserIndex, add it, alert. */
  async verifyAddEmail(email: string, code: string): Promise<VerifyAddEmailResult> {
    return verifyAddEmail(this.context(), email, code);
  }

  /** Make a verified address primary; alerts every address. */
  async setPrimaryEmail(email: string): Promise<SetPrimaryEmailResult> {
    return setPrimaryEmail(this.context(), email);
  }

  /** Remove an address (never the last; the primary needs `newPrimary`); held in the index. */
  async removeEmail(email: string, newPrimary?: string): Promise<RemoveEmailResult> {
    return removeEmail(this.context(), email, newPrimary);
  }

  // --- sessions ----------------------------------------------------------

  /**
   * Start a session after an interactive login. Throws if there is no
   * profile, or `account_disabled` (user/admin.ts isAccountDisabledError) if
   * the account is disabled.
   */
  async createSession(ctx: SessionContext): Promise<CreatedSession> {
    const profile = this.requireProfile();
    const now = Date.now();
    const sessionId = newId('ses');
    const secret = randomToken();
    const secretHash = await sha256Base64url(secret);
    const amr = JSON.stringify(ctx.amr);
    // After the await, so the check and the insert run without interleaving.
    assertNotDisabled(this.sql);
    this.ctx.storage.transactionSync(() => {
      this.sql.exec(
        `INSERT INTO sessions (id, secret_hash, created_at, last_seen_at, auth_time, amr,
           user_agent, ip, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        sessionId, secretHash, now, now, now, amr,
        ctx.userAgent ?? null, ctx.ip ?? null, now + config.REFRESH_TOKEN_TTL,
      );
      this.writeAudit('session.created', { sessionId, amr: ctx.amr, ip: ctx.ip ?? null }, now);
    });
    this.maintainQuietly();
    const claims = buildClaims(profile, this.primaryEmail(), { id: sessionId, auth_time: now, amr });
    return { sessionId, secret, claims };
  }

  /**
   * Rotate a refresh secret (design §3.2). The previous secret stays valid
   * for REFRESH_GRACE; presenting it later revokes the session (reuse).
   */
  async refreshSession(sessionId: string, secret: string): Promise<RefreshResult> {
    if (!this.exists()) return { ok: false, reason: 'invalid' };
    const presentedHash = await sha256Base64url(secret);
    const newSecret = randomToken();
    const newHash = await sha256Base64url(newSecret);
    // No awaits below: the read-decide-write runs atomically within the DO.
    const now = Date.now();
    const row = this.session(sessionId);
    const decision = decideRefresh(row, presentedHash, now);
    if (decision.action === 'reject') return { ok: false, reason: decision.reason };
    if (readDisabledAt(this.sql) !== null) return { ok: false, reason: 'revoked' };
    if (decision.action === 'reuse') {
      this.ctx.storage.transactionSync(() => {
        this.sql.exec('UPDATE sessions SET revoked_at = ? WHERE id = ?', now, sessionId);
        this.writeAudit('session.reuse_detected', { sessionId }, now);
      });
      return { ok: false, reason: 'reuse' };
    }
    if (decision.action === 'grace') {
      this.sql.exec('UPDATE sessions SET last_seen_at = ? WHERE id = ?', now, sessionId);
      return { ok: true, claims: buildClaims(this.requireProfile(), this.primaryEmail(), row!) };
    }
    const next = rotatedSecrets(row!, newHash, now);
    this.sql.exec(
      `UPDATE sessions SET secret_hash = ?, prev_secret_hash = ?, prev_valid_until = ?,
         expires_at = ?, last_seen_at = ? WHERE id = ?`,
      next.secret_hash, next.prev_secret_hash, next.prev_valid_until,
      next.expires_at, next.last_seen_at, sessionId,
    );
    const claims = buildClaims(this.requireProfile(), this.primaryEmail(), row!);
    return { ok: true, secret: newSecret, claims };
  }

  /**
   * Revoke one session. No-op if unknown or already revoked. With `secret`
   * (logout), revoke only if it matches the current or in-grace previous
   * secret, since sid alone is public (it is in the JWT). Without `secret`
   * (owner revoking from the profile page), revoke unconditionally.
   */
  async revokeSession(sessionId: string, secret?: string): Promise<void> {
    if (!this.exists()) return;
    const presentedHash = secret === undefined ? null : await sha256Base64url(secret);
    const now = Date.now();
    if (presentedHash !== null) {
      const { action } = decideRefresh(this.session(sessionId), presentedHash, now);
      if (action !== 'rotate' && action !== 'grace') return;
    }
    this.ctx.storage.transactionSync(() => {
      const cursor = this.sql.exec(
        'UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL', now, sessionId,
      );
      if (cursor.rowsWritten > 0) this.writeAudit('session.revoked', { sessionId }, now);
    });
  }

  /**
   * A re-login in the same browser (completeLogin): revoke `previousSessionId`
   * (only when `secret` is its current or in-grace secret, as for logout) and
   * move its live OIDC client tokens to `newSessionId`, so third-party apps
   * stay connected. Logout, password reset, admin revoke and disable still
   * end those tokens. No-op when the secret doesn't match or the new session
   * isn't live.
   */
  async supersedeSession(previousSessionId: string, secret: string, newSessionId: string): Promise<void> {
    if (!this.exists()) return;
    const presentedHash = await sha256Base64url(secret);
    const now = Date.now();
    const { action } = decideRefresh(this.session(previousSessionId), presentedHash, now);
    if (action !== 'rotate' && action !== 'grace') return;
    const next = this.session(newSessionId);
    const context = this.context();
    this.ctx.storage.transactionSync(() => {
      if (next && next.revoked_at === null && next.expires_at > now) {
        rebindSessionTokens(context, previousSessionId, newSessionId);
      }
      const cursor = this.sql.exec(
        'UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL', now, previousSessionId,
      );
      if (cursor.rowsWritten > 0) this.writeAudit('session.superseded', { sessionId: previousSessionId, by: newSessionId }, now);
    });
  }

  /** Active (not revoked, not expired) sessions, most recently seen first. */
  async listSessions(): Promise<SessionInfo[]> {
    const rows = this.sql.exec<SessionRow>(
      `SELECT * FROM sessions WHERE revoked_at IS NULL AND expires_at > ?
       ORDER BY last_seen_at DESC`,
      Date.now(),
    ).toArray();
    return rows.map((r) => ({
      id: r.id,
      createdAt: r.created_at,
      lastSeenAt: r.last_seen_at,
      authTime: r.auth_time,
      amr: parseStringArray(r.amr),
      userAgent: r.user_agent,
      ip: r.ip,
      expiresAt: r.expires_at,
    }));
  }

  /** Revoke every active session, optionally keeping one. Returns how many were revoked. */
  async revokeAllSessions(exceptSessionId?: string): Promise<number> {
    const now = Date.now();
    return this.ctx.storage.transactionSync(() => {
      const cursor = this.sql.exec(
        'UPDATE sessions SET revoked_at = ? WHERE revoked_at IS NULL AND id IS NOT ?',
        now, exceptSessionId ?? null,
      );
      const count = cursor.rowsWritten;
      this.writeAudit('session.revoked_all', { except: exceptSessionId ?? null, count }, now);
      return count;
    });
  }

  /** Claims for an active session, or null if it is revoked, expired, unknown or the account is disabled. */
  async getClaims(sessionId: string): Promise<UserClaims | null> {
    if (!this.exists()) return null;
    const row = this.session(sessionId);
    if (!row || row.revoked_at !== null || row.expires_at <= Date.now()) return null;
    if (readDisabledAt(this.sql) !== null) return null;
    return buildClaims(this.requireProfile(), this.primaryEmail(), row);
  }

  // --- audit -------------------------------------------------------------

  /** Append an audit_log entry. */
  async audit(event: string, detail?: unknown): Promise<void> {
    this.writeAudit(event, detail, Date.now());
  }

  // --- password ----------------------------------------------------------

  /** Set or replace the password (`hash` from crypto/password hashPassword). Clears backoff. */
  async setPassword(hash: string): Promise<void> {
    setPassword(this.context(), hash);
  }

  /** Design §6.2: backoff, verify, rehash if outdated, record the attempt, create a session. */
  async loginWithPassword(password: string, ctx: PasswordLoginContext): Promise<PasswordLoginResult> {
    try {
      return await loginWithPassword(this.context(), password, ctx);
    } catch (err) {
      // Only reached after the password verified (createSession refused).
      if (!isAccountDisabledError(err)) throw err;
      this.writeAudit('login.blocked_disabled', { method: 'password', ip: ctx.ip ?? null }, Date.now());
      return { ok: false, reason: 'disabled' };
    }
  }

  // --- roles -------------------------------------------------------------

  /** Add a config.ROLES role if missing (ADMIN_EMAILS bootstrap). True when added. */
  async ensureRole(role: string, reason = 'bootstrap'): Promise<boolean> {
    const context = this.context();
    const added = ensureRole(context, role, reason);
    if (added) await syncDirectorySafe(context);
    return added;
  }

  // --- roles / admin -------------------------------------------------------

  /** Current roles (config.ROLES values). */
  async getRoles(): Promise<string[]> {
    return getRoles(this.context());
  }

  /** Replace roles (admin page); audited with `actorUserId`. Refuses to drop the last admin. */
  async setRoles(roles: string[], actorUserId: string): Promise<SetRolesResult> {
    return setRoles(this.context(), roles, actorUserId);
  }

  /** Disable (revoking every session) or re-enable the account; audited with `actorUserId`. */
  async setDisabled(disabled: boolean, actorUserId: string): Promise<SetDisabledResult> {
    return setDisabled(this.context(), disabled, actorUserId);
  }

  /** Revoke every session on an admin's behalf; audited with `actorUserId`. Returns the count. */
  async revokeSessionsByAdmin(actorUserId: string): Promise<number> {
    return revokeSessionsByAdmin(this.context(), actorUserId);
  }

  /** The admin page's view of this user, or null when there is no profile. */
  async getAdminDetail(): Promise<AdminUserDetail | null> {
    if (!this.exists()) return null;
    return adminDetail(this.context(), await this.listSessions());
  }

  /**
   * Push this user's summary to the UserIndex directory (also the per-user
   * directory rebuild). False when there is no profile.
   */
  async syncDirectory(): Promise<boolean> {
    if (!this.exists()) return false;
    return syncDirectory(this.context());
  }

  // --- password reset ------------------------------------------------------

  /** Design §6.6: email a single-use reset link to `email` if it is verified here and the limit allows. */
  async requestPasswordReset(email: string): Promise<RequestResetResult> {
    if (!this.exists()) return { sent: false, reason: 'unknown_email' };
    return requestPasswordReset(this.context(), email);
  }

  /** Whether a reset secret (the last part of `pr1.<userId>.<secret>`) is usable. No side effects. */
  async checkResetToken(secret: string): Promise<ResetPasswordResult> {
    if (!this.exists()) return { ok: false, reason: 'invalid' };
    return checkResetToken(this.context(), secret);
  }

  /** Design §6.6: consume the token, set `hash`, revoke every session, alert all addresses. */
  async resetPassword(secret: string, hash: string): Promise<ResetPasswordResult> {
    if (!this.exists()) return { ok: false, reason: 'invalid' };
    return resetPassword(this.context(), secret, hash);
  }

  // --- maintenance ---------------------------------------------------------

  /** Prune old sessions/limits/tokens/audit rows; with `force` false, only if PRUNE_INTERVAL has passed. */
  async runMaintenance(force = true): Promise<PruneResult | null> {
    return force ? prune(this.context()) : pruneIfDue(this.context());
  }

  /** Opportunistic pruning (from createSession); never lets a failure break the caller. */
  private maintainQuietly(): void {
    try {
      pruneIfDue(this.context());
    } catch (err) {
      console.error('user maintenance failed', err);
    }
  }

  // --- passkeys ------------------------------------------------------------

  /** Store a passkey registration the Worker already verified (routes/passkey.ts). */
  async addPasskey(input: NewPasskey): Promise<AddPasskeyResult> {
    return addPasskey(this.context(), input);
  }

  /** Passkeys for the profile page, oldest first. */
  async listPasskeys(): Promise<PasskeyInfo[]> {
    return listPasskeys(this.context());
  }

  /** Existing passkeys as WebAuthn excludeCredentials entries. */
  async passkeyDescriptors(): Promise<PasskeyDescriptor[]> {
    return passkeyDescriptors(this.context());
  }

  async renamePasskey(id: string, label: string): Promise<PasskeyChangeResult> {
    return renamePasskey(this.context(), id, label);
  }

  /** Refused (`last_method`) when no password, other passkey or social login would remain. */
  async deletePasskey(id: string): Promise<PasskeyChangeResult> {
    return deletePasskey(this.context(), id);
  }

  /** Design §6.3: verify an assertion, update the counter, start an `hwk` session. */
  async verifyPasskeyLogin(
    response: AuthenticationResponseJSON,
    expectedChallenge: string,
    expectedOrigin: string | string[],
    expectedRPID: string,
    login: PasskeyLoginContext = {},
  ): Promise<PasskeyLoginResult | { ok: false; reason: 'disabled' }> {
    try {
      return await verifyPasskeyLogin(this.context(), response, expectedChallenge, expectedOrigin, expectedRPID, login);
    } catch (err) {
      // Only reached after the assertion verified (createSession refused).
      if (!isAccountDisabledError(err)) throw err;
      this.writeAudit('login.blocked_disabled', { method: 'passkey', ip: login.ip ?? null }, Date.now());
      return { ok: false, reason: 'disabled' };
    }
  }

  // --- oidc ----------------------------------------------------------------

  /** Scopes already granted to `clientId` (remembered consent), or null. */
  async getOAuthGrant(clientId: string): Promise<string[] | null> {
    return getGrant(this.context(), clientId);
  }

  /** Remember consent for `clientId` (union with earlier grants). Returns the granted scopes. */
  async saveOAuthGrant(clientId: string, scopes: string[]): Promise<string[]> {
    return saveGrant(this.context(), clientId, scopes);
  }

  /** Remembered consents, for a "connected apps" list. */
  async listOAuthGrants(): Promise<OAuthGrantInfo[]> {
    return listGrants(this.context());
  }

  /** Forget consent for a client and revoke its tokens. */
  async revokeOAuthClient(clientId: string): Promise<boolean> {
    return revokeClient(this.context(), clientId);
  }

  /** Park a validated authorize request behind a single-use consent token. */
  async startOAuthConsent(sessionId: string, request: AuthorizeRequest): Promise<{ token: string }> {
    return startConsent(this.context(), sessionId, request);
  }

  /** Take a consent token (single use) for this browser session. */
  async takeOAuthConsent(token: string, sessionId: string): Promise<AuthorizeRequest | null> {
    return takeConsent(this.context(), token, sessionId);
  }

  /** Issue an authorization code (the secret part of `ac1.<userId>.<secret>`). */
  async createOAuthCode(input: CreateCodeInput): Promise<CreateCodeResult> {
    return createCode(this.context(), input);
  }

  /** Token endpoint: exchange a code (PKCE-checked, single use; replay revokes). */
  async redeemOAuthCode(input: RedeemCodeInput): Promise<RedeemCodeResult> {
    if (!this.exists()) return { ok: false, reason: 'invalid' };
    return redeemCode(this.context(), input);
  }

  /** Token endpoint: rotate a client refresh token. */
  async refreshOAuthToken(input: RefreshGrantInput): Promise<RefreshGrantResult> {
    if (!this.exists()) return { ok: false, reason: 'invalid' };
    return refreshGrant(this.context(), input);
  }

  /** Userinfo: live claims behind a client access token, or null when it no longer stands. */
  async getOAuthTokenClaims(tokenId: string, sessionId: string, clientId: string): Promise<UserClaims | null> {
    if (!this.exists()) return null;
    return tokenClaims(this.context(), tokenId, sessionId, clientId);
  }

  // --- social login ----------------------------------------------------------

  /** Store a linked provider identity (already claimed in UserIndex.identities). */
  async addOAuthCredential(input: { provider: string; subject: string; email?: string | null; label?: string }): Promise<AddOAuthResult> {
    return addOAuthCredential(this.context(), input);
  }

  /** Linked provider identities for the profile page, oldest first. */
  async listOAuthCredentials(): Promise<OAuthCredentialInfo[]> {
    return listOAuthCredentials(this.context());
  }

  /** Refused (`last_method`) when no password, passkey or other social login would remain. */
  async unlinkOAuth(credentialId: string): Promise<UnlinkOAuthResult> {
    return unlinkOAuth(this.context(), credentialId);
  }

  /** Design §6.7: sign in with a linked identity; an `oauth:<provider>` session. */
  async loginWithOAuth(
    provider: string,
    subject: string,
    login: OAuthLoginContext = {},
  ): Promise<OAuthLoginResult | { ok: false; reason: 'disabled' }> {
    try {
      return await loginWithOAuth(this.context(), provider, subject, login);
    } catch (err) {
      if (!isAccountDisabledError(err)) throw err;
      this.writeAudit('login.blocked_disabled', { method: `oauth:${provider}`, ip: login.ip ?? null }, Date.now());
      return { ok: false, reason: 'disabled' };
    }
  }

  // --- context -------------------------------------------------------------

  /** Context for the feature modules in ./user/. */
  private context(): UserContext {
    const now = Date.now();
    return {
      sql: this.sql,
      storage: this.ctx.storage,
      env: this.env,
      now,
      audit: (event, detail) => this.writeAudit(event, detail, now),
      createSession: (session) => this.createSession(session),
    };
  }

  // --- internals -----------------------------------------------------------

  private writeAudit(event: string, detail: unknown, at: number): void {
    this.sql.exec(
      'INSERT INTO audit_log (at, event, detail) VALUES (?, ?, ?)',
      at, event, detail === undefined ? null : JSON.stringify(detail),
    );
  }

  private profile(): ProfileRow | null {
    const rows = this.sql.exec<ProfileRow>(
      'SELECT user_id, username, name, picture, roles FROM profile LIMIT 1',
    ).toArray();
    return rows[0] ?? null;
  }

  private requireProfile(): ProfileRow {
    const profile = this.profile();
    if (!profile) throw new Error('User profile does not exist');
    return profile;
  }

  private primaryEmail(): string {
    const rows = this.sql.exec<{ email: string }>(
      'SELECT email FROM emails WHERE is_primary = 1 LIMIT 1',
    ).toArray();
    const row = rows[0];
    if (!row) throw new Error('User has no primary email');
    return row.email;
  }

  private session(sessionId: string): SessionRow | null {
    const rows = this.sql.exec<SessionRow>('SELECT * FROM sessions WHERE id = ?', sessionId).toArray();
    return rows[0] ?? null;
  }
}
