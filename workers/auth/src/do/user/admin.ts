/**
 * Roles and admin actions on a User DO (design §8): role changes, account
 * disable, admin session revocation, the admin detail view, and pushing this
 * user's summary to the UserIndex directory.
 *
 * Directory sync: call `syncDirectory(ctx)` (or the `User.syncDirectory()`
 * RPC) after anything that changes username, primary email, roles or
 * disabled state. Other features (profile: rename, primary email) should call
 * it after their transaction commits.
 */

import { config } from '../../config';
import type { DirectorySummary } from '../index/directory';
import { parseStringArray } from '../sessions';
import type { SessionInfo } from '../user';
import { type UserContext, readPrimaryEmail, readProfile } from './context';

/** Error message createSession throws for a disabled account (survives RPC). */
export const ACCOUNT_DISABLED = 'account_disabled';

/** True for the error createSession throws when the account is disabled. */
export function isAccountDisabledError(err: unknown): boolean {
  const message = err instanceof Error ? err.message : String(err);
  return message.includes(ACCOUNT_DISABLED);
}

/** profile.disabled_at, or null when active (or no profile). */
export function readDisabledAt(sql: SqlStorage): number | null {
  return sql.exec<{ disabled_at: number | null }>(
    'SELECT disabled_at FROM profile LIMIT 1',
  ).toArray()[0]?.disabled_at ?? null;
}

/** Throws ACCOUNT_DISABLED when the account is disabled. createSession calls this. */
export function assertNotDisabled(sql: SqlStorage): void {
  if (readDisabledAt(sql) !== null) throw new Error(ACCOUNT_DISABLED);
}

// --- roles -----------------------------------------------------------------

/** Current roles. */
export function getRoles(ctx: UserContext): string[] {
  return parseStringArray(readProfile(ctx.sql)?.roles ?? null);
}

/**
 * Validate a requested role list: an array of config.ROLES values. Returns
 * them deduplicated in config order, or null if anything is invalid.
 */
export function normalizeRoles(input: unknown): string[] | null {
  if (!Array.isArray(input)) return null;
  if (!input.every((r) => typeof r === 'string' && config.ROLES.includes(r))) return null;
  return config.ROLES.filter((r) => input.includes(r));
}

export type SetRolesResult =
  | { ok: true; roles: string[]; changed: boolean }
  | { ok: false; reason: 'invalid_role' | 'not_found' | 'last_admin' };

/**
 * Replace the role list (admin page). Refuses to remove `admin` from the last
 * active admin. Audited with the actor; syncs the directory.
 */
export async function setRoles(ctx: UserContext, input: unknown, actorUserId: string): Promise<SetRolesResult> {
  const roles = normalizeRoles(input);
  if (!roles) return { ok: false, reason: 'invalid_role' };
  const profile = readProfile(ctx.sql);
  if (!profile) return { ok: false, reason: 'not_found' };
  const before = parseStringArray(profile.roles);
  const removingAdmin = before.includes('admin') && !roles.includes('admin');
  if (removingAdmin && readDisabledAt(ctx.sql) === null && !(await hasOtherAdmin(ctx, profile.user_id))) {
    return { ok: false, reason: 'last_admin' };
  }
  const changed = ctx.storage.transactionSync(() => {
    const current = parseStringArray(readProfile(ctx.sql)?.roles ?? null);
    if (sameRoles(current, roles)) return false;
    ctx.sql.exec('UPDATE profile SET roles = ?', JSON.stringify(roles));
    ctx.audit('role.set', { roles, previous: current, actor: actorUserId });
    return true;
  });
  await syncDirectory(ctx);
  return { ok: true, roles, changed };
}

// --- disable ---------------------------------------------------------------

export type SetDisabledResult =
  | { ok: true; disabledAt: number | null; revokedSessions: number }
  | { ok: false; reason: 'not_found' | 'last_admin' | 'self' };

/**
 * Disable or re-enable the account. Disabling revokes every session; a
 * disabled account can't log in (createSession throws) or refresh. An admin
 * can't disable themselves, nor the last active admin.
 */
export async function setDisabled(ctx: UserContext, disabled: boolean, actorUserId: string): Promise<SetDisabledResult> {
  const profile = readProfile(ctx.sql);
  if (!profile) return { ok: false, reason: 'not_found' };
  if (disabled && profile.user_id === actorUserId) return { ok: false, reason: 'self' };
  if (disabled && parseStringArray(profile.roles).includes('admin') && readDisabledAt(ctx.sql) === null
    && !(await hasOtherAdmin(ctx, profile.user_id))) {
    return { ok: false, reason: 'last_admin' };
  }
  const { now, sql } = ctx;
  const result = ctx.storage.transactionSync(() => {
    const current = readDisabledAt(sql);
    if (!disabled) {
      if (current !== null) {
        sql.exec('UPDATE profile SET disabled_at = NULL');
        ctx.audit('account.enabled', { actor: actorUserId });
      }
      return { disabledAt: null, revokedSessions: 0 };
    }
    const disabledAt = current ?? now;
    if (current === null) sql.exec('UPDATE profile SET disabled_at = ?', disabledAt);
    const revoked = sql.exec(
      'UPDATE sessions SET revoked_at = ? WHERE revoked_at IS NULL', now,
    ).rowsWritten;
    if (current === null) ctx.audit('account.disabled', { actor: actorUserId, revokedSessions: revoked });
    return { disabledAt, revokedSessions: revoked };
  });
  await syncDirectory(ctx);
  return { ok: true, ...result };
}

// --- sessions --------------------------------------------------------------

/** Revoke every active session on behalf of an admin. Returns how many were revoked. */
export function revokeSessionsByAdmin(ctx: UserContext, actorUserId: string): number {
  return ctx.storage.transactionSync(() => {
    const count = ctx.sql.exec(
      'UPDATE sessions SET revoked_at = ? WHERE revoked_at IS NULL', ctx.now,
    ).rowsWritten;
    ctx.audit('admin.sessions_revoked', { actor: actorUserId, count });
    return count;
  });
}

// --- admin detail ----------------------------------------------------------

export interface AuditEntry {
  at: number;
  event: string;
  detail: unknown;
}

/** Everything the admin page shows for one user. Times are epoch ms. */
export interface AdminUserDetail {
  userId: string;
  username: string;
  name: string | null;
  primaryEmail: string | null;
  emails: string[];
  roles: string[];
  createdAt: number;
  disabledAt: number | null;
  sessions: SessionInfo[];
  credentials: { type: string; label: string | null; createdAt: number; lastUsedAt: number | null }[];
  audit: AuditEntry[];
}

/** Most recent audit_log entries, newest first. */
export function readAuditLog(sql: SqlStorage, limit: number): AuditEntry[] {
  return sql.exec<{ at: number; event: string; detail: string | null }>(
    'SELECT at, event, detail FROM audit_log ORDER BY at DESC, rowid DESC LIMIT ?', limit,
  ).toArray().map((r) => ({ at: r.at, event: r.event, detail: parseJson(r.detail) }));
}

/** The admin view of this user, or null when there is no profile. */
export function adminDetail(ctx: UserContext, sessions: SessionInfo[]): AdminUserDetail | null {
  const { sql } = ctx;
  const profile = readProfile(sql);
  if (!profile) return null;
  const emails = sql.exec<{ email: string }>(
    'SELECT email FROM emails ORDER BY is_primary DESC, verified_at',
  ).toArray().map((r) => r.email);
  const credentials = sql.exec<{ type: string; label: string | null; created_at: number; last_used_at: number | null }>(
    'SELECT type, label, created_at, last_used_at FROM credentials ORDER BY created_at',
  ).toArray().map((r) => ({ type: r.type, label: r.label, createdAt: r.created_at, lastUsedAt: r.last_used_at }));
  return {
    userId: profile.user_id,
    username: profile.username,
    name: profile.name,
    primaryEmail: readPrimaryEmail(sql),
    emails,
    roles: parseStringArray(profile.roles),
    createdAt: readCreatedAt(sql),
    disabledAt: readDisabledAt(sql),
    sessions,
    credentials,
    audit: readAuditLog(sql, config.ADMIN_AUDIT_LIMIT),
  };
}

// --- directory sync --------------------------------------------------------

/** This user's directory summary, or null when there is no profile. */
export function directorySummary(sql: SqlStorage): DirectorySummary | null {
  const profile = readProfile(sql);
  if (!profile) return null;
  return {
    userId: profile.user_id,
    username: profile.username,
    primaryEmail: readPrimaryEmail(sql),
    roles: parseStringArray(profile.roles),
    createdAt: readCreatedAt(sql),
    disabledAt: readDisabledAt(sql),
  };
}

/**
 * Push this user's summary to the UserIndex directory. Returns false when
 * there is no profile yet. Throws if the index call fails; use
 * `syncDirectorySafe` where a stale directory row is acceptable.
 */
export async function syncDirectory(ctx: Pick<UserContext, 'sql' | 'env'>): Promise<boolean> {
  const summary = directorySummary(ctx.sql);
  if (!summary) return false;
  const index = ctx.env.USER_INDEX.get(ctx.env.USER_INDEX.idFromName('index'));
  await index.upsertDirectoryEntry(summary);
  return true;
}

/** syncDirectory that logs instead of throwing (login paths must not fail on it). */
export async function syncDirectorySafe(ctx: Pick<UserContext, 'sql' | 'env'>): Promise<void> {
  try {
    await syncDirectory(ctx);
  } catch (err) {
    console.error('directory sync failed', err);
  }
}

// --- internals ---------------------------------------------------------------

async function hasOtherAdmin(ctx: UserContext, userId: string): Promise<boolean> {
  const index = ctx.env.USER_INDEX.get(ctx.env.USER_INDEX.idFromName('index'));
  return (await index.countActiveAdmins(userId)) > 0;
}

function readCreatedAt(sql: SqlStorage): number {
  return sql.exec<{ created_at: number }>('SELECT created_at FROM profile LIMIT 1').toArray()[0]?.created_at ?? 0;
}

function sameRoles(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((r) => b.includes(r));
}

function parseJson(text: string | null): unknown {
  if (text === null) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}
