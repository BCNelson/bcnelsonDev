/**
 * Profile page data and edits (design §4.2, §5, phase 4): the account view,
 * display name / avatar, username changes, credential summaries and
 * password changes from the profile page.
 *
 * Username change: validateUsername, USERNAME_CHANGE_COOLDOWN (claimed
 * before the index call so concurrent renames can't both pass), then
 * UserIndex.renameHandle (new handle active, old one held for
 * USERNAME_HOLD), then the profile. A case-only change (Brad → BRAD) keeps
 * the same handle: no index call, no cooldown.
 */

import { config } from '../../config';
import { verifyPassword } from '../../crypto/password';
import { passwordChanged } from '../../email/templates';
import { normalizeUsername, validateUsername, type UsernameError } from '../../identifiers';
import { parseStringArray } from '../sessions';
import type { SessionInfo } from '../user';
import { syncDirectorySafe } from './admin';
import type { UserContext } from './context';
import { type EmailInfo, type PendingEmailInfo, listEmails, listPendingEmails, sendAlert } from './emails';
import { readPasswordCredential, setPassword } from './password';

/** A credential as the profile page shows it. Never includes `data`. */
export interface CredentialInfo {
  id: string;
  type: string;
  label: string | null;
  createdAt: number;
  lastUsedAt: number | null;
}

export interface ProfileInfo {
  userId: string;
  username: string;
  name: string | null;
  picture: string | null;
  roles: string[];
  createdAt: number;
  usernameChangedAt: number | null;
  /** When the next username change is allowed; null when it is allowed now. */
  usernameChangeAvailableAt: number | null;
}

/** Everything GET /profile and GET /api/me show. Times are epoch ms. */
export interface AccountInfo {
  profile: ProfileInfo;
  emails: EmailInfo[];
  pendingEmails: PendingEmailInfo[];
  sessions: SessionInfo[];
  credentials: CredentialInfo[];
  hasPassword: boolean;
}

export interface ProfileUpdate {
  /** Absent: unchanged. '' or null: cleared. */
  name?: string | null;
  picture?: string | null;
}

export type UpdateProfileResult =
  | { ok: true; profile: ProfileInfo; changed: boolean }
  | { ok: false; reason: 'invalid_name' | 'invalid_picture' };

export type ChangeUsernameResult =
  | { ok: true; username: string; changed: boolean }
  | { ok: false; reason: 'invalid_username'; detail?: UsernameError }
  | { ok: false; reason: 'username_taken' }
  | { ok: false; reason: 'cooldown'; retryAfterMs: number };

export type ChangePasswordResult =
  | { ok: true; revokedSessions: number }
  | { ok: false; reason: 'current_password_required' | 'invalid_password' };

type FullProfileRow = {
  user_id: string;
  username: string;
  name: string | null;
  picture: string | null;
  roles: string;
  created_at: number;
  username_changed_at: number | null;
};

// --- validation (pure) -------------------------------------------------------

/** Trimmed, NFC display name, or null for empty; undefined when invalid. */
export function normalizeName(input: string | null): string | null | undefined {
  if (input === null) return null;
  const name = input.normalize('NFC').trim();
  if (name === '') return null;
  if ([...name].length > config.PROFILE_NAME_MAX_LENGTH) return undefined;
  if (/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(name)) return undefined;
  return name;
}

/** Normalized https avatar URL, or null for empty; undefined when invalid. */
export function normalizePicture(input: string | null): string | null | undefined {
  if (input === null) return null;
  const raw = input.trim();
  if (raw === '') return null;
  if (raw.length > config.PICTURE_URL_MAX_LENGTH) return undefined;
  if (/[\s\u0000-\u001f\u007f\\]/.test(raw)) return undefined;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return undefined;
  }
  if (url.protocol !== 'https:' || url.username || url.password || !url.hostname) return undefined;
  return url.href.length > config.PICTURE_URL_MAX_LENGTH ? undefined : url.href;
}

// --- reads -------------------------------------------------------------------

function readFullProfile(sql: SqlStorage): FullProfileRow {
  const row = sql.exec<FullProfileRow>(
    'SELECT user_id, username, name, picture, roles, created_at, username_changed_at FROM profile LIMIT 1',
  ).toArray()[0];
  if (!row) throw new Error('User profile does not exist');
  return row;
}

function profileInfo(row: FullProfileRow, now: number): ProfileInfo {
  const next = row.username_changed_at === null ? null : row.username_changed_at + config.USERNAME_CHANGE_COOLDOWN;
  return {
    userId: row.user_id,
    username: row.username,
    name: row.name,
    picture: row.picture,
    roles: parseStringArray(row.roles),
    createdAt: row.created_at,
    usernameChangedAt: row.username_changed_at,
    usernameChangeAvailableAt: next !== null && next > now ? next : null,
  };
}

export function listCredentials(sql: SqlStorage): CredentialInfo[] {
  return sql.exec<{ id: string; type: string; label: string | null; created_at: number; last_used_at: number | null }>(
    'SELECT id, type, label, created_at, last_used_at FROM credentials ORDER BY created_at, id',
  ).toArray().map((r) => ({
    id: r.id,
    type: r.type,
    label: r.label,
    createdAt: r.created_at,
    lastUsedAt: r.last_used_at,
  }));
}

/** The account view; `sessions` comes from User.listSessions. */
export function getAccount(ctx: UserContext, sessions: SessionInfo[]): AccountInfo {
  const { sql, now } = ctx;
  return {
    profile: profileInfo(readFullProfile(sql), now),
    emails: listEmails(sql),
    pendingEmails: listPendingEmails(sql, now),
    sessions,
    credentials: listCredentials(sql),
    hasPassword: readPasswordCredential(sql) !== null,
  };
}

// --- edits -------------------------------------------------------------------

export function updateProfile(ctx: UserContext, update: ProfileUpdate): UpdateProfileResult {
  const name = update.name === undefined ? undefined : normalizeName(update.name);
  if (update.name !== undefined && name === undefined) return { ok: false, reason: 'invalid_name' };
  const picture = update.picture === undefined ? undefined : normalizePicture(update.picture);
  if (update.picture !== undefined && picture === undefined) return { ok: false, reason: 'invalid_picture' };
  const { sql, now } = ctx;
  return ctx.storage.transactionSync(() => {
    const row = readFullProfile(sql);
    const next = {
      name: update.name === undefined ? row.name : name!,
      picture: update.picture === undefined ? row.picture : picture!,
    };
    const changed = next.name !== row.name || next.picture !== row.picture;
    if (changed) {
      sql.exec('UPDATE profile SET name = ?, picture = ?', next.name, next.picture);
      ctx.audit('profile.updated', {
        name: next.name !== row.name,
        picture: next.picture !== row.picture,
      });
    }
    return { ok: true, profile: profileInfo({ ...row, ...next }, now), changed };
  });
}

export async function changeUsername(ctx: UserContext, input: string): Promise<ChangeUsernameResult> {
  const target = validateUsername(input);
  if (!target.ok) return { ok: false, reason: 'invalid_username', detail: target.reason };
  const { sql, now } = ctx;

  const claim = ctx.storage.transactionSync(() => {
    const row = readFullProfile(sql);
    if (row.username === target.display) return { kind: 'same' as const };
    if (normalizeUsername(row.username) === target.norm) {
      sql.exec('UPDATE profile SET username = ?', target.display);
      ctx.audit('username.changed', { from: row.username, to: target.display, caseOnly: true });
      return { kind: 'case' as const };
    }
    if (row.username_changed_at !== null) {
      const available = row.username_changed_at + config.USERNAME_CHANGE_COOLDOWN;
      if (available > now) return { kind: 'cooldown' as const, retryAfterMs: available - now };
    }
    // Claim the cooldown now; undone below if the index refuses.
    sql.exec('UPDATE profile SET username_changed_at = ?', now);
    return { kind: 'rename' as const, row };
  });
  if (claim.kind === 'same') return { ok: true, username: target.display, changed: false };
  if (claim.kind === 'cooldown') return { ok: false, reason: 'cooldown', retryAfterMs: claim.retryAfterMs };
  if (claim.kind === 'case') {
    await syncDirectorySafe(ctx);
    return { ok: true, username: target.display, changed: true };
  }

  const { row } = claim;
  const index = ctx.env.USER_INDEX.get(ctx.env.USER_INDEX.idFromName('index'));
  let result: Awaited<ReturnType<typeof index.renameHandle>>;
  try {
    result = await index.renameHandle({ userId: row.user_id, from: row.username, to: target.display });
  } catch (err) {
    restoreCooldown(sql, now, row.username_changed_at);
    throw err;
  }
  if (!result.ok) {
    restoreCooldown(sql, now, row.username_changed_at);
    return result.reason === 'invalid_username'
      ? { ok: false, reason: 'invalid_username' }
      : { ok: false, reason: 'username_taken' };
  }
  ctx.storage.transactionSync(() => {
    sql.exec('UPDATE profile SET username = ?', result.username);
    ctx.audit('username.changed', { from: row.username, to: result.username, heldUntil: result.heldUntil });
  });
  await syncDirectorySafe(ctx);
  return { ok: true, username: result.username, changed: true };
}

/** Undo the cooldown claim, unless something else changed it meanwhile. */
function restoreCooldown(sql: SqlStorage, claimedAt: number, previous: number | null): void {
  sql.exec('UPDATE profile SET username_changed_at = ? WHERE username_changed_at = ?', previous, claimedAt);
}

/**
 * Set a new password (`hash` already computed by the caller). When the
 * account has a password, `currentPassword` must match it. Revokes every
 * other session and alerts all verified addresses.
 */
export async function changePassword(
  ctx: UserContext,
  input: { currentPassword?: string; hash: string; keepSessionId?: string },
): Promise<ChangePasswordResult> {
  const { sql } = ctx;
  const existing = readPasswordCredential(sql);
  if (existing) {
    if (!input.currentPassword) return { ok: false, reason: 'current_password_required' };
    const check = await verifyPassword(input.currentPassword, existing.hash);
    if (!check.ok) {
      ctx.audit('password.change_failed', { reason: 'invalid_password' });
      return { ok: false, reason: 'invalid_password' };
    }
  }
  setPassword(ctx, input.hash);
  const revokedSessions = ctx.storage.transactionSync(() => {
    const count = sql.exec(
      'UPDATE sessions SET revoked_at = ? WHERE revoked_at IS NULL AND id IS NOT ?',
      ctx.now, input.keepSessionId ?? null,
    ).rowsWritten;
    ctx.audit('session.revoked_all', { except: input.keepSessionId ?? null, count, reason: 'password_changed' });
    return count;
  });
  await sendAlert(ctx, listEmails(sql).map((e) => e.email), passwordChanged(), 'password_changed');
  return { ok: true, revokedSessions };
}

