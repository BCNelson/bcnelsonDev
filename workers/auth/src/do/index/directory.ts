/**
 * User directory (admin page, design §8): one `users` row per account in
 * UserIndex, a denormalised copy of each User DO's summary. The User DO is
 * the source of truth and pushes its summary here (User side:
 * src/do/user/admin.ts syncDirectory) whenever username, primary email,
 * roles or disabled state change. Also counts active admins for the
 * last-admin guard.
 */

import { config } from '../../config';
import { normalizeEmail, normalizeUsername } from '../../identifiers';
import { parseStringArray } from '../sessions';
import type { IndexContext } from './context';

/** What a User DO pushes to the directory. Times are epoch ms. */
export interface DirectorySummary {
  userId: string;
  username: string;
  primaryEmail: string | null;
  roles: string[];
  createdAt: number;
  disabledAt: number | null;
}

/** A directory row as the admin API returns it. */
export interface DirectoryEntry extends DirectorySummary {
  updatedAt: number;
}

export interface DirectoryPage {
  users: DirectoryEntry[];
  /** Pass back as `cursor` for the next page; null on the last page. */
  nextCursor: string | null;
}

export interface ListDirectoryOptions {
  /** Return users with user_id > cursor (ids are ULIDs, so this is creation order). */
  cursor?: string | null;
  /** Username or primary-email prefix (case-insensitive). */
  q?: string | null;
  limit?: number;
}

type UserRow = {
  user_id: string;
  username: string;
  primary_email: string | null;
  roles: string;
  created_at: number;
  disabled_at: number | null;
  updated_at: number;
};

/** Insert or replace a user's directory row. */
export function upsertDirectoryEntry(sql: SqlStorage, summary: DirectorySummary, now: number): void {
  const roles = summary.roles.filter((r) => config.ROLES.includes(r));
  sql.exec(
    `INSERT INTO users (user_id, username, username_norm, primary_email, roles, is_admin,
       created_at, disabled_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT (user_id) DO UPDATE SET
       username = excluded.username, username_norm = excluded.username_norm,
       primary_email = excluded.primary_email, roles = excluded.roles,
       is_admin = excluded.is_admin, disabled_at = excluded.disabled_at,
       updated_at = excluded.updated_at`,
    summary.userId,
    summary.username,
    normalizeUsername(summary.username),
    summary.primaryEmail === null ? null : normalizeEmail(summary.primaryEmail),
    JSON.stringify(roles),
    roles.includes('admin') ? 1 : 0,
    summary.createdAt,
    summary.disabledAt,
    now,
  );
}

/** One directory row, or null. */
export function getDirectoryEntry(ctx: IndexContext, userId: string): DirectoryEntry | null {
  const row = ctx.sql.exec<UserRow>('SELECT * FROM users WHERE user_id = ?', userId).toArray()[0];
  return row ? toEntry(row) : null;
}

/** A page of users ordered by user_id, optionally filtered by username/email prefix. */
export function listDirectory(ctx: IndexContext, opts: ListDirectoryOptions = {}): DirectoryPage {
  const limit = clampLimit(opts.limit);
  const where: string[] = [];
  const params: unknown[] = [];
  if (opts.cursor) {
    where.push('user_id > ?');
    params.push(opts.cursor);
  }
  const q = (opts.q ?? '').trim().toLowerCase();
  if (q) {
    const pattern = `${escapeLike(q)}%`;
    where.push("(username_norm LIKE ? ESCAPE '\\' OR primary_email LIKE ? ESCAPE '\\')");
    params.push(pattern, pattern);
  }
  const rows = ctx.sql.exec<UserRow>(
    `SELECT * FROM users ${where.length ? `WHERE ${where.join(' AND ')}` : ''}
     ORDER BY user_id LIMIT ?`,
    ...params, limit + 1,
  ).toArray();
  const more = rows.length > limit;
  const page = more ? rows.slice(0, limit) : rows;
  return { users: page.map(toEntry), nextCursor: more ? page.at(-1)!.user_id : null };
}

/** Admins that are not disabled, optionally not counting `excludeUserId`. */
export function countActiveAdmins(ctx: IndexContext, excludeUserId?: string): number {
  const row = ctx.sql.exec<{ n: number }>(
    'SELECT COUNT(*) AS n FROM users WHERE is_admin = 1 AND disabled_at IS NULL AND user_id IS NOT ?',
    excludeUserId ?? null,
  ).one();
  return Number(row.n);
}

/** True when `userId` owns an active handle or has a directory row (i.e. is a real account). */
export function isKnownUser(ctx: IndexContext, userId: string): boolean {
  const row = ctx.sql.exec<{ n: number }>(
    `SELECT (SELECT COUNT(*) FROM users WHERE user_id = ?)
          + (SELECT COUNT(*) FROM handles WHERE user_id = ? AND status = 'active') AS n`,
    userId, userId,
  ).one();
  return Number(row.n) > 0;
}

/** Up to `limit` user ids with an active handle but no directory row (backfill). */
export function missingDirectoryEntries(ctx: IndexContext, limit: number): { userIds: string[]; remaining: number } {
  const query = `FROM handles h WHERE h.status = 'active' AND h.user_id IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM users u WHERE u.user_id = h.user_id)`;
  const total = Number(ctx.sql.exec<{ n: number }>(`SELECT COUNT(DISTINCT h.user_id) AS n ${query}`).one().n);
  const userIds = ctx.sql.exec<{ user_id: string }>(
    `SELECT DISTINCT h.user_id AS user_id ${query} ORDER BY h.user_id LIMIT ?`, limit,
  ).toArray().map((r) => r.user_id);
  return { userIds, remaining: total - userIds.length };
}

function toEntry(row: UserRow): DirectoryEntry {
  return {
    userId: row.user_id,
    username: row.username,
    primaryEmail: row.primary_email,
    roles: parseStringArray(row.roles),
    createdAt: row.created_at,
    disabledAt: row.disabled_at,
    updatedAt: row.updated_at,
  };
}

function clampLimit(limit: number | undefined): number {
  if (!limit || !Number.isFinite(limit)) return config.ADMIN_PAGE_SIZE;
  return Math.min(Math.max(1, Math.floor(limit)), config.ADMIN_MAX_PAGE_SIZE);
}

function escapeLike(value: string): string {
  return value.replace(/[\\%_]/g, (ch) => `\\${ch}`);
}
