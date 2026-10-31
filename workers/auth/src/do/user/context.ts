/**
 * What User feature modules (src/do/user/*) get from the DO class, plus
 * small read helpers they share. Feature logic lives in plain functions over
 * this context; the class methods only build it and delegate.
 */

import type { Env } from '../../env';
import type { CreatedSession, SessionContext } from '../../types';
import type { ProfileRow } from '../sessions';

export interface UserContext {
  sql: SqlStorage;
  storage: DurableObjectStorage;
  env: Env;
  /** Request time, epoch ms. Take it once per call so a call sees one "now". */
  now: number;
  /** Append an audit_log entry at `now`. */
  audit(event: string, detail?: unknown): void;
  /** Start a session (User.createSession). */
  createSession(session: SessionContext): Promise<CreatedSession>;
}

/** The profile row, or null before initProfile. */
export function readProfile(sql: SqlStorage): ProfileRow | null {
  return sql.exec<ProfileRow>(
    'SELECT user_id, username, name, picture, roles FROM profile LIMIT 1',
  ).toArray()[0] ?? null;
}

/** The primary (verified) email, or null. */
export function readPrimaryEmail(sql: SqlStorage): string | null {
  return sql.exec<{ email: string }>(
    'SELECT email FROM emails WHERE is_primary = 1 LIMIT 1',
  ).toArray()[0]?.email ?? null;
}
