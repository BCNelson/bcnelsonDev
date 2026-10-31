/**
 * User DO housekeeping: delete rows nothing needs any more. Runs
 * opportunistically from createSession, at most once per PRUNE_INTERVAL,
 * so idle accounts cost nothing and no alarm is needed. The last run time
 * lives in the `maintenance` table (USER_MIGRATIONS 4).
 *
 * - sessions: revoked, or expired, more than SESSION_RETENTION ago
 * - action_limits: older than the longest ACTION_LIMITS window
 * - tokens: used or expired
 * - audit_log: older than AUDIT_RETENTION
 * - oidc: expired consent screens, old codes, dead client tokens (user/oidc.ts
 *   pruneOidc); expired sessions that live client refresh tokens need are kept
 */

import { config } from '../../config';
import type { UserContext } from './context';
import { SESSIONS_IN_USE_BY_OIDC, pruneOidc } from './oidc';

const PRUNE_TASK = 'prune';

export interface PruneResult {
  sessions: number;
  actionLimits: number;
  tokens: number;
  audit: number;
}

/** The longest window in ACTION_LIMITS; older action_limits rows can't affect any decision. */
export function longestActionWindow(): number {
  return Math.max(0, ...Object.values(config.ACTION_LIMITS).map(([, windowMs]) => windowMs));
}

/** Prune now, unconditionally, and record the run. */
export function prune(ctx: UserContext): PruneResult {
  const { sql, now } = ctx;
  return ctx.storage.transactionSync(() => {
    const sessionCutoff = now - config.SESSION_RETENTION;
    const result: PruneResult = {
      sessions: sql.exec(
        `DELETE FROM sessions WHERE (revoked_at IS NOT NULL AND revoked_at <= ?)
           OR (expires_at <= ? AND NOT ${SESSIONS_IN_USE_BY_OIDC})`,
        sessionCutoff, sessionCutoff, now,
      ).rowsWritten,
      actionLimits: sql.exec(
        'DELETE FROM action_limits WHERE at <= ?', now - longestActionWindow(),
      ).rowsWritten,
      tokens: sql.exec(
        'DELETE FROM tokens WHERE used_at IS NOT NULL OR expires_at <= ?', now,
      ).rowsWritten,
      audit: sql.exec('DELETE FROM audit_log WHERE at <= ?', now - config.AUDIT_RETENTION).rowsWritten,
    };
    pruneOidc(ctx);
    sql.exec(
      'INSERT OR REPLACE INTO maintenance (task, last_run_at) VALUES (?, ?)', PRUNE_TASK, now,
    );
    return result;
  });
}

/** Prune if the last run was at least PRUNE_INTERVAL ago (or never). Null when skipped. */
export function pruneIfDue(ctx: UserContext): PruneResult | null {
  const last = ctx.sql.exec<{ last_run_at: number }>(
    'SELECT last_run_at FROM maintenance WHERE task = ?', PRUNE_TASK,
  ).toArray()[0]?.last_run_at;
  if (last !== undefined && ctx.now - last < config.PRUNE_INTERVAL) return null;
  return prune(ctx);
}
