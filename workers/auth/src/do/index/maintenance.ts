/**
 * UserIndex expiry sweep (design §4.1). Every table with rows that stop
 * mattering at `expires_at` is listed here; the alarm deletes expired rows
 * and reschedules itself for the next expiry. Add new expiring tables to
 * EXPIRING (and call ctx.scheduleSweep when writing them).
 */

import type { IndexContext } from './context';

/** Tables whose rows carry an `expires_at` the sweeper honours. Active handles/emails never expire. */
export const EXPIRING: readonly { table: string; where: string }[] = [
  { table: 'handles', where: "status IN ('pending','held')" },
  { table: 'emails', where: "status = 'held'" },
  { table: 'pending_signups', where: '1' },
  { table: 'challenges', where: '1' },
  { table: 'send_limits', where: '1' },
  { table: 'oauth_pending', where: '1' },
];

/** Delete every expired row in one transaction. Returns rows deleted per table. */
export function sweepExpired(ctx: Pick<IndexContext, 'sql' | 'storage' | 'now'>): Record<string, number> {
  const { sql, now } = ctx;
  return ctx.storage.transactionSync(() => {
    const deleted: Record<string, number> = {};
    for (const { table, where } of EXPIRING) {
      deleted[table] = sql.exec(`DELETE FROM ${table} WHERE ${where} AND expires_at <= ?`, now).rowsWritten;
    }
    return deleted;
  });
}

/** Earliest pending expiry across EXPIRING, or null when nothing is left to sweep. */
export function nextExpiry(sql: SqlStorage): number | null {
  let next: number | null = null;
  for (const { table, where } of EXPIRING) {
    const row = sql.exec<{ v: number | null }>(
      `SELECT MIN(expires_at) AS v FROM ${table} WHERE ${where} AND expires_at IS NOT NULL`,
    ).one();
    if (row.v !== null && (next === null || row.v < next)) next = row.v;
  }
  return next;
}
