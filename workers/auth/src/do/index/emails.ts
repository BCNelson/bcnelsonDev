/**
 * Verified emails in the UserIndex (design §4.1, §6.5). Only verified
 * addresses are ever claimed here; the User DO verifies the code first.
 *
 * claim   → `active` for the user. Fails if active, or still held, for anyone
 *           else (a pending signup never reaches this table). Idempotent, and
 *           the owner may take back their own held address.
 * hold    → after removal: `held` (same user_id) for EMAIL_HOLD, then swept.
 * release → delete an active row outright (undoing a claim that the User DO
 *           then refused, e.g. over the per-account cap).
 */

import { config } from '../../config';
import { normalizeEmail } from '../../identifiers';
import { isLive, type IndexContext } from './context';

export type ClaimEmailResult = { ok: true } | { ok: false; reason: 'taken' };

type EmailRow = { status: string; user_id: string; expires_at: number | null };

function emailRow(sql: SqlStorage, norm: string): EmailRow | null {
  return sql.exec<EmailRow>(
    'SELECT status, user_id, expires_at FROM emails WHERE email_norm = ?', norm,
  ).toArray()[0] ?? null;
}

export function claimEmail(ctx: IndexContext, userId: string, email: string): ClaimEmailResult {
  const norm = normalizeEmail(email);
  const { sql, now } = ctx;
  return ctx.storage.transactionSync(() => {
    const row = emailRow(sql, norm);
    if (row && row.user_id !== userId && isLive(row.status, row.expires_at, now)) {
      return { ok: false, reason: 'taken' } as const;
    }
    sql.exec(
      `INSERT OR REPLACE INTO emails (email_norm, user_id, status, expires_at)
       VALUES (?, ?, 'active', NULL)`,
      norm, userId,
    );
    return { ok: true } as const;
  });
}

/** Turn this user's active address into a hold. False when it isn't theirs/active. */
export async function holdEmail(ctx: IndexContext, userId: string, email: string): Promise<boolean> {
  const norm = normalizeEmail(email);
  const until = ctx.now + config.EMAIL_HOLD;
  const changed = ctx.sql.exec(
    "UPDATE emails SET status = 'held', expires_at = ? WHERE email_norm = ? AND user_id = ? AND status = 'active'",
    until, norm, userId,
  ).rowsWritten > 0;
  if (changed) await ctx.scheduleSweep(until);
  return changed;
}

/** Delete this user's active row for `email`. False when there was none. */
export function releaseEmail(ctx: IndexContext, userId: string, email: string): boolean {
  return ctx.sql.exec(
    "DELETE FROM emails WHERE email_norm = ? AND user_id = ? AND status = 'active'",
    normalizeEmail(email), userId,
  ).rowsWritten > 0;
}
