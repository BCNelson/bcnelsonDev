/**
 * Username changes in the UserIndex (design §5). A rename atomically makes
 * the new handle `active` and turns the old one into a `held` row (same
 * user_id) for USERNAME_HOLD, so nobody else can grab it straight away and
 * links to the old name don't silently point at a stranger. The owner may
 * take their own held handle back. The User DO enforces the cooldown.
 */

import { config } from '../../config';
import { normalizeUsername, validateUsername } from '../../identifiers';
import { isLive, type IndexContext } from './context';

export type RenameHandleResult =
  | { ok: true; username: string; heldUntil: number }
  | { ok: false; reason: 'invalid_username' | 'username_taken' | 'not_owner' };

type HandleRow = { status: string; user_id: string | null; expires_at: number | null };

function handleRow(sql: SqlStorage, norm: string): HandleRow | null {
  return sql.exec<HandleRow>(
    'SELECT status, user_id, expires_at FROM handles WHERE username_norm = ?', norm,
  ).toArray()[0] ?? null;
}

/**
 * Move `userId` from handle `from` (its current username, any casing) to
 * `to` (display form). Fails unless `from` is this user's active handle and
 * `to` is free or this user's own held handle.
 */
export async function renameHandle(
  ctx: IndexContext,
  input: { userId: string; from: string; to: string },
): Promise<RenameHandleResult> {
  const target = validateUsername(input.to);
  if (!target.ok) return { ok: false, reason: 'invalid_username' };
  const fromNorm = normalizeUsername(input.from);
  if (fromNorm === target.norm) return { ok: false, reason: 'invalid_username' };
  const { sql, now } = ctx;
  const heldUntil = now + config.USERNAME_HOLD;

  const outcome = ctx.storage.transactionSync(() => {
    const old = handleRow(sql, fromNorm);
    if (!old || old.status !== 'active' || old.user_id !== input.userId) return 'not_owner' as const;
    const existing = handleRow(sql, target.norm);
    const ownHeld = existing?.status === 'held' && existing.user_id === input.userId;
    if (existing && isLive(existing.status, existing.expires_at, now) && !ownHeld) return 'username_taken' as const;
    sql.exec(
      `INSERT OR REPLACE INTO handles (username_norm, user_id, status, expires_at)
       VALUES (?, ?, 'active', NULL)`,
      target.norm, input.userId,
    );
    sql.exec(
      "UPDATE handles SET status = 'held', expires_at = ? WHERE username_norm = ?",
      heldUntil, fromNorm,
    );
    return 'ok' as const;
  });
  if (outcome !== 'ok') return { ok: false, reason: outcome };
  await ctx.scheduleSweep(heldUntil);
  return { ok: true, username: target.display, heldUntil };
}
