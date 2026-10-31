/**
 * Sliding-window counters for emails the UserIndex sends (signup codes and
 * already-registered notices), keyed `email:<norm>` / `ip:<ip>`. Rows carry
 * `expires_at` so the expiry sweep removes them.
 */

import { slidingWindow } from '../../ratelimit';

export interface SendLimit {
  key: string;
  max: number;
  windowMs: number;
}

/** Checks every limit; allowed only when all are. retryAfterMs is the longest wait. */
export function checkSends(
  sql: SqlStorage,
  limits: readonly SendLimit[],
  now: number,
): { allowed: boolean; retryAfterMs: number } {
  let allowed = true;
  let retryAfterMs = 0;
  for (const { key, max, windowMs } of limits) {
    const times = sql.exec<{ at: number }>(
      'SELECT at FROM send_limits WHERE key = ? AND at > ?', key, now - windowMs,
    ).toArray().map((r) => r.at);
    const decision = slidingWindow(times, now, max, windowMs);
    if (!decision.allowed) {
      allowed = false;
      retryAfterMs = Math.max(retryAfterMs, decision.retryAfterMs);
    }
  }
  return { allowed, retryAfterMs };
}

/** Records one send against every limit. Returns the latest expiry written. */
export function recordSends(sql: SqlStorage, limits: readonly SendLimit[], now: number): number {
  let latest = now;
  for (const { key, windowMs } of limits) {
    sql.exec('INSERT INTO send_limits (key, at, expires_at) VALUES (?, ?, ?)', key, now, now + windowMs);
    latest = Math.max(latest, now + windowMs);
  }
  return latest;
}
