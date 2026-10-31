/**
 * Sliding-window limits for per-user actions (design §7, `action_limits`).
 * Pure functions over the timestamps of earlier actions.
 */

import { config } from '../config';

export type LimitedAction = 'password_reset' | 'verification_send' | 'email_add';

export interface WindowDecision {
  allowed: boolean;
  /** Actions still allowed in the current window (after this one, if allowed). */
  remaining: number;
  /** How long until one more action is allowed; 0 when allowed. */
  retryAfterMs: number;
  /** Timestamps before this are outside the window and can be deleted. */
  windowStart: number;
}

/** Generic sliding window: at most `max` events in any `windowMs` span. */
export function slidingWindow(
  timestamps: readonly number[],
  now: number,
  max: number,
  windowMs: number,
): WindowDecision {
  const windowStart = now - windowMs;
  const inWindow = timestamps.filter((t) => t > windowStart).sort((a, b) => a - b);
  if (inWindow.length < max) {
    return { allowed: true, remaining: max - inWindow.length - 1, retryAfterMs: 0, windowStart };
  }
  // Allowed again once enough of the oldest events have aged out.
  const unblockAt = inWindow[inWindow.length - max]! + windowMs;
  return { allowed: false, remaining: 0, retryAfterMs: Math.max(0, unblockAt - now), windowStart };
}

/** Configured limit for `action` (config.ACTION_LIMITS). */
export function actionLimit(action: LimitedAction): readonly [number, number] {
  const limit = config.ACTION_LIMITS[action];
  if (!limit) throw new Error(`No action limit configured for ${action}`);
  return limit;
}

/** Sliding window using the configured limit for `action`. */
export function checkActionLimit(
  action: LimitedAction,
  timestamps: readonly number[],
  now: number,
): WindowDecision {
  const [max, windowMs] = actionLimit(action);
  return slidingWindow(timestamps, now, max, windowMs);
}
