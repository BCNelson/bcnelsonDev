/**
 * Per-user, per-method password backoff policy (design §7). Pure functions;
 * the User DO persists the state in `login_attempts`.
 */

import { config } from '../config';

/** Mirrors a `login_attempts` row. Times are epoch ms. */
export interface AttemptState {
  failures: number;
  lastFailureAt: number | null;
  lockedUntil: number | null;
}

export interface BackoffDecision {
  /** False while locked out; the attempt must not be checked at all. */
  allowed: boolean;
  /** The attempt needs a valid Turnstile token. */
  needsTurnstile: boolean;
  /** How long until the lock lifts; 0 when allowed. */
  retryAfterMs: number;
}

export const EMPTY_ATTEMPTS: AttemptState = { failures: 0, lastFailureAt: null, lockedUntil: null };

/** Decide whether an attempt may proceed now. */
export function checkBackoff(state: AttemptState, now: number): BackoffDecision {
  const locked = state.lockedUntil !== null && now < state.lockedUntil;
  return {
    allowed: !locked,
    needsTurnstile: state.failures >= config.TURNSTILE_AFTER_FAILURES,
    retryAfterMs: locked ? state.lockedUntil! - now : 0,
  };
}

/** Lock duration after the `failures`-th consecutive failure; 0 below the threshold. */
export function lockoutDuration(failures: number): number {
  if (failures < config.BACKOFF_AFTER_FAILURES) return 0;
  const exponent = failures - config.BACKOFF_AFTER_FAILURES;
  // Cap the exponent so huge failure counts can't overflow to Infinity/NaN.
  const factor = 2 ** Math.min(exponent, 30);
  return Math.min(config.BACKOFF_BASE * factor, config.BACKOFF_MAX);
}

/** State after a failed attempt, plus whether to email the primary address. */
export function recordFailure(
  state: AttemptState,
  now: number,
): { state: AttemptState; shouldAlert: boolean } {
  const failures = state.failures + 1;
  const lock = lockoutDuration(failures);
  return {
    state: { failures, lastFailureAt: now, lockedUntil: lock > 0 ? now + lock : null },
    shouldAlert: failures === config.ALERT_AFTER_FAILURES,
  };
}

/** State after a successful attempt: everything resets. */
export function recordSuccess(): AttemptState {
  return { ...EMPTY_ATTEMPTS };
}
