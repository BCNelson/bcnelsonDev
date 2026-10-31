import { describe, expect, it } from 'vitest';
import { config } from '../src/config';
import {
  type AttemptState,
  EMPTY_ATTEMPTS,
  actionLimit,
  checkActionLimit,
  checkBackoff,
  checkIdentifier,
  checkIp,
  lockoutDuration,
  recordFailure,
  recordSuccess,
  slidingWindow,
} from '../src/ratelimit';

const NOW = 1_800_000_000_000;

function failTimes(n: number, at = NOW): { state: AttemptState; alerts: number[] } {
  let state = EMPTY_ATTEMPTS;
  const alerts: number[] = [];
  for (let i = 1; i <= n; i++) {
    const r = recordFailure(state, at);
    state = r.state;
    if (r.shouldAlert) alerts.push(i);
  }
  return { state, alerts };
}

describe('binding wrappers', () => {
  function fakeLimiter(success: boolean) {
    const keys: string[] = [];
    return { keys, limiter: { limit: async ({ key }: { key: string }) => { keys.push(key); return { success }; } } };
  }

  it('checkIp keys by IP', async () => {
    const { keys, limiter } = fakeLimiter(true);
    expect(await checkIp({ RL_IP: limiter }, '1.2.3.4')).toBe(true);
    expect(keys).toEqual(['1.2.3.4']);
  });

  it('checkIdentifier keys by login:<norm>', async () => {
    const { keys, limiter } = fakeLimiter(false);
    expect(await checkIdentifier({ RL_IDENTIFIER: limiter }, 'brad')).toBe(false);
    expect(keys).toEqual(['login:brad']);
  });
});

describe('password backoff', () => {
  it('allows freely with no failures', () => {
    expect(checkBackoff(EMPTY_ATTEMPTS, NOW)).toEqual({ allowed: true, needsTurnstile: false, retryAfterMs: 0 });
  });

  it('requires Turnstile from TURNSTILE_AFTER_FAILURES', () => {
    const before = failTimes(config.TURNSTILE_AFTER_FAILURES - 1).state;
    expect(checkBackoff(before, NOW).needsTurnstile).toBe(false);
    const at = failTimes(config.TURNSTILE_AFTER_FAILURES).state;
    expect(checkBackoff(at, NOW)).toEqual({ allowed: true, needsTurnstile: true, retryAfterMs: 0 });
  });

  it('locks from BACKOFF_AFTER_FAILURES with doubling, capped at BACKOFF_MAX', () => {
    expect(lockoutDuration(config.BACKOFF_AFTER_FAILURES - 1)).toBe(0);
    expect(lockoutDuration(config.BACKOFF_AFTER_FAILURES)).toBe(config.BACKOFF_BASE);
    expect(lockoutDuration(config.BACKOFF_AFTER_FAILURES + 1)).toBe(config.BACKOFF_BASE * 2);
    expect(lockoutDuration(config.BACKOFF_AFTER_FAILURES + 3)).toBe(config.BACKOFF_BASE * 8);
    expect(lockoutDuration(config.BACKOFF_AFTER_FAILURES + 50)).toBe(config.BACKOFF_MAX);
    expect(lockoutDuration(1e9)).toBe(config.BACKOFF_MAX);
  });

  it('blocks while locked and reports retryAfterMs, then allows again', () => {
    const { state } = failTimes(config.BACKOFF_AFTER_FAILURES);
    expect(state.lockedUntil).toBe(NOW + config.BACKOFF_BASE);
    expect(checkBackoff(state, NOW + 1000)).toEqual({
      allowed: false, needsTurnstile: true, retryAfterMs: config.BACKOFF_BASE - 1000,
    });
    expect(checkBackoff(state, NOW + config.BACKOFF_BASE).allowed).toBe(true);
  });

  it('alerts exactly once, at ALERT_AFTER_FAILURES', () => {
    expect(failTimes(config.ALERT_AFTER_FAILURES + 5).alerts).toEqual([config.ALERT_AFTER_FAILURES]);
  });

  it('success resets everything', () => {
    expect(recordSuccess()).toEqual({ failures: 0, lastFailureAt: null, lockedUntil: null });
    expect(recordSuccess()).not.toBe(EMPTY_ATTEMPTS);
  });

  it('is never permanent', () => {
    const { state } = failTimes(1000);
    expect(checkBackoff(state, NOW + config.BACKOFF_MAX).allowed).toBe(true);
  });
});

describe('sliding window', () => {
  it('allows up to max events per window', () => {
    expect(slidingWindow([], NOW, 3, 1000)).toEqual({
      allowed: true, remaining: 2, retryAfterMs: 0, windowStart: NOW - 1000,
    });
    expect(slidingWindow([NOW - 10, NOW - 5], NOW, 3, 1000)).toMatchObject({ allowed: true, remaining: 0 });
  });

  it('blocks at max and says when the oldest needed event ages out', () => {
    const d = slidingWindow([NOW - 900, NOW - 500, NOW - 100], NOW, 3, 1000);
    expect(d).toMatchObject({ allowed: false, remaining: 0, retryAfterMs: 100 });
    // With more events than max, the (n-max)th oldest decides.
    const e = slidingWindow([NOW - 950, NOW - 900, NOW - 500, NOW - 100], NOW, 3, 1000);
    expect(e.retryAfterMs).toBe(100);
  });

  it('ignores events outside the window, order-insensitively', () => {
    expect(slidingWindow([NOW - 100, NOW - 1000, NOW - 5000], NOW, 2, 1000).allowed).toBe(true);
  });

  it('uses config.ACTION_LIMITS', () => {
    const [max, windowMs] = actionLimit('password_reset');
    expect([max, windowMs]).toEqual(config.ACTION_LIMITS.password_reset);
    const times = Array.from({ length: max }, (_, i) => NOW - i);
    expect(checkActionLimit('password_reset', times, NOW).allowed).toBe(false);
    expect(checkActionLimit('password_reset', times, NOW + windowMs).allowed).toBe(true);
    expect(checkActionLimit('email_add', times, NOW).allowed).toBe(true);
  });
});
