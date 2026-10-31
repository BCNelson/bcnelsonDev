/**
 * What UserIndex feature modules (src/do/index/*) get from the DO class.
 * Feature logic lives in plain functions over this context; the class methods
 * only build it and delegate.
 */

import type { Env } from '../../env';

export interface IndexContext {
  sql: SqlStorage;
  storage: DurableObjectStorage;
  env: Env;
  /** Request time, epoch ms. Take it once per call so a call sees one "now". */
  now: number;
  /** Make sure the expiry sweep runs by `at`. Call whenever an expiring row is written. */
  scheduleSweep(at: number): Promise<void>;
}

/** True when an index row with this status/expiry still blocks a new claim. */
export function isLive(status: string, expiresAt: number | null, now: number): boolean {
  return status === 'active' || (expiresAt ?? Infinity) > now;
}
