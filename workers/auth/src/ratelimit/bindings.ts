/**
 * Thin wrappers over the Workers rate-limiting bindings (design §7). Limits
 * and periods are set on the bindings in wrangler.json.
 */

import type { Env } from '../env';

/** True when the request from `ip` is within the RL_IP limit. */
export async function checkIp(env: Pick<Env, 'RL_IP'>, ip: string): Promise<boolean> {
  const { success } = await env.RL_IP.limit({ key: ip });
  return success;
}

/** True when attempts against a normalized login identifier are within RL_IDENTIFIER. */
export async function checkIdentifier(
  env: Pick<Env, 'RL_IDENTIFIER'>,
  norm: string,
): Promise<boolean> {
  const { success } = await env.RL_IDENTIFIER.limit({ key: `login:${norm}` });
  return success;
}
