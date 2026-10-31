/**
 * Server-side Turnstile verification (siteverify).
 *
 * Secret: TURNSTILE_SECRET from the Secrets Store, else TURNSTILE_SECRET_DEV.
 *
 * Local dev (COOKIE_DOMAIN is a dev domain, see isDevDomain):
 * - Preferred: use Cloudflare's documented test keys, which really call
 *   siteverify. Site key `1x00000000000000000000AA` (TURNSTILE_SITE_KEY var
 *   override) renders an always-passing widget, and secret
 *   `1x0000000000000000000000000000000AA` (TURNSTILE_SECRET_DEV in .dev.vars)
 *   accepts any token, including the dummy `XXXX.DUMMY.TOKEN.XXXX`. Secret
 *   `2x0000000000000000000000000000000AA` always fails.
 * - If no secret is available at all, verification is skipped and passes
 *   (`skipped: true`), so `wrangler dev` works without any Turnstile setup.
 *
 * Production (any other COOKIE_DOMAIN) fails closed: a missing secret, a
 * test secret, a network error or a timeout all count as failure.
 */

import { config } from '../config';
import type { Env } from '../env';
import { isDevDomain } from './index';

export type TurnstileResult =
  | { ok: true; skipped?: boolean }
  | { ok: false; reason: 'missing' | 'invalid' | 'unavailable'; errors?: string[] };

export interface TurnstileOptions {
  /** Injectable for tests. */
  fetch?: typeof fetch;
}

/** Cloudflare's dummy secrets ("1x", "2x", "3x" prefixes) are never valid in production. */
const TEST_SECRET = /^[123]x0{30,}A{2}$/;
/** Tokens are at most 2048 characters (Cloudflare docs). */
const MAX_TOKEN_LENGTH = 2048;

type TurnstileEnv = Pick<Env, 'COOKIE_DOMAIN' | 'TURNSTILE_SECRET' | 'TURNSTILE_SECRET_DEV'>;

/** Verify a widget token for the request from `ip`. Never throws. */
export async function verifyTurnstile(
  env: TurnstileEnv,
  token: string | null | undefined,
  ip?: string,
  options: TurnstileOptions = {},
): Promise<TurnstileResult> {
  const dev = isDevDomain(env.COOKIE_DOMAIN);
  const secret = await readSecret(env);
  if (!secret) {
    if (dev) return { ok: true, skipped: true };
    console.error('TURNSTILE_SECRET is not available');
    return { ok: false, reason: 'unavailable' };
  }
  if (!dev && TEST_SECRET.test(secret)) {
    console.error('TURNSTILE_SECRET is a test secret; refusing in production');
    return { ok: false, reason: 'unavailable' };
  }
  if (!token || token.length > MAX_TOKEN_LENGTH) return { ok: false, reason: 'missing' };

  const body = new FormData();
  body.set('secret', secret);
  body.set('response', token);
  if (ip) body.set('remoteip', ip);
  const doFetch = options.fetch ?? fetch;
  try {
    const res = await doFetch(config.TURNSTILE_SITEVERIFY_URL, {
      method: 'POST',
      body,
      signal: AbortSignal.timeout(config.TURNSTILE_TIMEOUT),
    });
    if (!res.ok) return { ok: false, reason: 'unavailable' };
    const data = (await res.json()) as { success?: unknown; 'error-codes'?: unknown };
    if (data.success === true) return { ok: true };
    const errors = Array.isArray(data['error-codes'])
      ? data['error-codes'].filter((e): e is string => typeof e === 'string')
      : [];
    return { ok: false, reason: 'invalid', errors };
  } catch (err) {
    console.error('turnstile siteverify failed', err);
    return { ok: false, reason: 'unavailable' };
  }
}

async function readSecret(env: TurnstileEnv): Promise<string | null> {
  try {
    const value = await env.TURNSTILE_SECRET?.get();
    if (value) return value;
  } catch {
    // Not in the store (local dev); fall through.
  }
  return env.TURNSTILE_SECRET_DEV || null;
}
