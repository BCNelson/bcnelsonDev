/**
 * Social login provider adapters (design §6.7). Each provider is one object
 * implementing OAuthProvider; register it in ./index.ts PROVIDERS and add
 * its client ID var + client secret binding (env.ts, wrangler.json).
 *
 * The routes (routes/oauth.ts) own state, PKCE verifiers, cookies and
 * account logic; an adapter only builds the authorization URL and turns a
 * code into a normalized ProviderProfile.
 */

import type { Env } from '../env';

/** What the routes need to know about the person who signed in at the provider. */
export interface ProviderProfile {
  /** Stable, provider-unique account id (never the email or username). */
  subject: string;
  /** Best email the provider gave us, display form. */
  email?: string;
  /** True only when the provider vouches that `email` is verified. */
  emailVerified: boolean;
  name?: string;
  /** https avatar URL. */
  picture?: string;
  /** Provider handle (e.g. GitHub login): a username suggestion. */
  username?: string;
}

/** Outbound HTTP, injectable for tests. Defaults to the global fetch at call time. */
export interface OAuthDeps {
  fetch: typeof fetch;
}

export interface OAuthProvider {
  /** URL segment and `identities.provider` value, e.g. 'github'. Never change it once shipped. */
  id: string;
  /** Button text: "Continue with <label>". */
  label: string;
  /** False when the client ID is unset: hidden from pages, routes answer 404. */
  enabled(env: Env): boolean;
  /** Where to send the browser. `verifier` is the PKCE code verifier (S256). */
  authorizationUrl(env: Env, state: string, verifier: string): Promise<URL>;
  /** Exchange the callback's code. Throws OAuthExchangeError (or anything) on failure. */
  exchange(env: Env, code: string, verifier: string, deps?: OAuthDeps): Promise<ProviderProfile>;
}

/** A provider answered with something we can't use. Message is safe to log, never shown to users. */
export class OAuthExchangeError extends Error {
  override name = 'OAuthExchangeError';
}

/** `${ISSUER}/oauth/<id>/callback`, the redirect URI registered with each provider. */
export function redirectUri(env: Env, providerId: string): string {
  return `${env.ISSUER.replace(/\/+$/, '')}/oauth/${providerId}/callback`;
}

/** Secrets Store first, then the `_DEV` string fallback (like AUTH_SIGNING_KEY_DEV). */
export async function readSecret(
  secret: SecretsStoreSecret | undefined,
  dev: string | undefined,
  name: string,
): Promise<string> {
  try {
    const value = await secret?.get();
    if (value) return value;
  } catch (err) {
    if (!dev) throw err;
  }
  if (dev) return dev;
  throw new Error(`${name} is not set`);
}

/** Calls the global fetch at call time (so a stubbed global works); one object, so caches keyed on it hold. */
const DEFAULT_DEPS: OAuthDeps = { fetch: (input, init) => fetch(input, init) };

/** The default deps (global fetch). Requests set their own timeouts. */
export function defaultDeps(): OAuthDeps {
  return DEFAULT_DEPS;
}

/** Trimmed string of at most `max` characters, or undefined. */
export function cleanString(value: unknown, max: number): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > max) return undefined;
  return trimmed;
}

/** An https URL of at most `max` characters, or undefined. */
export function cleanHttpsUrl(value: unknown, max: number): string | undefined {
  const s = cleanString(value, max);
  if (!s) return undefined;
  try {
    return new URL(s).protocol === 'https:' ? s : undefined;
  } catch {
    return undefined;
  }
}
