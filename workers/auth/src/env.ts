/// <reference types="@cloudflare/workers-types" />
/**
 * Bindings for the auth Worker. Mirrors wrangler.json; keep the two in sync.
 */

import type { UserIndex } from './do/user-index';
import type { User } from './do/user';

export interface Env {
  // vars
  ISSUER: string;
  COOKIE_DOMAIN: string;
  RP_ID: string;
  /** Comma-separated origins allowed to make state-changing requests. */
  ALLOWED_ORIGINS: string;
  /** Comma-separated emails granted `admin` on login. */
  ADMIN_EMAILS: string;
  TURNSTILE_SITE_KEY: string;

  // secrets (Secrets Store)
  TURNSTILE_SECRET: SecretsStoreSecret;
  /** Local-dev fallback for TURNSTILE_SECRET, set in .dev.vars (see http/turnstile.ts). */
  TURNSTILE_SECRET_DEV?: string;
  /** Ed25519 private JWK (JSON string) with a `kid`. */
  AUTH_SIGNING_KEY: SecretsStoreSecret;
  /** Local-dev fallback for AUTH_SIGNING_KEY, set in .dev.vars. */
  AUTH_SIGNING_KEY_DEV?: string;

  // social login (src/oauth/). A provider with an empty client ID is hidden and disabled.
  GITHUB_CLIENT_ID?: string;
  GITHUB_CLIENT_SECRET?: SecretsStoreSecret;
  /** Local-dev fallback for GITHUB_CLIENT_SECRET, set in .dev.vars. */
  GITHUB_CLIENT_SECRET_DEV?: string;
  GOOGLE_CLIENT_ID?: string;
  GOOGLE_CLIENT_SECRET?: SecretsStoreSecret;
  /** Local-dev fallback for GOOGLE_CLIENT_SECRET, set in .dev.vars. */
  GOOGLE_CLIENT_SECRET_DEV?: string;

  // rate limiting
  RL_IP: RateLimit;
  RL_IDENTIFIER: RateLimit;

  // durable objects
  USER_INDEX: DurableObjectNamespace<UserIndex>;
  USER: DurableObjectNamespace<User>;

  // email — Cloudflare Email Service `send_email` binding; absent → dev mailer
  EMAIL?: SendEmail;
}
