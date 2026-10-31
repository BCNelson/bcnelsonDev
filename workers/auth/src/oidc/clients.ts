/**
 * OAuth client registry rules (design §9): what a registered client looks
 * like, and validation of admin input. Pure; storage is do/index/clients.ts.
 *
 * - client_id: `^[a-z0-9][a-z0-9._-]{2,63}$`, generated (`cli_<ulid>`) when
 *   not given. Never the site audience / cookie domain / auth host, and a
 *   non-first-party client may not borrow the site's name.
 * - redirect URIs: absolute, canonical (`new URL(u).href === u`), no fragment
 *   or userinfo; https, or http on loopback / a dev domain. Never on the auth
 *   host itself. Site hosts (*.COOKIE_DOMAIN) only for first-party clients.
 *   Matching at /authorize is exact string equality.
 * - allowed scopes: a subset of OIDC_SCOPES that includes `openid`.
 * - confidential clients authenticate with a secret (SHA-256 stored, shown once).
 */

import { config } from '../config';
import { sha256Base64url, timingSafeEqual } from '../crypto/hash';
import { randomToken, ulid } from '../crypto/ids';
import type { Env } from '../env';
import { isDevDomain } from '../http';

/** A registered client as stored (secret hash included; never send it to a browser). */
export interface OAuthClientRecord {
  clientId: string;
  name: string;
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  allowedScopes: string[];
  firstParty: boolean;
  confidential: boolean;
  /** SHA-256 (base64url) of the client secret; null for public clients. */
  secretHash: string | null;
  createdAt: number;
  updatedAt: number;
  disabledAt: number | null;
}

/** The admin view: everything but the secret hash. */
export type OAuthClientInfo = Omit<OAuthClientRecord, 'secretHash'> & { hasSecret: boolean };

export function clientInfo(record: OAuthClientRecord): OAuthClientInfo {
  const { secretHash, ...rest } = record;
  return { ...rest, hasSecret: secretHash !== null };
}

/** Validated fields for create/update. */
export interface ClientFields {
  name: string;
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  allowedScopes: string[];
  firstParty: boolean;
}

export const CLIENT_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{2,63}$/;
/** Generated client secrets: `cs1_` + 32 random bytes. */
const SECRET_PATTERN = /^cs1_[A-Za-z0-9_-]{43}$/;

export function newClientId(): string {
  return `cli_${ulid().toLowerCase()}`;
}

/** A fresh client secret and its stored hash. */
export async function newClientSecret(): Promise<{ secret: string; hash: string }> {
  const secret = `cs1_${randomToken()}`;
  return { secret, hash: await sha256Base64url(secret) };
}

/** Constant-time check of a presented secret against the stored hash. */
export async function verifyClientSecret(record: OAuthClientRecord, presented: string): Promise<boolean> {
  if (!record.secretHash || !SECRET_PATTERN.test(presented)) return false;
  return timingSafeEqual(await sha256Base64url(presented), record.secretHash);
}

export type ClientValidation<T> = { ok: true; value: T } | { ok: false; error: string; message: string };

function bad<T>(error: string, message: string): ClientValidation<T> {
  return { ok: false, error, message };
}

function siteDomain(env: Pick<Env, 'COOKIE_DOMAIN'>): string {
  return env.COOKIE_DOMAIN.toLowerCase();
}

function authHost(env: Pick<Env, 'ISSUER'>): string {
  try {
    return new URL(env.ISSUER).hostname.toLowerCase();
  } catch {
    return '';
  }
}

/** True when `host` is the site domain or a subdomain of it. */
function isSiteHost(host: string, env: Pick<Env, 'COOKIE_DOMAIN'>): boolean {
  const domain = siteDomain(env);
  return host === domain || host.endsWith(`.${domain}`);
}

/** The site's own name (first label of COOKIE_DOMAIN, e.g. `bcnelson`). */
function siteName(env: Pick<Env, 'COOKIE_DOMAIN'>): string {
  return siteDomain(env).split('.')[0] ?? '';
}

/** A client id chosen by an admin (or the generated default). */
export function validateClientId(
  raw: unknown,
  firstParty: boolean,
  env: Pick<Env, 'COOKIE_DOMAIN' | 'ISSUER'>,
): ClientValidation<string> {
  if (raw === undefined || raw === null || raw === '') return { ok: true, value: newClientId() };
  if (typeof raw !== 'string' || !CLIENT_ID_PATTERN.test(raw)) {
    return bad('invalid_client_id', 'Client ids are 3–64 characters: lowercase letters, digits, ".", "_" or "-".');
  }
  const reserved = new Set([config.AUDIENCE.toLowerCase(), siteDomain(env), authHost(env)]);
  if (reserved.has(raw)) return bad('invalid_client_id', 'That client id is reserved.');
  if (!firstParty && (raw.includes(siteDomain(env)) || raw.includes(siteName(env)))) {
    return bad('invalid_client_id', "Only first-party clients may use the site's name in their id.");
  }
  return { ok: true, value: raw };
}

/** One redirect (or post-logout redirect) URI. */
export function validateRedirectUri(
  raw: unknown,
  firstParty: boolean,
  env: Pick<Env, 'COOKIE_DOMAIN' | 'ISSUER'>,
): ClientValidation<string> {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > config.MAX_RETURN_TO_LENGTH) {
    return bad('invalid_redirect_uri', 'Redirect URIs must be absolute URLs.');
  }
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return bad('invalid_redirect_uri', `Not a URL: ${raw}`);
  }
  if (url.href !== raw) return bad('invalid_redirect_uri', `Use the canonical form: ${url.href}`);
  if (url.hash || raw.includes('#')) return bad('invalid_redirect_uri', 'Redirect URIs may not have a fragment.');
  if (url.username || url.password) return bad('invalid_redirect_uri', 'Redirect URIs may not have userinfo.');
  const host = url.hostname.toLowerCase();
  const loopback = host === 'localhost' || host === '127.0.0.1' || host === '[::1]' || host.endsWith('.localhost');
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && (loopback || isDevDomain(host)))) {
    return bad('invalid_redirect_uri', 'Redirect URIs must use https (http only for localhost).');
  }
  if (host === authHost(env)) return bad('invalid_redirect_uri', 'Redirect URIs may not point at the auth server.');
  if (!firstParty && isSiteHost(host, env)) {
    return bad('invalid_redirect_uri', `Only first-party clients may redirect to ${siteDomain(env)}.`);
  }
  return { ok: true, value: raw };
}

function stringList(raw: unknown): string[] | null {
  if (raw === undefined || raw === null) return [];
  if (typeof raw === 'string') return raw.split(/[\s,]+/).filter(Boolean);
  if (Array.isArray(raw) && raw.every((v) => typeof v === 'string')) return raw as string[];
  return null;
}

function bool(raw: unknown): boolean | null {
  if (raw === undefined || raw === null || raw === '') return false;
  if (raw === true || raw === 'true' || raw === 'on' || raw === '1') return true;
  if (raw === false || raw === 'false' || raw === '0') return false;
  return null;
}

/** Validate create/update input (`{ name, redirect_uris, post_logout_redirect_uris, allowed_scopes, first_party }`). */
export function validateClientFields(
  input: Record<string, unknown>,
  env: Pick<Env, 'COOKIE_DOMAIN' | 'ISSUER'>,
): ClientValidation<ClientFields> {
  const firstParty = bool(input.first_party);
  if (firstParty === null) return bad('bad_request', 'first_party must be a boolean.');

  const name = typeof input.name === 'string' ? input.name.trim() : '';
  if (!name || [...name].length > config.OIDC_CLIENT_NAME_MAX_LENGTH || /[\u0000-\u001f\u007f]/.test(name)) {
    return bad('invalid_name', `Give the client a name (at most ${config.OIDC_CLIENT_NAME_MAX_LENGTH} characters).`);
  }
  if (!firstParty) {
    const lower = name.toLowerCase();
    if (lower.includes(siteDomain(env)) || lower.includes(siteName(env))) {
      return bad('invalid_name', "Only first-party clients may use the site's name.");
    }
  }

  const redirects = stringList(input.redirect_uris);
  const logouts = stringList(input.post_logout_redirect_uris);
  if (!redirects || !logouts) return bad('bad_request', 'Redirect URIs must be a list of strings.');
  if (redirects.length === 0) return bad('invalid_redirect_uri', 'Add at least one redirect URI.');
  if (redirects.length > config.OIDC_MAX_REDIRECT_URIS || logouts.length > config.OIDC_MAX_REDIRECT_URIS) {
    return bad('invalid_redirect_uri', `At most ${config.OIDC_MAX_REDIRECT_URIS} URIs of each kind.`);
  }
  for (const uri of [...redirects, ...logouts]) {
    const checked = validateRedirectUri(uri, firstParty, env);
    if (!checked.ok) return checked;
  }

  const scopes = stringList(input.allowed_scopes ?? ['openid']);
  if (!scopes || !scopes.every((s) => config.OIDC_SCOPES.includes(s))) {
    return bad('invalid_scope', `Scopes must be from: ${config.OIDC_SCOPES.join(', ')}.`);
  }
  if (!scopes.includes('openid')) return bad('invalid_scope', 'Allowed scopes must include openid.');

  return {
    ok: true,
    value: {
      name,
      redirectUris: [...new Set(redirects)],
      postLogoutRedirectUris: [...new Set(logouts)],
      allowedScopes: config.OIDC_SCOPES.filter((s) => scopes.includes(s)),
      firstParty,
    },
  };
}
