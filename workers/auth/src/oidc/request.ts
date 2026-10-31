/**
 * Parse and validate a GET /authorize request (OIDC Core §3.1.2.1, OAuth 2.1).
 *
 * Errors before client_id + redirect_uri are known good render an error page
 * (never redirect to an unverified URI); later errors go back to the client
 * as `?error=…&error_description=…&state=…&iss=…`.
 */

import { config } from '../config';
import type { OAuthClientRecord } from './clients';
import { PKCE_PATTERN } from './formats';
import type { AuthorizeRequest } from './types';

/** Internal parameter: set when we send the user to log in, so the forced login isn't asked for twice. */
export const AUTH_AFTER_PARAM = 'bcn_auth_after';

const SINGLE_PARAMS = [
  'client_id', 'redirect_uri', 'response_type', 'scope', 'state', 'nonce', 'code_challenge',
  'code_challenge_method', 'prompt', 'max_age', 'response_mode', AUTH_AFTER_PARAM,
];

export type ParsedAuthorize =
  | { ok: true; request: AuthorizeRequest; client: OAuthClientRecord }
  /** Show an error page: the redirect URI can't be trusted. */
  | { ok: false; redirect: false; error: string; description: string }
  /** Redirect the error to the client. */
  | { ok: false; redirect: true; redirectUri: string; state?: string; error: string; description: string };

/** Fewer than 10 years, as seconds. */
const MAX_AGE_LIMIT = 10 * 365 * 24 * 3600;

export async function parseAuthorizeRequest(
  params: URLSearchParams,
  getClient: (clientId: string) => Promise<OAuthClientRecord | null>,
): Promise<ParsedAuthorize> {
  const page = (description: string, error = 'invalid_request'): ParsedAuthorize =>
    ({ ok: false, redirect: false, error, description });

  for (const name of ['client_id', 'redirect_uri']) {
    if (params.getAll(name).length > 1) return page(`${name} was given more than once.`);
  }
  const clientId = params.get('client_id') ?? '';
  if (!clientId || clientId.length > 128) return page('The request has no client_id.');
  const client = await getClient(clientId);
  if (!client || client.disabledAt !== null) return page('This application is not registered (or has been disabled).', 'invalid_client');
  const redirectUri = params.get('redirect_uri') ?? '';
  if (!redirectUri) return page('The request has no redirect_uri.');
  // Exact string match against the registered list (no normalization, no wildcards).
  if (!client.redirectUris.includes(redirectUri)) return page('The redirect_uri is not registered for this application.');

  // From here on, errors go back to the client.
  const rawState = params.get('state') ?? undefined;
  const state = rawState !== undefined && rawState.length <= config.OIDC_MAX_PARAM_LENGTH ? rawState : undefined;
  const fail = (error: string, description: string): ParsedAuthorize =>
    ({ ok: false, redirect: true, redirectUri, state, error, description });

  for (const name of SINGLE_PARAMS) {
    if (params.getAll(name).length > 1) return fail('invalid_request', `${name} was given more than once.`);
    if ((params.get(name)?.length ?? 0) > config.OIDC_MAX_PARAM_LENGTH) return fail('invalid_request', `${name} is too long.`);
  }
  if (params.has('request')) return fail('request_not_supported', 'Request objects are not supported.');
  if (params.has('request_uri')) return fail('request_uri_not_supported', 'request_uri is not supported.');

  if (params.get('response_type') !== 'code') {
    return fail('unsupported_response_type', 'Only response_type=code is supported.');
  }
  const responseMode = params.get('response_mode');
  if (responseMode !== null && responseMode !== 'query') return fail('invalid_request', 'Only response_mode=query is supported.');

  const requested = (params.get('scope') ?? '').split(' ').filter(Boolean);
  if (!requested.includes('openid')) return fail('invalid_scope', 'The openid scope is required.');
  // Unknown scopes are ignored; ones the client may not have are dropped (the token response says what was granted).
  const scopes = config.OIDC_SCOPES.filter((s) => requested.includes(s) && client.allowedScopes.includes(s));

  const codeChallenge = params.get('code_challenge') ?? '';
  if (!codeChallenge) return fail('invalid_request', 'PKCE is required: send code_challenge (S256).');
  if (params.get('code_challenge_method') !== 'S256') return fail('invalid_request', 'code_challenge_method must be S256.');
  if (!PKCE_PATTERN.test(codeChallenge)) return fail('invalid_request', 'code_challenge is malformed.');

  const promptValues = (params.get('prompt') ?? '').split(' ').filter(Boolean);
  const prompt = {
    none: promptValues.includes('none'),
    login: promptValues.includes('login'),
    consent: promptValues.includes('consent'),
  };
  if (prompt.none && promptValues.length > 1) return fail('invalid_request', 'prompt=none cannot be combined with other values.');

  let maxAge: number | undefined;
  const rawMaxAge = params.get('max_age');
  if (rawMaxAge !== null) {
    if (!/^\d{1,10}$/.test(rawMaxAge) || Number(rawMaxAge) > MAX_AGE_LIMIT) return fail('invalid_request', 'max_age must be a number of seconds.');
    maxAge = Number(rawMaxAge);
  }

  let authAfter: number | undefined;
  const rawAfter = params.get(AUTH_AFTER_PARAM);
  if (rawAfter !== null && /^\d{1,12}$/.test(rawAfter)) authAfter = Number(rawAfter);

  const request: AuthorizeRequest = { clientId, redirectUri, scopes, codeChallenge, prompt };
  if (rawState !== undefined) request.state = rawState;
  const nonce = params.get('nonce');
  if (nonce !== null) request.nonce = nonce;
  if (maxAge !== undefined) request.maxAge = maxAge;
  if (authAfter !== undefined) request.authAfter = authAfter;
  return { ok: true, request, client };
}

/** Append authorization-response parameters to a registered redirect URI (keeps its own query). */
export function redirectWith(redirectUri: string, params: Record<string, string | undefined>): string {
  const url = new URL(redirectUri);
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) url.searchParams.set(key, value);
  }
  return url.href;
}
