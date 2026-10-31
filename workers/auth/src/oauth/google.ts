/**
 * Google (OpenID Connect). Scopes `openid email profile`, PKCE S256 via
 * arctic's `Google` client (token request uses the global fetch).
 *
 * The profile comes from the id_token, which we validate fully even though
 * it arrives straight from Google's token endpoint over TLS (OIDC Core
 * 3.1.3.7 would allow skipping the signature there): signature against
 * Google's JWKS (jose createRemoteJWKSet, cached per isolate and per fetch
 * implementation), `iss` (accounts.google.com, with or without https://),
 * `aud` = our client ID, `exp`/`iat` with a small clock tolerance, and a
 * non-empty `sub`. `email_verified` must be literally true to count.
 */

import { Google } from 'arctic';
import { createRemoteJWKSet, customFetch, jwtVerify, type JWTVerifyGetKey } from 'jose';
import { config } from '../config';
import type { Env } from '../env';
import {
  OAuthExchangeError,
  cleanHttpsUrl,
  cleanString,
  defaultDeps,
  readSecret,
  redirectUri,
  type OAuthDeps,
  type OAuthProvider,
  type ProviderProfile,
} from './types';

export const GOOGLE_JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs';
export const GOOGLE_ISSUERS = ['https://accounts.google.com', 'accounts.google.com'];
const SCOPES = ['openid', 'email', 'profile'];

async function client(env: Env): Promise<Google> {
  const secret = await readSecret(env.GOOGLE_CLIENT_SECRET, env.GOOGLE_CLIENT_SECRET_DEV, 'GOOGLE_CLIENT_SECRET');
  return new Google(env.GOOGLE_CLIENT_ID ?? '', secret, redirectUri(env, 'google'));
}

/** One remote key set per fetch implementation (production: one per isolate). */
const keySets = new WeakMap<typeof fetch, JWTVerifyGetKey>();

function googleKeys(deps: OAuthDeps): JWTVerifyGetKey {
  let keys = keySets.get(deps.fetch);
  if (!keys) {
    keys = createRemoteJWKSet(new URL(GOOGLE_JWKS_URL), {
      timeoutDuration: config.OAUTH_HTTP_TIMEOUT,
      [customFetch]: (url, options) => deps.fetch(url, options as RequestInit),
    });
    keySets.set(deps.fetch, keys);
  }
  return keys;
}

/** Validate a Google id_token for `clientId` and map its claims. */
export async function verifyGoogleIdToken(idToken: string, clientId: string, deps: OAuthDeps): Promise<ProviderProfile> {
  let payload;
  try {
    ({ payload } = await jwtVerify(idToken, googleKeys(deps), {
      issuer: GOOGLE_ISSUERS,
      audience: clientId,
      algorithms: ['RS256'],
      clockTolerance: 60,
      requiredClaims: ['sub', 'exp', 'iat'],
    }));
  } catch (err) {
    throw new OAuthExchangeError(`google id_token: ${(err as Error)?.message ?? err}`);
  }
  const subject = cleanString(payload.sub, 255);
  if (!subject) throw new OAuthExchangeError('google id_token: no sub');
  const email = cleanString(payload.email, 254);
  return {
    subject,
    email,
    emailVerified: Boolean(email) && payload.email_verified === true,
    name: cleanString(payload.name, config.PROFILE_NAME_MAX_LENGTH),
    picture: cleanHttpsUrl(payload.picture, config.PICTURE_URL_MAX_LENGTH),
    username: email ? cleanString(email.split('@')[0], 64) : undefined,
  };
}

export const google: OAuthProvider = {
  id: 'google',
  label: 'Google',
  enabled: (env) => Boolean(env.GOOGLE_CLIENT_ID),

  async authorizationUrl(env, state, verifier) {
    return (await client(env)).createAuthorizationURL(state, verifier, SCOPES);
  },

  async exchange(env, code, verifier, deps = defaultDeps()) {
    const tokens = await (await client(env)).validateAuthorizationCode(code, verifier);
    let idToken: string;
    try {
      idToken = tokens.idToken();
    } catch {
      throw new OAuthExchangeError('google: no id_token');
    }
    return verifyGoogleIdToken(idToken, env.GOOGLE_CLIENT_ID ?? '', deps);
  },
};
