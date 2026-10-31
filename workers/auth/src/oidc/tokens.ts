/**
 * Tokens for OIDC clients. Both are EdDSA JWTs from the same key set as the
 * site cookie JWT, but `aud` is always the client_id, never config.AUDIENCE,
 * so a client token can never pass as a bcnelson.dev cookie token (and vice
 * versa: verifyClientAccessToken refuses config.AUDIENCE).
 *
 * Access token (RFC 9068 shape, header typ `at+jwt`):
 *   iss, sub, aud = client_id, client_id, scope, sid, gid (oauth_tokens id),
 *   auth_time, iat, exp, jti
 * ID token (typ `JWT`):
 *   iss, sub, aud = client_id, azp, iat, exp, auth_time, nonce?, at_hash, sid,
 *   amr, + claims by scope (oidc/claims.ts)
 *
 * at_hash: EdDSA/Ed25519 uses SHA-512 (OIDC Core errata), left half, base64url.
 */

import { SignJWT, compactVerify, createLocalJWKSet, decodeProtectedHeader, jwtVerify, type JWTPayload } from 'jose';
import { config } from '../config';
import { toBase64url } from '../crypto/hash';
import { randomToken } from '../crypto/ids';
import type { Env } from '../env';
import { SIGNING_ALG, getJwks, loadKeySet } from '../tokens';
import type { UserClaims } from '../types';
import { scopedClaims } from './claims';
import { TOKEN_ID_PATTERN } from './formats';

export const ACCESS_TOKEN_TYP = 'at+jwt';

export interface ClientAccessTokenPayload extends JWTPayload {
  iss: string;
  sub: string;
  aud: string;
  client_id: string;
  scope: string;
  sid: string;
  gid: string;
  auth_time: number;
  iat: number;
  exp: number;
}

export interface SignedClientTokens {
  accessToken: string;
  idToken: string;
  /** Seconds until the access token expires. */
  expiresIn: number;
}

export interface SignClientTokensInput {
  clientId: string;
  claims: UserClaims;
  scopes: string[];
  tokenId: string;
  nonce?: string;
}

/** at_hash for an EdDSA (Ed25519) signed ID token. */
export async function atHash(accessToken: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-512', new TextEncoder().encode(accessToken)));
  return toBase64url(digest.slice(0, digest.length / 2));
}

/** Sign the access token and ID token for one token-endpoint response. */
export async function signClientTokens(env: Env, input: SignClientTokensInput, now = Date.now()): Promise<SignedClientTokens> {
  if (input.clientId === config.AUDIENCE) throw new Error('client tokens may not use the site audience');
  const { current } = await loadKeySet(env);
  const iat = Math.floor(now / 1000);
  const accessExp = iat + Math.floor(config.OIDC_ACCESS_TOKEN_TTL / 1000);
  const { claims } = input;

  const accessToken = await new SignJWT({
    client_id: input.clientId,
    scope: input.scopes.join(' '),
    sid: claims.sid,
    gid: input.tokenId,
    auth_time: claims.auth_time,
    jti: randomToken(16),
  })
    .setProtectedHeader({ alg: SIGNING_ALG, typ: ACCESS_TOKEN_TYP, kid: current.kid })
    .setIssuer(env.ISSUER)
    .setSubject(claims.sub)
    .setAudience(input.clientId)
    .setIssuedAt(iat)
    .setExpirationTime(accessExp)
    .sign(current.privateKey);

  const idPayload: JWTPayload = {
    ...scopedClaims(claims, input.scopes),
    azp: input.clientId,
    auth_time: claims.auth_time,
    sid: claims.sid,
    amr: claims.amr,
    at_hash: await atHash(accessToken),
  };
  if (input.nonce !== undefined) idPayload.nonce = input.nonce;
  const idToken = await new SignJWT(idPayload)
    .setProtectedHeader({ alg: SIGNING_ALG, typ: 'JWT', kid: current.kid })
    .setIssuer(env.ISSUER)
    .setSubject(claims.sub)
    .setAudience(input.clientId)
    .setIssuedAt(iat)
    .setExpirationTime(iat + Math.floor(config.OIDC_ID_TOKEN_TTL / 1000))
    .sign(current.privateKey);

  return { accessToken, idToken, expiresIn: accessExp - iat };
}

/**
 * Verify a client access token (signature, iss, exp, typ at+jwt, shape).
 * The caller still checks that `aud` is a registered, enabled client.
 */
export async function verifyClientAccessToken(env: Env, token: string): Promise<ClientAccessTokenPayload | null> {
  try {
    const { payload } = await jwtVerify(token, createLocalJWKSet(await getJwks(env)), {
      issuer: env.ISSUER,
      algorithms: [SIGNING_ALG],
      typ: ACCESS_TOKEN_TYP,
    });
    const p = payload as Partial<ClientAccessTokenPayload>;
    if (typeof p.aud !== 'string' || p.aud === config.AUDIENCE || p.client_id !== p.aud) return null;
    if (typeof p.sub !== 'string' || typeof p.sid !== 'string' || typeof p.scope !== 'string') return null;
    if (typeof p.gid !== 'string' || !TOKEN_ID_PATTERN.test(p.gid)) return null;
    return p as ClientAccessTokenPayload;
  } catch {
    return null;
  }
}

/**
 * An id_token_hint for RP-initiated logout: our signature and issuer, an ID
 * token (not an access token); expiry is ignored, as the spec allows. Returns
 * its aud (client id), sub and sid, or null.
 */
export async function verifyIdTokenHint(env: Env, token: string): Promise<{ aud: string; sub: string; sid?: string } | null> {
  try {
    if (decodeProtectedHeader(token).typ === ACCESS_TOKEN_TYP) return null;
    const { payload } = await compactVerify(token, createLocalJWKSet(await getJwks(env)), { algorithms: [SIGNING_ALG] });
    const claims = JSON.parse(new TextDecoder().decode(payload)) as JWTPayload & { sid?: unknown };
    if (claims.iss !== env.ISSUER || typeof claims.aud !== 'string' || typeof claims.sub !== 'string') return null;
    if (claims.aud === config.AUDIENCE) return null;
    return { aud: claims.aud, sub: claims.sub, sid: typeof claims.sid === 'string' ? claims.sid : undefined };
  } catch {
    return null;
  }
}
