/**
 * Access JWTs (design §3.3): EdDSA-signed, published via JWKS.
 */

import { SignJWT, createLocalJWKSet, jwtVerify, type JSONWebKeySet, type JWTPayload } from 'jose';
import { config } from '../config';
import type { Env } from '../env';
import type { UserClaims } from '../types';
import { SIGNING_ALG, loadKeySet } from './keys';

export { SIGNING_ALG, loadKeySet, parseKeySet, resetKeyCache, type KeySet, type SigningKey } from './keys';

export interface SignedToken {
  token: string;
  /** Seconds since epoch, same as the token's `exp`. */
  expiresAt: number;
}

export type AccessTokenPayload = UserClaims &
  JWTPayload & { iss: string; aud: string; iat: number; exp: number; email_verified: true };

/** Signs an access token for `claims`; adds iss, aud, iat, exp and email_verified. */
export async function signAccessToken(env: Env, claims: UserClaims, now = Date.now()): Promise<SignedToken> {
  const { current } = await loadKeySet(env);
  const iat = Math.floor(now / 1000);
  const expiresAt = iat + Math.floor(config.ACCESS_TOKEN_TTL / 1000);

  const { roles, ...rest } = claims;
  const payload: JWTPayload = { ...rest, email_verified: true };
  if (roles && roles.length > 0) payload.roles = roles;

  const token = await new SignJWT(payload)
    .setProtectedHeader({ alg: SIGNING_ALG, typ: 'JWT', kid: current.kid })
    .setIssuer(env.ISSUER)
    .setAudience(config.AUDIENCE)
    .setIssuedAt(iat)
    .setExpirationTime(expiresAt)
    .sign(current.privateKey);
  return { token, expiresAt };
}

/** Public JWKS (current + previous keys). */
export async function getJwks(env: Env): Promise<JSONWebKeySet> {
  const { publicJwks } = await loadKeySet(env);
  return { keys: publicJwks.map((k) => ({ ...k })) };
}

/** Verifies a token against our own JWKS; throws on any failure. */
export async function verifyAccessToken(env: Env, token: string): Promise<AccessTokenPayload> {
  const jwks = createLocalJWKSet(await getJwks(env));
  const { payload } = await jwtVerify(token, jwks, {
    issuer: env.ISSUER,
    audience: config.AUDIENCE,
    algorithms: [SIGNING_ALG],
  });
  return payload as AccessTokenPayload;
}
