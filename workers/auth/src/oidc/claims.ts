/**
 * Which user claims a client sees, by scope (OIDC Core §5.4, plus `roles`):
 *   openid  → sub
 *   profile → preferred_username, name, picture
 *   email   → email, email_verified (always true: only verified addresses exist)
 *   roles   → roles ([] when none)
 */

import type { UserClaims } from '../types';

export interface ScopedClaims {
  sub: string;
  preferred_username?: string;
  name?: string;
  picture?: string;
  email?: string;
  email_verified?: true;
  roles?: string[];
}

export function scopedClaims(claims: UserClaims, scopes: readonly string[]): ScopedClaims {
  const out: ScopedClaims = { sub: claims.sub };
  if (scopes.includes('profile')) {
    out.preferred_username = claims.preferred_username;
    if (claims.name) out.name = claims.name;
    if (claims.picture) out.picture = claims.picture;
  }
  if (scopes.includes('email')) {
    out.email = claims.email;
    out.email_verified = true;
  }
  if (scopes.includes('roles')) out.roles = claims.roles ?? [];
  return out;
}

/** Claims the provider can return (discovery `claims_supported`). */
export const OIDC_CLAIMS_SUPPORTED = [
  'iss', 'sub', 'aud', 'azp', 'exp', 'iat', 'auth_time', 'nonce', 'at_hash', 'sid', 'amr',
  'preferred_username', 'name', 'picture', 'email', 'email_verified', 'roles',
];
