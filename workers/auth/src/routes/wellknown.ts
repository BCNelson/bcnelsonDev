/**
 * Discovery documents (design §9). The OpenID configuration advertises only what exists.
 */

import { Hono } from 'hono';
import type { AppEnv } from '../http';
import { SIGNING_ALG, getJwks } from '../tokens';
import { oidcDiscovery } from '../oidc/discovery';

export const wellknownRoutes = new Hono<AppEnv>();

const PUBLIC_CACHE = 'public, max-age=300';

/** Claims an access token may carry. */
export const CLAIMS_SUPPORTED = [
  'iss', 'aud', 'sub', 'sid', 'iat', 'exp', 'auth_time', 'amr',
  'preferred_username', 'name', 'picture', 'email', 'email_verified', 'roles',
];

wellknownRoutes.get('/.well-known/jwks.json', async (c) => {
  const jwks = await getJwks(c.env);
  return c.json(jwks, 200, { 'Cache-Control': PUBLIC_CACHE, 'Access-Control-Allow-Origin': '*' });
});

wellknownRoutes.get('/.well-known/openid-configuration', (c) => {
  const issuer = c.env.ISSUER;
  return c.json(
    {
      issuer,
      jwks_uri: `${issuer}/.well-known/jwks.json`,
      id_token_signing_alg_values_supported: [SIGNING_ALG],
      subject_types_supported: ['public'],
      claims_supported: CLAIMS_SUPPORTED,
      // OpenID provider endpoints (routes/oidc.ts); overrides claims_supported with the client view.
      ...oidcDiscovery(issuer),
    },
    200,
    { 'Cache-Control': PUBLIC_CACHE, 'Access-Control-Allow-Origin': '*' },
  );
});
