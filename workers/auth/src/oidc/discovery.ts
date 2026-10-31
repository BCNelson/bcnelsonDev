/**
 * The OpenID provider part of /.well-known/openid-configuration (OIDC
 * Discovery 1.0, RFC 8414), merged in by routes/wellknown.ts.
 */

import { config } from '../config';
import { OIDC_CLAIMS_SUPPORTED } from './claims';

export function oidcDiscovery(issuer: string): Record<string, unknown> {
  return {
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    userinfo_endpoint: `${issuer}/userinfo`,
    end_session_endpoint: `${issuer}/logout`,
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    scopes_supported: [...config.OIDC_SCOPES],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
    claims_supported: OIDC_CLAIMS_SUPPORTED,
    prompt_values_supported: ['none', 'login', 'consent'],
    authorization_response_iss_parameter_supported: true,
    request_parameter_supported: false,
    request_uri_parameter_supported: false,
    claims_parameter_supported: false,
  };
}
