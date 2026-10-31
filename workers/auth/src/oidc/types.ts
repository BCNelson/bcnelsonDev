/**
 * Types shared between the OIDC routes and the User DO's oidc module.
 */

import type { UserClaims } from '../types';

/** A validated /authorize request (oidc/request.ts). */
export interface AuthorizeRequest {
  clientId: string;
  redirectUri: string;
  /** Granted-to-be scopes: requested ∩ supported ∩ client-allowed; always includes openid. */
  scopes: string[];
  state?: string;
  nonce?: string;
  /** S256 code challenge. */
  codeChallenge: string;
  prompt: { none: boolean; login: boolean; consent: boolean };
  /** Seconds; the login must be at most this old. */
  maxAge?: number;
  /** Internal: epoch seconds after which a forced login must have happened (set when we sent the user to log in). */
  authAfter?: number;
}

export interface CreateCodeInput {
  sessionId: string;
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  nonce?: string;
  scopes: string[];
}

export type CreateCodeResult =
  | { ok: true; secret: string; expiresAt: number }
  | { ok: false; reason: 'session' | 'disabled' };

export interface RedeemCodeInput {
  secret: string;
  clientId: string;
  redirectUri: string;
  codeVerifier: string;
}

/** What a successful code exchange or refresh hands back for signing. */
export interface IssuedGrant {
  tokenId: string;
  /** New client refresh secret (offline_access only). */
  refreshSecret?: string;
  /** Live claims for the bound browser session. */
  claims: UserClaims;
  scopes: string[];
  nonce?: string;
}

export type RedeemCodeResult =
  | ({ ok: true } & IssuedGrant)
  | { ok: false; reason: 'invalid' | 'expired' | 'reuse' | 'mismatch' | 'pkce' | 'session' | 'disabled' };

export interface RefreshGrantInput {
  tokenId: string;
  secret: string;
  clientId: string;
  /** Optional narrower scope set (RFC 6749 §6). */
  scopes?: string[];
}

export type RefreshGrantResult =
  | ({ ok: true } & IssuedGrant)
  | { ok: false; reason: 'invalid' | 'expired' | 'revoked' | 'reuse' | 'mismatch' | 'scope' | 'session' | 'disabled' };

/** A remembered consent, for a future profile-page "connected apps" list. */
export interface OAuthGrantInfo {
  clientId: string;
  scopes: string[];
  createdAt: number;
  updatedAt: number;
}
