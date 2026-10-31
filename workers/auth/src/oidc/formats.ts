/**
 * Opaque OIDC credential formats. Each carries the userId so the Worker can go
 * straight to the right User DO; only SHA-256 of the secret is stored.
 *
 *   authorization code      ac1.<userId>.<secret>
 *   client refresh token    crt1.<userId>.<tokenId>.<secret>
 */

import { ulid } from '../crypto/ids';
import { SECRET_PATTERN, USER_ID_PATTERN } from '../session/refresh-token';

/** oauth_tokens ids: `otk_` + ULID. */
export const TOKEN_ID_PATTERN = /^otk_[0-9A-HJKMNP-TV-Z]{26}$/;

export function newTokenId(): string {
  return `otk_${ulid()}`;
}

export interface CodeParts {
  userId: string;
  secret: string;
}

export function formatCode({ userId, secret }: CodeParts): string {
  return `ac1.${userId}.${secret}`;
}

export function parseCode(value: string | null | undefined): CodeParts | null {
  if (!value || value.length > 128) return null;
  const parts = value.split('.');
  if (parts.length !== 3) return null;
  const [prefix, userId, secret] = parts as [string, string, string];
  if (prefix !== 'ac1' || !USER_ID_PATTERN.test(userId) || !SECRET_PATTERN.test(secret)) return null;
  return { userId, secret };
}

export interface ClientRefreshParts {
  userId: string;
  tokenId: string;
  secret: string;
}

export function formatClientRefreshToken({ userId, tokenId, secret }: ClientRefreshParts): string {
  return `crt1.${userId}.${tokenId}.${secret}`;
}

export function parseClientRefreshToken(value: string | null | undefined): ClientRefreshParts | null {
  if (!value || value.length > 160) return null;
  const parts = value.split('.');
  if (parts.length !== 4) return null;
  const [prefix, userId, tokenId, secret] = parts as [string, string, string, string];
  if (prefix !== 'crt1' || !USER_ID_PATTERN.test(userId) || !TOKEN_ID_PATTERN.test(tokenId) || !SECRET_PATTERN.test(secret)) {
    return null;
  }
  return { userId, tokenId, secret };
}

/** RFC 7636 code_verifier / code_challenge charset and length. */
export const PKCE_PATTERN = /^[A-Za-z0-9._~-]{43,128}$/;
