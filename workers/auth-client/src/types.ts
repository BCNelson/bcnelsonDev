/**
 * Claim and user shapes. Duplicated from workers/auth on purpose: this package
 * must stand alone so any Worker can depend on it.
 */

/** Claims carried by a bcnelson.dev access JWT (design doc §3.3). */
export interface AccessClaims {
  iss: string;
  aud: string | string[];
  sub: string;
  sid: string;
  iat: number;
  exp: number;
  auth_time: number; // seconds since epoch
  amr: string[]; // 'pwd' | 'hwk' | `oauth:${provider}`
  preferred_username: string;
  name?: string;
  picture?: string;
  email: string; // primary, always verified
  email_verified?: boolean;
  roles?: string[]; // omitted when empty
  [claim: string]: unknown;
}

/** The verified user, as apps see it. */
export interface AuthUser {
  id: string;
  sessionId: string;
  username: string;
  name?: string;
  picture?: string;
  email: string;
  roles: string[];
  amr: string[];
  /** Last interactive login, seconds since epoch. */
  authTime: number;
  hasRole(role: string): boolean;
  claims: AccessClaims;
}

/** Minimal service-binding shape, so callers needn't match workers-types exactly. */
export interface FetcherLike {
  fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
}

export type FetchLike = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

export interface AuthClientOptions {
  /** Default 'https://auth.bcnelson.dev'. */
  issuer?: string;
  /** Default 'bcnelson.dev'. */
  audience?: string;
  /** Access-token cookie. Default 'bcn_at'. */
  cookieName?: string;
  /** Service binding to the auth Worker; JWKS is fetched through it when present. */
  service?: FetcherLike;
  /** How long a fetched JWKS is trusted. Default 10 minutes. */
  jwksTtlMs?: number;
  /** Minimum gap between refetches triggered by an unknown kid. Default 30 s. */
  jwksCooldownMs?: number;
  /** Allowed clock skew for exp/iat/nbf, in seconds. Default 30. */
  clockToleranceSec?: number;
  /** fetch override (tests). Ignored when `service` is set. */
  fetch?: FetchLike;
}
