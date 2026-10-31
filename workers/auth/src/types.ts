/**
 * Types shared across modules. The User DO produces these; tokens/ and
 * session/ consume them.
 */

/** Per-user claims. tokens/ adds iss, aud, iat, exp and email_verified when signing. */
export interface UserClaims {
  sub: string;
  sid: string;
  auth_time: number; // seconds since epoch
  amr: string[]; // 'pwd' | 'hwk' | `oauth:${provider}`
  preferred_username: string;
  name?: string;
  picture?: string;
  email: string; // primary, always verified
  roles?: string[]; // omitted when empty
}

/** Request details recorded on a session. */
export interface SessionContext {
  amr: string[];
  userAgent?: string;
  ip?: string;
}

export type RefreshResult =
  /**
   * `secret` is the rotated refresh secret. It's absent when the caller presented
   * the previous secret inside the grace window: a concurrent refresh already
   * rotated, so the caller must leave the browser's (newer) refresh cookie alone.
   */
  | { ok: true; secret?: string; claims: UserClaims }
  | { ok: false; reason: 'invalid' | 'expired' | 'revoked' | 'reuse' };

/** What User.createSession returns: the new session's id, refresh secret and claims. */
export interface CreatedSession {
  sessionId: string;
  secret: string;
  claims: UserClaims;
}

/** Context for User.loginWithPassword; `turnstileOk` is true when the request carried a valid token. */
export type PasswordLoginContext = SessionContext & { turnstileOk: boolean };

export type PasswordLoginResult =
  | { ok: true; session: CreatedSession }
  /**
   * `invalid`: wrong password or no password credential. `turnstile_required`:
   * retry with a Turnstile token. `locked`: backoff in force for `retryAfterMs`.
   * `disabled`: correct password, but an admin disabled the account.
   */
  | { ok: false; reason: 'invalid' | 'locked' | 'turnstile_required' | 'disabled'; retryAfterMs?: number };
