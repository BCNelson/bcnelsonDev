/**
 * OpenID provider state on a User DO (design §9).
 *
 * - oauth_grants: remembered consent (client → scopes). Consent covers a
 *   request when every requested scope is already granted.
 * - oauth_requests: a pending consent screen. The page carries a single-use
 *   token; its hash maps to the validated authorize request and the browser
 *   session that saw it (OIDC_CONSENT_TTL).
 * - oauth_codes: authorization codes `ac1.<userId>.<secret>` (hash stored),
 *   single use, OIDC_CODE_TTL, bound to client, redirect_uri, PKCE challenge,
 *   nonce, scopes and the browser session. Used codes are kept for
 *   OIDC_CODE_RETENTION; presenting one again revokes what it issued.
 * - oauth_tokens: one row per code exchange, bound to the browser session.
 *   With offline_access it holds a rotating refresh secret
 *   (`crt1.<userId>.<tokenId>.<secret>`); presenting the previous secret is
 *   treated as theft and revokes the row. Rows (and the access tokens that
 *   name them in `gid`) die with the browser session: revoked session,
 *   disabled account or revoked row → nothing works.
 */

import { config } from '../../config';
import { sha256Base64url, timingSafeEqual } from '../../crypto/hash';
import { randomToken } from '../../crypto/ids';
import { newTokenId } from '../../oidc/formats';
import type {
  AuthorizeRequest,
  CreateCodeInput,
  CreateCodeResult,
  IssuedGrant,
  OAuthGrantInfo,
  RedeemCodeInput,
  RedeemCodeResult,
  RefreshGrantInput,
  RefreshGrantResult,
} from '../../oidc/types';
import type { UserClaims } from '../../types';
import { buildClaims, parseStringArray } from '../sessions';
import { readDisabledAt } from './admin';
import { type UserContext, readPrimaryEmail, readProfile } from './context';

type SessionRow = { id: string; auth_time: number; amr: string; expires_at: number; revoked_at: number | null };

type CodeRow = {
  code_hash: string;
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  nonce: string | null;
  scopes: string;
  session_id: string;
  auth_time: number;
  expires_at: number;
  used_at: number | null;
  token_id: string | null;
};

type TokenRow = {
  id: string;
  client_id: string;
  session_id: string;
  scopes: string;
  secret_hash: string | null;
  prev_secret_hash: string | null;
  expires_at: number;
  revoked_at: number | null;
};

function sessionRow(sql: SqlStorage, sessionId: string): SessionRow | null {
  return sql.exec<SessionRow>(
    'SELECT id, auth_time, amr, expires_at, revoked_at FROM sessions WHERE id = ?', sessionId,
  ).toArray()[0] ?? null;
}

/**
 * Claims for `sessionId` when it can still back OIDC tokens: not revoked,
 * account enabled. `requireUnexpired` (codes) also needs the browser session
 * unexpired; client refresh tokens outlive an idle browser session's expiry
 * (but not its revocation).
 */
function sessionClaims(ctx: UserContext, sessionId: string, requireUnexpired: boolean): UserClaims | 'session' | 'disabled' {
  const row = sessionRow(ctx.sql, sessionId);
  if (!row || row.revoked_at !== null) return 'session';
  if (requireUnexpired && row.expires_at <= ctx.now) return 'session';
  if (readDisabledAt(ctx.sql) !== null) return 'disabled';
  const profile = readProfile(ctx.sql);
  const email = readPrimaryEmail(ctx.sql);
  if (!profile || !email) return 'session';
  return buildClaims(profile, email, row);
}

// --- consent -----------------------------------------------------------------

/** Scopes this user already granted `clientId`, or null. */
export function getGrant(ctx: UserContext, clientId: string): string[] | null {
  const row = ctx.sql.exec<{ scopes: string }>(
    'SELECT scopes FROM oauth_grants WHERE client_id = ?', clientId,
  ).toArray()[0];
  return row ? parseStringArray(row.scopes) : null;
}

/** Remember consent: the union of what was granted before and `scopes`. */
export function saveGrant(ctx: UserContext, clientId: string, scopes: string[]): string[] {
  return ctx.storage.transactionSync(() => {
    const previous = getGrant(ctx, clientId);
    const merged = config.OIDC_SCOPES.filter((s) => scopes.includes(s) || previous?.includes(s));
    ctx.sql.exec(
      `INSERT INTO oauth_grants (client_id, scopes, created_at, updated_at) VALUES (?, ?, ?, ?)
       ON CONFLICT (client_id) DO UPDATE SET scopes = excluded.scopes, updated_at = excluded.updated_at`,
      clientId, JSON.stringify(merged), ctx.now, ctx.now,
    );
    ctx.audit('oauth.consent', { clientId, scopes: merged });
    return merged;
  });
}

export function listGrants(ctx: UserContext): OAuthGrantInfo[] {
  return ctx.sql.exec<{ client_id: string; scopes: string; created_at: number; updated_at: number }>(
    'SELECT client_id, scopes, created_at, updated_at FROM oauth_grants ORDER BY created_at',
  ).toArray().map((r) => ({
    clientId: r.client_id, scopes: parseStringArray(r.scopes), createdAt: r.created_at, updatedAt: r.updated_at,
  }));
}

/** Forget consent for `clientId` and revoke its tokens. True when anything changed. */
export function revokeClient(ctx: UserContext, clientId: string): boolean {
  return ctx.storage.transactionSync(() => {
    const grants = ctx.sql.exec('DELETE FROM oauth_grants WHERE client_id = ?', clientId).rowsWritten;
    const tokens = ctx.sql.exec(
      'UPDATE oauth_tokens SET revoked_at = ? WHERE client_id = ? AND revoked_at IS NULL', ctx.now, clientId,
    ).rowsWritten;
    if (grants + tokens > 0) ctx.audit('oauth.client_revoked', { clientId, tokens });
    return grants + tokens > 0;
  });
}

/** Store a pending consent screen; returns its single-use token. */
export async function startConsent(ctx: UserContext, sessionId: string, request: AuthorizeRequest): Promise<{ token: string }> {
  const token = randomToken();
  const hash = await sha256Base64url(token);
  ctx.sql.exec(
    'INSERT INTO oauth_requests (token_hash, session_id, request, expires_at) VALUES (?, ?, ?, ?)',
    hash, sessionId, JSON.stringify(request), ctx.now + config.OIDC_CONSENT_TTL,
  );
  return { token };
}

/** Take (delete) a pending consent for `sessionId`; null when unknown, expired or another session's. */
export async function takeConsent(ctx: UserContext, token: string, sessionId: string): Promise<AuthorizeRequest | null> {
  if (!token || token.length > 128) return null;
  const hash = await sha256Base64url(token);
  const now = Date.now();
  return ctx.storage.transactionSync(() => {
    const row = ctx.sql.exec<{ session_id: string; request: string; expires_at: number }>(
      'SELECT session_id, request, expires_at FROM oauth_requests WHERE token_hash = ?', hash,
    ).toArray()[0];
    if (!row) return null;
    ctx.sql.exec('DELETE FROM oauth_requests WHERE token_hash = ?', hash);
    if (row.session_id !== sessionId || row.expires_at <= now) return null;
    try {
      return JSON.parse(row.request) as AuthorizeRequest;
    } catch {
      return null;
    }
  });
}

// --- codes ---------------------------------------------------------------------

/** Issue an authorization code for a live session. */
export async function createCode(ctx: UserContext, input: CreateCodeInput): Promise<CreateCodeResult> {
  const secret = randomToken();
  const hash = await sha256Base64url(secret);
  const now = Date.now();
  const live = sessionClaims({ ...ctx, now }, input.sessionId, true);
  if (live === 'session' || live === 'disabled') return { ok: false, reason: live };
  const expiresAt = now + config.OIDC_CODE_TTL;
  ctx.sql.exec(
    `INSERT INTO oauth_codes (code_hash, client_id, redirect_uri, code_challenge, nonce, scopes,
       session_id, auth_time, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    hash, input.clientId, input.redirectUri, input.codeChallenge, input.nonce ?? null,
    JSON.stringify(input.scopes), input.sessionId, live.auth_time * 1000, expiresAt,
  );
  return { ok: true, secret, expiresAt };
}

/**
 * Exchange a code (token endpoint). Any presentation uses the code up; a
 * second presentation revokes the token row the first one created.
 */
export async function redeemCode(ctx: UserContext, input: RedeemCodeInput): Promise<RedeemCodeResult> {
  const hash = await sha256Base64url(input.secret);
  // S256: BASE64URL(SHA256(ASCII(code_verifier))).
  const challenge = await sha256Base64url(input.codeVerifier);
  const refreshSecret = randomToken();
  const refreshHash = await sha256Base64url(refreshSecret);
  // No awaits below: the read-decide-write runs atomically within the DO.
  const now = Date.now();
  const c = { ...ctx, now };
  return ctx.storage.transactionSync((): RedeemCodeResult => {
    const row = c.sql.exec<CodeRow>('SELECT * FROM oauth_codes WHERE code_hash = ?', hash).toArray()[0];
    if (!row) return { ok: false, reason: 'invalid' };
    if (row.used_at !== null) {
      if (row.token_id) {
        c.sql.exec('UPDATE oauth_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL', now, row.token_id);
      }
      c.audit('oauth.code_reuse', { clientId: row.client_id, tokenId: row.token_id });
      return { ok: false, reason: 'reuse' };
    }
    c.sql.exec('UPDATE oauth_codes SET used_at = ? WHERE code_hash = ?', now, hash);
    if (row.expires_at <= now) return { ok: false, reason: 'expired' };
    if (row.client_id !== input.clientId || row.redirect_uri !== input.redirectUri) return { ok: false, reason: 'mismatch' };
    if (!timingSafeEqual(challenge, row.code_challenge)) return { ok: false, reason: 'pkce' };
    const claims = sessionClaims(c, row.session_id, true);
    if (claims === 'session' || claims === 'disabled') return { ok: false, reason: claims };

    const scopes = parseStringArray(row.scopes);
    const offline = scopes.includes('offline_access');
    const tokenId = newTokenId();
    const expiresAt = now + (offline ? config.OIDC_REFRESH_TOKEN_TTL : config.OIDC_ACCESS_TOKEN_TTL);
    c.sql.exec(
      `INSERT INTO oauth_tokens (id, client_id, session_id, scopes, secret_hash, created_at, last_used_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      tokenId, row.client_id, row.session_id, row.scopes, offline ? refreshHash : null, now, now, expiresAt,
    );
    c.sql.exec('UPDATE oauth_codes SET token_id = ? WHERE code_hash = ?', tokenId, hash);
    c.audit('oauth.token_issued', { clientId: row.client_id, tokenId, scopes, sessionId: row.session_id });
    const grant: IssuedGrant = { tokenId, claims, scopes };
    if (offline) grant.refreshSecret = refreshSecret;
    if (row.nonce !== null) grant.nonce = row.nonce;
    return { ok: true, ...grant };
  });
}

// --- client refresh tokens --------------------------------------------------------

/** Rotate a client refresh token. No grace window: the previous secret revokes the row. */
export async function refreshGrant(ctx: UserContext, input: RefreshGrantInput): Promise<RefreshGrantResult> {
  const presented = await sha256Base64url(input.secret);
  const nextSecret = randomToken();
  const nextHash = await sha256Base64url(nextSecret);
  const now = Date.now();
  const c = { ...ctx, now };
  return ctx.storage.transactionSync((): RefreshGrantResult => {
    const row = c.sql.exec<TokenRow>('SELECT * FROM oauth_tokens WHERE id = ?', input.tokenId).toArray()[0];
    if (!row || row.secret_hash === null) return { ok: false, reason: 'invalid' };
    const current = timingSafeEqual(presented, row.secret_hash);
    const previous = row.prev_secret_hash !== null && timingSafeEqual(presented, row.prev_secret_hash);
    if (!current && !previous) return { ok: false, reason: 'invalid' };
    if (row.client_id !== input.clientId) return { ok: false, reason: 'mismatch' };
    if (row.revoked_at !== null) return { ok: false, reason: 'revoked' };
    if (previous) {
      c.sql.exec('UPDATE oauth_tokens SET revoked_at = ? WHERE id = ?', now, row.id);
      c.audit('oauth.refresh_reuse', { clientId: row.client_id, tokenId: row.id });
      return { ok: false, reason: 'reuse' };
    }
    if (row.expires_at <= now) return { ok: false, reason: 'expired' };
    const granted = parseStringArray(row.scopes);
    if (!granted.includes('offline_access')) return { ok: false, reason: 'invalid' };
    const scopes = input.scopes ?? granted;
    if (!scopes.includes('openid') || !scopes.every((s) => granted.includes(s))) return { ok: false, reason: 'scope' };
    const claims = sessionClaims(c, row.session_id, false);
    if (claims === 'session' || claims === 'disabled') {
      c.sql.exec('UPDATE oauth_tokens SET revoked_at = ? WHERE id = ?', now, row.id);
      return { ok: false, reason: claims };
    }
    c.sql.exec(
      `UPDATE oauth_tokens SET secret_hash = ?, prev_secret_hash = ?, last_used_at = ?, expires_at = ?
       WHERE id = ?`,
      nextHash, row.secret_hash, now, now + config.OIDC_REFRESH_TOKEN_TTL, row.id,
    );
    // The refresh token keeps its full grant; a narrower `scope` only narrows this access token.
    return { ok: true, tokenId: row.id, refreshSecret: nextSecret, claims, scopes };
  });
}

/**
 * Live claims behind a client access token (userinfo): the token row exists
 * for this client and session and isn't revoked, the session isn't revoked,
 * the account is enabled. Null otherwise.
 */
export function tokenClaims(ctx: UserContext, tokenId: string, sessionId: string, clientId: string): UserClaims | null {
  const row = ctx.sql.exec<TokenRow>('SELECT * FROM oauth_tokens WHERE id = ?', tokenId).toArray()[0];
  if (!row || row.revoked_at !== null || row.client_id !== clientId) return null;
  // The row's session is authoritative: a re-login moves rows to the new
  // session (rebindSessionTokens), so an access token minted before it names
  // the old sid. The row id is random and signed into the token, so this
  // doesn't loosen anything. `sessionId` is kept for the signature only.
  void sessionId;
  const claims = sessionClaims(ctx, row.session_id, false);
  return typeof claims === 'string' ? null : claims;
}

/**
 * A re-login in the same browser replaces session `from` with `to`
 * (routes/auth-common completeLogin): move the live client tokens bound to
 * `from` over, so re-confirming your identity doesn't silently sign third-
 * party apps out. Run before `from` is revoked. Returns the rows moved.
 */
export function rebindSessionTokens(ctx: UserContext, from: string, to: string): number {
  const moved = ctx.sql.exec(
    'UPDATE oauth_tokens SET session_id = ? WHERE session_id = ? AND revoked_at IS NULL AND expires_at > ?',
    to, from, ctx.now,
  ).rowsWritten;
  if (moved > 0) ctx.audit('oauth.tokens_rebound', { from, to, count: moved });
  return moved;
}

// --- maintenance -------------------------------------------------------------------

/** Delete expired consent screens, old codes and long-dead token rows (user/maintenance.ts prune). */
export function pruneOidc(ctx: Pick<UserContext, 'sql' | 'now'>): number {
  const { sql, now } = ctx;
  const tokenCutoff = now - config.SESSION_RETENTION;
  return (
    sql.exec('DELETE FROM oauth_requests WHERE expires_at <= ?', now).rowsWritten +
    sql.exec('DELETE FROM oauth_codes WHERE expires_at <= ?', now - config.OIDC_CODE_RETENTION).rowsWritten +
    sql.exec(
      'DELETE FROM oauth_tokens WHERE (revoked_at IS NOT NULL AND revoked_at <= ?) OR expires_at <= ?',
      tokenCutoff, tokenCutoff,
    ).rowsWritten
  );
}

/**
 * SQL condition (on `sessions`) for sessions that live client refresh tokens
 * still depend on, so maintenance keeps expired-but-unrevoked sessions they need.
 */
export const SESSIONS_IN_USE_BY_OIDC =
  'id IN (SELECT session_id FROM oauth_tokens WHERE revoked_at IS NULL AND expires_at > ?)';
