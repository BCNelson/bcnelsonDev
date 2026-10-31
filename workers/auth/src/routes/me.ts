/**
 * Profile JSON API (phase 4): /api/me/*. Every route requires a session
 * (http/auth requireSession, checked against the User DO); POSTs also pass
 * the global Origin check and the IP limit. Routes marked (reauth) need a
 * login within REAUTH_WINDOW (design §6.5) and otherwise answer
 * 403 { ok: false, error: 'reauth_required', message, reauthUrl }.
 *
 * GET  /api/me                          → { ok, profile, emails, pendingEmails, sessions[+current], credentials, hasPassword, currentSessionId }
 * POST /api/me/profile        { name?, picture? }          → { ok, profile }   400 invalid_name | invalid_picture
 * POST /api/me/username       { username }        (reauth) → { ok, username }  400 invalid_username · 409 username_taken · 429 username_cooldown
 * POST /api/me/emails         { email }           (reauth) → { ok, email, expiresAt }
 *        400 invalid_email · 409 already_added | too_many_pending | too_many_emails · 429 rate_limited
 * POST /api/me/emails/verify  { email, code }               → { ok, email }
 *        400 invalid_code | code_expired | too_many_attempts · 409 too_many_emails | email_unavailable
 * POST /api/me/emails/primary { email }           (reauth) → { ok, changed }   404 email_not_found
 * POST /api/me/emails/remove  { email, newPrimary? } (reauth) → { ok }
 *        404 email_not_found · 409 last_email · 400 primary_required | invalid_new_primary
 * POST /api/me/password       { currentPassword?, newPassword } (reauth) → { ok, revokedSessions }
 *        400 weak_password | current_password_required | invalid_password
 * POST /api/me/sessions/:id/revoke                          → { ok, current }  (current → cookies cleared)
 * POST /api/me/sessions/revoke-others                       → { ok, revoked }
 * GET  /api/me/credentials                                  → { ok, credentials: [{ id, type, label, createdAt, lastUsedAt }] }
 * POST /api/me/apps/:clientId/revoke              (reauth) → { ok }  forget consent, revoke the app's tokens · 404 app_not_found
 *
 * Changes that affect token claims (username, name, picture, primary email)
 * re-sign bcn_at for the current session so the cookie reflects them at once.
 */

import { Hono } from 'hono';
import type { ClientErrorStatusCode } from 'hono/utils/http-status';
import { config } from '../config';
import { hashPassword, validatePasswordPolicy } from '../crypto/password';
import type { AccountInfo } from '../do/user/profile';
import type { AppContext } from '../http';
import { requireReauth, requireSession, type AuthContext, type AuthEnv } from '../http/auth';
import { readBody } from '../http/body';
import { CLIENT_ID_PATTERN } from '../oidc/clients';
import { SESSION_ID_PATTERN, clearSessionCookies, issueSession } from '../session';
import { BAD_REQUEST, apiError, limitIp, userStub } from './auth-common';

export const meRoutes = new Hono<AuthEnv>();

/** AuthContext → AppContext for helpers typed on the base env (same Bindings). */
const base = (c: AuthContext) => c as unknown as AppContext;

const session = requireSession({ verifyActive: true });
const reauth = requireReauth();

// '/api/me/*' also matches '/api/me'.
meRoutes.use('/api/me/*', async (c, next) => {
  await next();
  c.header('Cache-Control', 'no-store');
});
meRoutes.use('/api/me/*', session);
meRoutes.use('/api/me/*', async (c, next) => {
  if (c.req.method === 'POST') {
    const limited = await limitIp(base(c));
    if (limited) return limited;
  }
  await next();
});

const fail = (c: AuthContext, status: ClientErrorStatusCode, error: string, message: string, retryAfterMs?: number) =>
  apiError(base(c), status, error, message, retryAfterMs);

const USERNAME_MESSAGES: Record<string, string> = {
  empty: 'Choose a username.',
  non_ascii: 'Usernames can only use letters, numbers, - and _.',
  invalid_format: 'Usernames are 3–30 characters: letters, numbers, - and _, starting with a letter or number.',
  reserved: "That username isn't available.",
};

const PASSWORD_MESSAGES: Record<string, string> = {
  too_short: `Use at least ${config.PASSWORD_MIN_LENGTH} characters.`,
  too_long: `Use at most ${config.PASSWORD_MAX_LENGTH} characters.`,
  invalid_unicode: 'That password contains characters we can’t store.',
};

function user(c: AuthContext) {
  return userStub(c.env, c.get('user').sub);
}

/** Re-sign bcn_at for the current session from fresh claims (refresh cookie untouched). */
async function reissue(c: AuthContext): Promise<void> {
  const { sub, sid } = c.get('user');
  const claims = await userStub(c.env, sub).getClaims(sid);
  if (claims) await issueSession(base(c), sub, { sessionId: sid, claims });
}

function withCurrent(account: AccountInfo, sid: string) {
  return {
    ...account,
    sessions: account.sessions.map((s) => ({ ...s, current: s.id === sid })),
    currentSessionId: sid,
  };
}

// --- reads -------------------------------------------------------------------

meRoutes.get('/api/me', async (c) => {
  const account = await user(c).getAccount();
  return c.json({ ok: true, ...withCurrent(account, c.get('user').sid) });
});

meRoutes.get('/api/me/credentials', async (c) => {
  return c.json({ ok: true, credentials: await user(c).listCredentials() });
});

// --- profile -----------------------------------------------------------------

meRoutes.post('/api/me/profile', async (c) => {
  const body = await readProfileBody(c);
  if (!body) return fail(c, 400, 'bad_request', BAD_REQUEST);
  const result = await user(c).updateProfile(body);
  if (!result.ok) {
    return result.reason === 'invalid_name'
      ? fail(c, 400, 'invalid_name', `Use at most ${config.PROFILE_NAME_MAX_LENGTH} characters, without control characters.`)
      : fail(c, 400, 'invalid_picture', 'Use an https:// image address.');
  }
  if (result.changed) await reissue(c);
  return c.json({ ok: true, profile: result.profile });
});

meRoutes.post('/api/me/username', reauth, async (c) => {
  const body = await readBody(base(c));
  const username = body?.fields.username;
  if (!username) return fail(c, 400, 'bad_request', BAD_REQUEST);
  const result = await user(c).changeUsername(username);
  if (result.ok) {
    if (result.changed) await reissue(c);
    return c.json({ ok: true, username: result.username });
  }
  switch (result.reason) {
    case 'username_taken':
      return fail(c, 409, 'username_taken', 'That username is taken.');
    case 'cooldown': {
      const days = Math.max(1, Math.ceil(result.retryAfterMs / 86_400_000));
      return fail(c, 429, 'username_cooldown',
        `You changed your username recently. Try again in ${days} day${days === 1 ? '' : 's'}.`, result.retryAfterMs);
    }
    default:
      return fail(c, 400, 'invalid_username', USERNAME_MESSAGES[result.detail ?? 'invalid_format'] ?? USERNAME_MESSAGES.invalid_format!);
  }
});

// --- emails ------------------------------------------------------------------

meRoutes.post('/api/me/emails', reauth, async (c) => {
  const body = await readBody(base(c));
  const email = body?.fields.email;
  if (!email) return fail(c, 400, 'bad_request', BAD_REQUEST);
  const result = await user(c).startAddEmail(email);
  if (result.ok) return c.json({ ok: true, email: result.email, expiresAt: result.expiresAt });
  switch (result.reason) {
    case 'invalid_email':
      return fail(c, 400, 'invalid_email', 'Enter a valid email address.');
    case 'already_added':
      return fail(c, 409, 'already_added', 'That address is already on your account.');
    case 'too_many_pending':
      return fail(c, 409, 'too_many_pending',
        `You have ${config.MAX_PENDING_EMAILS} addresses waiting for verification. Verify one or wait for its code to expire.`);
    case 'too_many_emails':
      return fail(c, 409, 'too_many_emails', `Accounts can have at most ${config.MAX_EMAILS_PER_ACCOUNT} email addresses.`);
    default:
      return fail(c, 429, 'rate_limited', 'Too many codes sent. Please try again later.', result.retryAfterMs);
  }
});

meRoutes.post('/api/me/emails/verify', async (c) => {
  const body = await readBody(base(c));
  const email = body?.fields.email;
  const code = (body?.fields.code ?? '').replace(/\s+/g, '');
  if (!email || !code) return fail(c, 400, 'bad_request', BAD_REQUEST);
  const result = await user(c).verifyAddEmail(email, code);
  if (result.ok) return c.json({ ok: true, email: result.email });
  switch (result.reason) {
    case 'expired':
      return fail(c, 400, 'code_expired', 'That code has expired. Send a new one.');
    case 'too_many_attempts':
      return fail(c, 400, 'too_many_attempts', 'Too many wrong codes. Send a new one.');
    case 'too_many_emails':
      return fail(c, 409, 'too_many_emails', `Accounts can have at most ${config.MAX_EMAILS_PER_ACCOUNT} email addresses.`);
    case 'unavailable':
      return fail(c, 409, 'email_unavailable', "That address can't be added to your account.");
    default:
      return fail(c, 400, 'invalid_code', "That code isn't right. Check the email and try again.");
  }
});

meRoutes.post('/api/me/emails/primary', reauth, async (c) => {
  const body = await readBody(base(c));
  const email = body?.fields.email;
  if (!email) return fail(c, 400, 'bad_request', BAD_REQUEST);
  const result = await user(c).setPrimaryEmail(email);
  if (!result.ok) return fail(c, 404, 'email_not_found', "That address isn't on your account.");
  if (result.changed) await reissue(c);
  return c.json({ ok: true, changed: result.changed });
});

meRoutes.post('/api/me/emails/remove', reauth, async (c) => {
  const body = await readBody(base(c));
  const email = body?.fields.email;
  if (!email) return fail(c, 400, 'bad_request', BAD_REQUEST);
  const result = await user(c).removeEmail(email, body.fields.newPrimary || undefined);
  if (result.ok) {
    if (result.primaryChanged) await reissue(c);
    return c.json({ ok: true });
  }
  switch (result.reason) {
    case 'not_found':
      return fail(c, 404, 'email_not_found', "That address isn't on your account.");
    case 'last_email':
      return fail(c, 409, 'last_email', "You can't remove your only email address.");
    case 'primary_required':
      return fail(c, 400, 'primary_required', 'Choose a new primary address first.');
    default:
      return fail(c, 400, 'invalid_new_primary', 'Choose another of your addresses as the new primary.');
  }
});

// --- password ----------------------------------------------------------------

meRoutes.post('/api/me/password', reauth, async (c) => {
  const body = await readBody(base(c));
  const newPassword = body?.fields.newPassword;
  if (!newPassword) return fail(c, 400, 'bad_request', BAD_REQUEST);
  const problem = validatePasswordPolicy(newPassword);
  if (problem) return fail(c, 400, 'weak_password', PASSWORD_MESSAGES[problem] ?? PASSWORD_MESSAGES.too_short!);
  const hash = await hashPassword(newPassword);
  const result = await user(c).changePassword({
    currentPassword: body.fields.currentPassword || undefined,
    hash,
    keepSessionId: c.get('user').sid,
  });
  if (result.ok) return c.json({ ok: true, revokedSessions: result.revokedSessions });
  return result.reason === 'current_password_required'
    ? fail(c, 400, 'current_password_required', 'Enter your current password.')
    : fail(c, 400, 'invalid_password', "Your current password isn't right.");
});

// --- sessions ------------------------------------------------------------------

meRoutes.post('/api/me/sessions/revoke-others', async (c) => {
  const revoked = await user(c).revokeAllSessions(c.get('user').sid);
  return c.json({ ok: true, revoked });
});

meRoutes.post('/api/me/sessions/:id/revoke', async (c) => {
  const id = c.req.param('id');
  if (!SESSION_ID_PATTERN.test(id)) return fail(c, 404, 'session_not_found', "That session doesn't exist.");
  await user(c).revokeSession(id);
  const current = id === c.get('user').sid;
  if (current) clearSessionCookies(base(c));
  return c.json({ ok: true, current });
});

// --- connected apps (OIDC grants; the profile section is routes/oidc.ts PROFILE_SLOTS.apps) ---

meRoutes.post('/api/me/apps/:clientId/revoke', reauth, async (c) => {
  const clientId = c.req.param('clientId');
  if (!CLIENT_ID_PATTERN.test(clientId)) return fail(c, 404, 'app_not_found', "That app isn't connected.");
  const changed = await user(c).revokeOAuthClient(clientId);
  if (!changed) return fail(c, 404, 'app_not_found', "That app isn't connected.");
  return c.json({ ok: true });
});

// --- internals -----------------------------------------------------------------

/**
 * Body for /api/me/profile (JSON only; picture may exceed MAX_FIELD_LENGTH).
 * Absent → unchanged; null or '' → cleared. Null for anything malformed.
 */
async function readProfileBody(c: AuthContext): Promise<{ name?: string | null; picture?: string | null } | null> {
  const type = (c.req.header('Content-Type') ?? '').split(';')[0]!.trim().toLowerCase();
  if (type !== 'application/json') return null;
  let parsed: unknown;
  try {
    parsed = await c.req.json();
  } catch {
    return null;
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return null;
  const raw = parsed as Record<string, unknown>;
  const out: { name?: string | null; picture?: string | null } = {};
  for (const [key, limit] of [['name', config.MAX_FIELD_LENGTH], ['picture', config.PICTURE_URL_MAX_LENGTH * 2]] as const) {
    const value = raw[key];
    if (value === undefined) continue;
    if (value !== null && (typeof value !== 'string' || value.length > limit)) return null;
    out[key] = value;
  }
  return out;
}
