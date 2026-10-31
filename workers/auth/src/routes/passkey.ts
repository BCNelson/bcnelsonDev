/**
 * Passkeys (design §6.3). RP ID is env.RP_ID; expected origins are
 * ALLOWED_ORIGINS (https://auth.bcnelson.dev in production). Challenges live
 * in the UserIndex (single use, WEBAUTHN_CHALLENGE_TTL) and are found again
 * through the response's clientDataJSON, so clients never echo them.
 * Bodies are JSON; errors are `{ ok: false, error, message }`.
 *
 * POST /passkey/login/options     {}                         → { ok, options }
 * POST /passkey/login/verify      { credential, return_to? } → { ok, redirect }, cookies set
 *   400 bad_request | challenge_expired · 401 passkey_failed · 403 account_disabled · 429
 * POST /passkey/register/options  { signupId }  (signup, after email verification)
 *                                 {}            (signed in, recent login) → { ok, options }
 *   400 not_verified · 401 unauthorized · 403 reauth_required · 409 too_many
 * POST /passkey/register/verify   { credential, label? }  (signed in) → { ok, passkey }
 *   400 bad_request | challenge_expired | passkey_failed · 401 unauthorized · 403 reauth_required · 409 duplicate | too_many
 *   (A signup finishes through POST /signup/complete { signupId, credential, return_to? },
 *   handled by passkeySignupCredential.)
 * POST /passkey/credentials/:id/rename  { label }  → { ok }   400 invalid_label · 404 not_found
 * POST /passkey/credentials/:id/delete  {}         → { ok }   404 not_found · 409 last_method
 *   both: 401 unauthorized · 403 reauth_required
 *
 * The signed-in endpoints use the shared http/auth.ts shapes: 401
 * unauthorized = no valid bcn_at or a revoked session; 403 reauth_required =
 * auth_time older than REAUTH_WINDOW (the body carries `reauthUrl`).
 */

import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type RegistrationResponseJSON,
} from '@simplewebauthn/server';
import { decodeClientDataJSON, isoBase64URL } from '@simplewebauthn/server/helpers';
import { Hono } from 'hono';
import { config } from '../config';
import type { ChallengeData } from '../do/index/challenges';
import type { NewPasskey } from '../do/user/passkeys';
import type { Env } from '../env';
import { allowedOrigins, type AppContext, type AppEnv } from '../http';
import { hasRecentAuth, liveSession, reauthRequiredResponse, reauthUrl, unauthorizedResponse } from '../http/auth';
import { readBody } from '../http/body';
import {
  BAD_REQUEST,
  apiError,
  completeLogin,
  indexStub,
  limitIp,
  noStore,
  requestInfo,
  returnToFrom,
  userStub,
} from './auth-common';
import { PASSKEY_SECTION_SCRIPTS, passkeySection } from '../pages/passkeys';
import { PROFILE_SLOTS } from './profile';
import type { SignupCredential } from './signup';

export const PURPOSE_LOGIN = 'login';
export const PURPOSE_SIGNUP = 'register:signup';
export const PURPOSE_ADD = 'register:user';

const USER_ID = /^usr_[0-9A-HJKMNP-TV-Z]{26}$/;
const SIGNUP_ID = /^sig_[0-9A-HJKMNP-TV-Z]{26}$/i;
const CRED_ID = /^cred_[0-9A-HJKMNP-TV-Z]{26}$/;
const B64URL = /^[A-Za-z0-9_-]+$/;
/** Upper bound on any base64url field of a WebAuthn response. */
const MAX_B64_LENGTH = 16_384;

export const PASSKEY_MESSAGES = {
  passkey_failed: "That passkey couldn't be used. Try again, or use another way to sign in.",
  register_failed: "We couldn't save that passkey. Please try again.",
  challenge_expired: 'That request expired. Please try again.',
  reauth_required: 'For your security, please sign in again to change your passkeys.',
  not_verified: 'Verify your email first, or start again.',
  duplicate: 'That passkey is already registered.',
  too_many: `You can have at most ${config.MAX_PASSKEYS_PER_ACCOUNT} passkeys.`,
  invalid_label: `Use 1–${config.PASSKEY_LABEL_MAX_LENGTH} characters for the name.`,
  not_found: "That passkey doesn't exist anymore. Reload the page.",
  last_method: "You can't remove your only way to sign in. Add a password or another passkey first.",
  account_disabled: 'This account has been disabled. Contact the site owner if you think this is a mistake.',
} as const;

/** Origins a WebAuthn response may come from. */
export function passkeyOrigins(env: Env): string[] {
  return allowedOrigins(env);
}

export const passkeyRoutes = new Hono<AppEnv>();

passkeyRoutes.use('/passkey/*', noStore);

// --- login -----------------------------------------------------------------

passkeyRoutes.post('/passkey/login/options', async (c) => {
  const limited = await limitIp(c);
  if (limited) return limited;
  const options = await generateAuthenticationOptions({
    rpID: c.env.RP_ID,
    allowCredentials: [],
    userVerification: 'preferred',
    timeout: config.WEBAUTHN_CHALLENGE_TTL,
  });
  await indexStub(c.env).putChallenge(PURPOSE_LOGIN, options.challenge);
  return c.json({ ok: true, options });
});

passkeyRoutes.post('/passkey/login/verify', async (c) => {
  const limited = await limitIp(c);
  if (limited) return limited;
  const body = await readBody(c);
  const credential = asAuthenticationResponse(body?.json?.credential);
  if (!body || !credential) return apiError(c, 400, 'bad_request', BAD_REQUEST);
  const challenge = challengeOf(credential.response.clientDataJSON);
  const userId = userIdOf(credential.response.userHandle);
  if (!challenge) return apiError(c, 400, 'bad_request', BAD_REQUEST);

  const index = indexStub(c.env);
  if (!(await index.consumeChallenge(challenge, PURPOSE_LOGIN))) {
    return apiError(c, 400, 'challenge_expired', PASSKEY_MESSAGES.challenge_expired);
  }
  // Unknown handle, unknown credential and bad signature all look the same.
  if (!userId || !(await index.isActiveUser(userId))) {
    return apiError(c, 401, 'passkey_failed', PASSKEY_MESSAGES.passkey_failed);
  }
  const result = await userStub(c.env, userId).verifyPasskeyLogin(
    credential, challenge, passkeyOrigins(c.env), c.env.RP_ID, requestInfo(c),
  );
  if (result.ok) return completeLogin(c, userId, result.session, returnToFrom(c, body));
  if (result.reason === 'disabled') return apiError(c, 403, 'account_disabled', PASSKEY_MESSAGES.account_disabled);
  return apiError(c, 401, 'passkey_failed', PASSKEY_MESSAGES.passkey_failed);
});

// --- registration ------------------------------------------------------------

passkeyRoutes.post('/passkey/register/options', async (c) => {
  const limited = await limitIp(c);
  if (limited) return limited;
  const body = await readBody(c);
  if (!body) return apiError(c, 400, 'bad_request', BAD_REQUEST);
  const index = indexStub(c.env);

  const signupId = body.fields.signupId;
  if (signupId !== undefined) {
    if (!SIGNUP_ID.test(signupId)) return apiError(c, 400, 'bad_request', BAD_REQUEST);
    const signup = await index.getVerifiedSignup(signupId);
    if (!signup) return apiError(c, 400, 'not_verified', PASSKEY_MESSAGES.not_verified);
    const options = await registrationOptions(c.env, signup.userId, signup.username, []);
    await index.putChallenge(PURPOSE_SIGNUP, options.challenge, { signupId, userId: signup.userId });
    return c.json({ ok: true, options });
  }

  const auth = await requireRecentAuth(c);
  if (auth instanceof Response) return auth;
  const user = userStub(c.env, auth.userId);
  const existing = await user.passkeyDescriptors();
  if (existing.length >= config.MAX_PASSKEYS_PER_ACCOUNT) {
    return apiError(c, 409, 'too_many', PASSKEY_MESSAGES.too_many);
  }
  const options = await registrationOptions(c.env, auth.userId, auth.username, existing);
  await index.putChallenge(PURPOSE_ADD, options.challenge, { userId: auth.userId, sessionId: auth.sessionId });
  return c.json({ ok: true, options });
});

passkeyRoutes.post('/passkey/register/verify', async (c) => {
  const limited = await limitIp(c);
  if (limited) return limited;
  const body = await readBody(c);
  if (!body) return apiError(c, 400, 'bad_request', BAD_REQUEST);
  const auth = await requireRecentAuth(c);
  if (auth instanceof Response) return auth;

  const verified = await verifyRegistration(c, body.json?.credential, PURPOSE_ADD);
  if (verified instanceof Response) return verified;
  const data = verified.data;
  if (data?.userId !== auth.userId) return apiError(c, 400, 'passkey_failed', PASSKEY_MESSAGES.register_failed);

  const label = typeof body.json?.label === 'string' ? body.json.label : undefined;
  const result = await userStub(c.env, auth.userId).addPasskey({ ...verified.passkey, label });
  if (result.ok) return c.json({ ok: true, passkey: result.passkey });
  if (result.reason === 'duplicate') return apiError(c, 409, 'duplicate', PASSKEY_MESSAGES.duplicate);
  if (result.reason === 'too_many') return apiError(c, 409, 'too_many', PASSKEY_MESSAGES.too_many);
  return apiError(c, 400, 'passkey_failed', PASSKEY_MESSAGES.register_failed);
});

// --- management (profile page) ---------------------------------------------------

passkeyRoutes.post('/passkey/credentials/:id/rename', async (c) => {
  const limited = await limitIp(c);
  if (limited) return limited;
  const id = c.req.param('id');
  const body = await readBody(c);
  if (!body || !CRED_ID.test(id)) return apiError(c, 400, 'bad_request', BAD_REQUEST);
  const auth = await requireRecentAuth(c);
  if (auth instanceof Response) return auth;
  const result = await userStub(c.env, auth.userId).renamePasskey(id, body.fields.label ?? '');
  if (result.ok) return c.json({ ok: true });
  if (result.reason === 'invalid_label') return apiError(c, 400, 'invalid_label', PASSKEY_MESSAGES.invalid_label);
  return apiError(c, 404, 'not_found', PASSKEY_MESSAGES.not_found);
});

passkeyRoutes.post('/passkey/credentials/:id/delete', async (c) => {
  const limited = await limitIp(c);
  if (limited) return limited;
  const id = c.req.param('id');
  if (!CRED_ID.test(id)) return apiError(c, 400, 'bad_request', BAD_REQUEST);
  const auth = await requireRecentAuth(c);
  if (auth instanceof Response) return auth;
  const result = await userStub(c.env, auth.userId).deletePasskey(id);
  if (result.ok) return c.json({ ok: true });
  if (result.reason === 'last_method') return apiError(c, 409, 'last_method', PASSKEY_MESSAGES.last_method);
  return apiError(c, 404, 'not_found', PASSKEY_MESSAGES.not_found);
});

// --- profile page (PROFILE_SLOTS hook) ------------------------------------------

PROFILE_SLOTS.passkeys = async ({ c, user }) => ({
  html: passkeySection(await userStub(c.env, user.sub).listPasskeys(), {
    reauthUrl: reauthUrl(c.env, `${c.env.ISSUER}/profile`),
  }),
  scripts: [...PASSKEY_SECTION_SCRIPTS],
});

// --- signup (SIGNUP_CREDENTIALS hook) -------------------------------------------

/**
 * /signup/complete with `{ signupId, credential }`: verify the registration
 * against a `register:signup` challenge issued for this signup, then attach
 * the passkey once the User DO exists.
 */
export const passkeySignupCredential: SignupCredential = {
  matches: (body) => typeof body.json?.credential === 'object' && body.json.credential !== null,
  async prepare(c, body, signup) {
    const verified = await verifyRegistration(c, body.json?.credential, PURPOSE_SIGNUP);
    if (verified instanceof Response) return verified;
    const data = verified.data;
    if (data?.signupId !== signup.signupId || data?.userId !== signup.userId) {
      return apiError(c, 400, 'passkey_failed', PASSKEY_MESSAGES.register_failed);
    }
    return {
      amr: ['hwk'],
      async attach(user) {
        const result = await user.addPasskey(verified.passkey);
        if (!result.ok) throw new Error(`signup passkey not stored: ${result.reason}`);
      },
    };
  },
};

// --- helpers -------------------------------------------------------------------

function registrationOptions(
  env: Env,
  userId: string,
  username: string,
  exclude: { id: string; transports: string[] }[],
) {
  return generateRegistrationOptions({
    rpName: config.PASSKEY_RP_NAME,
    rpID: env.RP_ID,
    userID: new Uint8Array(new TextEncoder().encode(userId)),
    userName: username,
    userDisplayName: username,
    timeout: config.WEBAUTHN_CHALLENGE_TTL,
    attestationType: 'none',
    excludeCredentials: exclude.map((d) => ({ id: d.id, transports: d.transports })),
    authenticatorSelection: { residentKey: 'required', requireResidentKey: true, userVerification: 'preferred' },
  });
}

/**
 * Consume the response's challenge for `purpose` and verify the
 * registration. Returns the passkey to store plus the challenge's data, or
 * an error Response.
 */
async function verifyRegistration(
  c: AppContext,
  raw: unknown,
  purpose: string,
): Promise<Response | { passkey: NewPasskey; data: ChallengeData | null }> {
  const response = asRegistrationResponse(raw);
  const challenge = response ? challengeOf(response.response.clientDataJSON) : null;
  if (!response || !challenge) return apiError(c, 400, 'bad_request', BAD_REQUEST);
  const record = await indexStub(c.env).consumeChallenge(challenge, purpose);
  if (!record) return apiError(c, 400, 'challenge_expired', PASSKEY_MESSAGES.challenge_expired);

  let info;
  try {
    const result = await verifyRegistrationResponse({
      response,
      expectedChallenge: challenge,
      expectedOrigin: passkeyOrigins(c.env),
      expectedRPID: c.env.RP_ID,
      requireUserVerification: false,
    });
    if (!result.verified) throw new Error('not verified');
    info = result.registrationInfo;
  } catch {
    return apiError(c, 400, 'passkey_failed', PASSKEY_MESSAGES.register_failed);
  }
  const { credential } = info;
  const transports = credential.transports ?? response.response.transports ?? [];
  return {
    data: record.data,
    passkey: {
      credentialId: credential.id,
      publicKey: isoBase64URL.fromBuffer(credential.publicKey),
      counter: credential.counter,
      transports: transports.filter((t): t is string => typeof t === 'string').slice(0, 10),
      aaguid: info.aaguid,
      backedUp: info.credentialBackedUp,
      deviceType: info.credentialDeviceType,
    },
  };
}

interface RecentAuth {
  userId: string;
  sessionId: string;
  username: string;
}

/**
 * A live session (http/auth liveSession) whose last interactive login is
 * within REAUTH_WINDOW. Otherwise the shared shapes: 401 unauthorized when
 * signed out / revoked, 403 reauth_required when the login is too old.
 * (Not requireSession middleware: /passkey/register/options also serves
 * signed-out signups.)
 */
async function requireRecentAuth(c: AppContext): Promise<RecentAuth | Response> {
  const live = await liveSession(c);
  if (!live) return unauthorizedResponse(c);
  if (!hasRecentAuth(live.claims)) {
    return reauthRequiredResponse(c, `${c.env.ISSUER}/profile`, PASSKEY_MESSAGES.reauth_required);
  }
  return { userId: live.token.sub, sessionId: live.token.sid, username: live.claims.preferred_username };
}

/** The challenge in a base64url clientDataJSON, or null. */
function challengeOf(clientDataJSON: string): string | null {
  try {
    const { challenge } = decodeClientDataJSON(clientDataJSON);
    return typeof challenge === 'string' && B64URL.test(challenge) && challenge.length <= 256 ? challenge : null;
  } catch {
    return null;
  }
}

/** The userId in a userHandle (base64url of the userId's UTF-8 bytes), or null. */
function userIdOf(userHandle: string | undefined): string | null {
  if (!userHandle || !B64URL.test(userHandle) || userHandle.length > 128) return null;
  try {
    const userId = isoBase64URL.toUTF8String(userHandle);
    return USER_ID.test(userId) ? userId : null;
  } catch {
    return null;
  }
}

function isB64(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= MAX_B64_LENGTH && B64URL.test(value);
}

/** Shape check before anything is decoded; the library validates the rest. */
function asAuthenticationResponse(raw: unknown): AuthenticationResponseJSON | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const r = raw as Record<string, unknown>;
  const resp = r.response as Record<string, unknown> | undefined;
  if (!isB64(r.id) || !isB64(r.rawId) || r.type !== 'public-key' || typeof resp !== 'object' || resp === null) return null;
  if (!isB64(resp.clientDataJSON) || !isB64(resp.authenticatorData) || !isB64(resp.signature)) return null;
  if (resp.userHandle !== undefined && resp.userHandle !== null && !isB64(resp.userHandle)) return null;
  return {
    id: r.id,
    rawId: r.rawId,
    type: 'public-key',
    clientExtensionResults: {},
    response: {
      clientDataJSON: resp.clientDataJSON,
      authenticatorData: resp.authenticatorData,
      signature: resp.signature,
      ...(typeof resp.userHandle === 'string' ? { userHandle: resp.userHandle } : {}),
    },
  };
}

function asRegistrationResponse(raw: unknown): RegistrationResponseJSON | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const r = raw as Record<string, unknown>;
  const resp = r.response as Record<string, unknown> | undefined;
  if (!isB64(r.id) || !isB64(r.rawId) || r.type !== 'public-key' || typeof resp !== 'object' || resp === null) return null;
  if (!isB64(resp.clientDataJSON) || !isB64(resp.attestationObject)) return null;
  const transports = Array.isArray(resp.transports)
    ? resp.transports.filter((t): t is string => typeof t === 'string' && t.length <= 32)
    : undefined;
  return {
    id: r.id,
    rawId: r.rawId,
    type: 'public-key',
    clientExtensionResults: {},
    response: {
      clientDataJSON: resp.clientDataJSON,
      attestationObject: resp.attestationObject,
      ...(transports ? { transports: transports as RegistrationResponseJSON['response']['transports'] } : {}),
    },
  };
}
