/**
 * The signed state cookie that carries a social login from
 * /oauth/:provider/start to its callback: `state`, the PKCE verifier, the
 * intent, return_to and (for linking) the signed-in user + session.
 *
 * Format: `<base64url(JSON payload)>.<base64url(HMAC-SHA256)>`. The HMAC key
 * is derived from the access-token signing key rather than a new secret:
 * Ed25519 signatures are deterministic, so the signature over a fixed label
 * is a stable secret only the signing-key holder can compute; it is then run
 * through HKDF-SHA256 for a separate 256-bit HMAC key. No extra secret to
 * provision; rotating AUTH_SIGNING_KEY only invalidates in-flight logins
 * (OAUTH_STATE_TTL). The payload isn't encrypted: the PKCE verifier is no
 * secret from the browser that holds it, and the cookie is HttpOnly,
 * Path=/oauth, SameSite=Lax, Secure on https.
 */

import { config } from '../config';
import { toBase64url, timingSafeEqual } from '../crypto/hash';
import type { Env } from '../env';
import { loadKeySet } from '../tokens';

export type OAuthIntent = 'login' | 'link';

export interface OAuthState {
  /** Provider id. */
  provider: string;
  /** The `state` parameter sent to the provider. */
  state: string;
  /** PKCE code verifier. */
  verifier: string;
  intent: OAuthIntent;
  /** Validated return_to. */
  returnTo: string;
  /** intent=link: who started it, and from which session. */
  userId?: string;
  sessionId?: string;
  /** Epoch ms. */
  expiresAt: number;
}

const LABEL = 'bcnelson.dev oauth-state key v1';
const MAC_PREFIX = 'oauth-state.v1.';
const MAX_COOKIE_LENGTH = 4096;
const encoder = new TextEncoder();

const keys = new WeakMap<CryptoKey, Promise<CryptoKey>>();

/** HMAC key for state cookies, derived from (and cached per) the current signing key. */
export async function stateKey(env: Env): Promise<CryptoKey> {
  const { current } = await loadKeySet(env);
  let key = keys.get(current.privateKey);
  if (!key) {
    key = (async () => {
      const seed = await crypto.subtle.sign('Ed25519', current.privateKey, encoder.encode(LABEL));
      const ikm = await crypto.subtle.importKey('raw', seed, 'HKDF', false, ['deriveKey']);
      return crypto.subtle.deriveKey(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: encoder.encode('oauth-state-hmac') },
        ikm,
        { name: 'HMAC', hash: 'SHA-256', length: 256 },
        false,
        ['sign'],
      );
    })();
    keys.set(current.privateKey, key);
  }
  return key;
}

async function mac(env: Env, body: string): Promise<string> {
  const sig = await crypto.subtle.sign('HMAC', await stateKey(env), encoder.encode(MAC_PREFIX + body));
  return toBase64url(new Uint8Array(sig));
}

function b64urlEncodeJson(value: unknown): string {
  return toBase64url(encoder.encode(JSON.stringify(value)));
}

function b64urlDecodeJson(value: string): unknown {
  const b64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
  const bytes = Uint8Array.from(bin, (ch) => ch.charCodeAt(0));
  return JSON.parse(new TextDecoder().decode(bytes));
}

/** Serialize and sign. */
export async function sealState(env: Env, state: OAuthState): Promise<string> {
  const body = b64urlEncodeJson({
    v: 1,
    p: state.provider,
    s: state.state,
    cv: state.verifier,
    i: state.intent,
    r: state.returnTo,
    u: state.userId,
    sid: state.sessionId,
    exp: state.expiresAt,
  });
  return `${body}.${await mac(env, body)}`;
}

/** Verify (constant-time) and parse; null when malformed, tampered with or expired. */
export async function openState(env: Env, cookie: string | undefined, now = Date.now()): Promise<OAuthState | null> {
  if (!cookie || cookie.length > MAX_COOKIE_LENGTH) return null;
  const dot = cookie.indexOf('.');
  if (dot <= 0 || dot !== cookie.lastIndexOf('.')) return null;
  const body = cookie.slice(0, dot);
  const sig = cookie.slice(dot + 1);
  if (!/^[A-Za-z0-9_-]+$/.test(body) || !/^[A-Za-z0-9_-]+$/.test(sig)) return null;
  if (!timingSafeEqual(await mac(env, body), sig)) return null;
  let raw: Record<string, unknown>;
  try {
    const parsed = b64urlDecodeJson(body);
    if (typeof parsed !== 'object' || parsed === null) return null;
    raw = parsed as Record<string, unknown>;
  } catch {
    return null;
  }
  const str = (v: unknown) => (typeof v === 'string' && v.length > 0 && v.length <= config.MAX_RETURN_TO_LENGTH ? v : null);
  const provider = str(raw.p);
  const state = str(raw.s);
  const verifier = str(raw.cv);
  const returnTo = str(raw.r);
  const intent = raw.i === 'login' || raw.i === 'link' ? raw.i : null;
  if (raw.v !== 1 || !provider || !state || !verifier || !returnTo || !intent) return null;
  if (typeof raw.exp !== 'number' || raw.exp <= now) return null;
  const userId = str(raw.u) ?? undefined;
  const sessionId = str(raw.sid) ?? undefined;
  if (intent === 'link' && (!userId || !sessionId)) return null;
  return { provider, state, verifier, intent, returnTo, userId, sessionId, expiresAt: raw.exp };
}
