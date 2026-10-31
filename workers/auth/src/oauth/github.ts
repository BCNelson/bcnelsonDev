/**
 * GitHub (OAuth app, not OIDC). Scopes `read:user user:email`.
 *
 * Uses arctic's generic OAuth2Client rather than its `GitHub` class so the
 * flow carries PKCE (S256) as well as `state`; GitHub supports PKCE for OAuth
 * apps. The token request goes through arctic (global fetch); the API calls
 * below use the injectable `deps.fetch`.
 *
 * Profile: GET /user (id → subject, login → username, name, avatar_url) and
 * GET /user/emails. The email is the primary address when it is verified,
 * else the first verified one; with no verified address we keep the primary
 * (or /user's public email) with emailVerified false, so signup falls back to
 * our own code verification.
 */

import { CodeChallengeMethod, OAuth2Client } from 'arctic';
import { config } from '../config';
import type { Env } from '../env';
import {
  OAuthExchangeError,
  cleanHttpsUrl,
  cleanString,
  defaultDeps,
  readSecret,
  redirectUri,
  type OAuthDeps,
  type OAuthProvider,
  type ProviderProfile,
} from './types';

const AUTHORIZE_URL = 'https://github.com/login/oauth/authorize';
const TOKEN_URL = 'https://github.com/login/oauth/access_token';
const API = 'https://api.github.com';
const SCOPES = ['read:user', 'user:email'];

async function client(env: Env): Promise<OAuth2Client> {
  const secret = await readSecret(env.GITHUB_CLIENT_SECRET, env.GITHUB_CLIENT_SECRET_DEV, 'GITHUB_CLIENT_SECRET');
  return new OAuth2Client(env.GITHUB_CLIENT_ID ?? '', secret, redirectUri(env, 'github'));
}

async function api(deps: OAuthDeps, path: string, accessToken: string): Promise<unknown> {
  const res = await deps.fetch(`${API}${path}`, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': config.OAUTH_USER_AGENT,
    },
    signal: AbortSignal.timeout(config.OAUTH_HTTP_TIMEOUT),
  });
  if (!res.ok) throw new OAuthExchangeError(`github ${path}: HTTP ${res.status}`);
  return res.json();
}

interface GitHubEmail {
  email: string;
  primary: boolean;
  verified: boolean;
}

/** Choose the address per the module comment. */
export function pickGitHubEmail(list: unknown, fallback?: string): { email?: string; emailVerified: boolean } {
  const emails: GitHubEmail[] = Array.isArray(list)
    ? list.flatMap((e) => {
      const email = cleanString((e as Record<string, unknown>)?.email, 254);
      if (!email) return [];
      const r = e as Record<string, unknown>;
      return [{ email, primary: r.primary === true, verified: r.verified === true }];
    })
    : [];
  const chosen = emails.find((e) => e.primary && e.verified) ?? emails.find((e) => e.verified);
  if (chosen) return { email: chosen.email, emailVerified: true };
  const primary = emails.find((e) => e.primary)?.email ?? fallback;
  return { email: primary, emailVerified: false };
}

export const github: OAuthProvider = {
  id: 'github',
  label: 'GitHub',
  enabled: (env) => Boolean(env.GITHUB_CLIENT_ID),

  async authorizationUrl(env, state, verifier) {
    return (await client(env)).createAuthorizationURLWithPKCE(AUTHORIZE_URL, state, CodeChallengeMethod.S256, verifier, SCOPES);
  },

  async exchange(env, code, verifier, deps = defaultDeps()): Promise<ProviderProfile> {
    const tokens = await (await client(env)).validateAuthorizationCode(TOKEN_URL, code, verifier);
    const accessToken = tokens.accessToken();
    const user = (await api(deps, '/user', accessToken)) as Record<string, unknown> | null;
    const id = user?.id;
    if (typeof id !== 'number' && typeof id !== 'string') throw new OAuthExchangeError('github /user: no id');
    const subject = String(id);
    if (!/^[0-9]{1,20}$/.test(subject)) throw new OAuthExchangeError('github /user: unexpected id');
    const emails = await api(deps, '/user/emails', accessToken);
    const { email, emailVerified } = pickGitHubEmail(emails, cleanString(user?.email, 254));
    return {
      subject,
      email,
      emailVerified,
      name: cleanString(user?.name, config.PROFILE_NAME_MAX_LENGTH),
      picture: cleanHttpsUrl(user?.avatar_url, config.PICTURE_URL_MAX_LENGTH),
      username: cleanString(user?.login, 39),
    };
  },
};
