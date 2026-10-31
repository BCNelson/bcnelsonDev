/**
 * GET /profile (phase 4): the account page. Its actions post to /api/me/*
 * (routes/me.ts).
 *
 * Other features add sections through PROFILE_SLOTS (like SIGNUP_CREDENTIALS):
 *
 *   // e.g. in routes/passkey.ts
 *   PROFILE_SLOTS.passkeys = ({ account }) => ({
 *     html: passkeySection(account.credentials.filter((c) => c.type === 'passkey')),
 *     scripts: [PASSKEYS_JS],
 *   });
 *   // e.g. in routes/admin.ts
 *   PROFILE_SLOTS.admin = ({ account }) =>
 *     account.profile.roles.includes('admin') ? { html: html`<p><a href="/admin">Admin</a></p>` } : null;
 *
 * Without a passkeys provider the page lists non-password credentials
 * (pages/profile.ts credentialList); without an admin provider the slot is empty.
 */

import { Hono } from 'hono';
import type { AccessTokenPayload } from '../tokens';
import type { AccountInfo } from '../do/user/profile';
import type { AppContext } from '../http';
import { requireSession, type AuthContext, type AuthEnv } from '../http/auth';
import { renderPage, type Html } from '../pages/layout';
import { PROFILE_JS, profilePage } from '../pages/profile';
import { userStub } from './auth-common';

export interface ProfileSlotInput {
  c: AuthContext;
  account: AccountInfo;
  user: AccessTokenPayload;
}

export interface ProfileSlotContent {
  html: Html;
  /** defineAsset paths, loaded after profile.js. */
  scripts?: string[];
}

export type ProfileSlotProvider = (input: ProfileSlotInput) => ProfileSlotContent | null | Promise<ProfileSlotContent | null>;

/** Section providers for the profile page; see the module comment. */
export const PROFILE_SLOTS: {
  passkeys?: ProfileSlotProvider;
  admin?: ProfileSlotProvider;
  /** Linked social accounts (routes/oauth.ts), under "Sign-in methods". */
  social?: ProfileSlotProvider;
  /** Connected apps: OIDC grants with revoke (routes/oidc.ts). */
  apps?: ProfileSlotProvider;
} = {};

export const profileRoutes = new Hono<AuthEnv>();

profileRoutes.get('/profile', requireSession({ verifyActive: true }), async (c) => {
  const user = c.get('user');
  const account = await userStub(c.env, user.sub).getAccount();
  const input: ProfileSlotInput = { c, account, user };
  const [passkeys, admin, social, apps] = await Promise.all([
    PROFILE_SLOTS.passkeys?.(input) ?? null,
    PROFILE_SLOTS.admin?.(input) ?? null,
    PROFILE_SLOTS.social?.(input) ?? null,
    PROFILE_SLOTS.apps?.(input) ?? null,
  ]);
  return renderPage(c as unknown as AppContext, {
    title: 'Your account',
    body: profilePage({
      account,
      currentSessionId: user.sid,
      slots: { passkeys: passkeys?.html, admin: admin?.html, social: social?.html, apps: apps?.html },
    }),
    scripts: [PROFILE_JS, ...[passkeys, admin, social, apps].flatMap((slot) => slot?.scripts ?? [])],
  });
});
