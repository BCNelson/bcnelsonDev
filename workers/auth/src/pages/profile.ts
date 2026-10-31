/**
 * GET /profile page (phase 4): profile, email addresses, sessions and
 * sign-in methods. Needs JS: every action is a `form[data-api]` that
 * profile.js posts as JSON to that /api/me/* endpoint, then reloads (or goes
 * to `data-next`). A `reauth_required` answer sends the browser to its
 * `reauthUrl`.
 *
 * Slots (filled by routes/profile.ts PROFILE_SLOTS):
 *   passkeys → replaces the generic credential list under "Sign-in methods"
 *   admin    → shown under the heading (e.g. an "Admin" link)
 *   social   → linked accounts, after passkeys
 *   apps     → "Connected apps" section at the end
 */

import { html } from 'hono/html';
import { config } from '../config';
import type { AccountInfo, CredentialInfo } from '../do/user/profile';
import type { SessionInfo } from '../do/user';
import { defineAsset } from './assets';
import { errorBox, type Html } from './layout';

export interface ProfilePageOptions {
  account: AccountInfo;
  currentSessionId: string;
  /** `social`: linked accounts (routes/oauth.ts), after passkeys under "Sign-in methods". */
  /** `apps`: connected apps (routes/oidc.ts), its own section after sign-in methods. */
  slots?: { passkeys?: Html; admin?: Html; social?: Html; apps?: Html };
}

/** `2026-10-31 12:00 UTC`. */
export function formatTime(ms: number): string {
  return `${new Date(ms).toISOString().slice(0, 16).replace('T', ' ')} UTC`;
}

function shortAgent(ua: string | null): string {
  if (!ua) return 'Unknown device';
  return ua.length > 80 ? `${ua.slice(0, 77)}…` : ua;
}

export function profilePage(opts: ProfilePageOptions): Html {
  const { account } = opts;
  const p = account.profile;
  return html`<h1>Your account</h1>
<noscript><p class="error">This page needs JavaScript.</p></noscript>
<p class="muted">Signed in as <strong>${p.username}</strong>.</p>
<!-- slot: admin (phase 6) -->
<div data-slot="admin">${opts.slots?.admin ?? ''}</div>
${accountSection(account)}
${emailsSection(account)}
${sessionsSection(account.sessions, opts.currentSessionId)}
${signInSection(account, opts.slots?.passkeys, opts.slots?.social)}
<!-- slot: apps (connected OIDC apps) -->
<div data-slot="apps">${opts.slots?.apps ?? ''}</div>`;
}

/** One connected app as the profile page shows it. */
export interface ConnectedApp {
  clientId: string;
  name: string;
  scopes: string[];
  connectedAt: number;
  /** The client was disabled by an admin (its tokens no longer work). */
  disabled: boolean;
}

/** "Connected apps": remembered OIDC consents, each with Disconnect (reauth). */
export function connectedAppsSection(apps: ConnectedApp[]): Html {
  return html`<section id="apps" aria-labelledby="h-apps">
<h2 id="h-apps">Connected apps</h2>
<p class="muted">Apps you allowed to sign you in. Disconnecting signs the app out and asks again next time.</p>
<ul class="passkey-list" data-list="apps">
${apps.map((a) => html`<li data-app="${a.clientId}">
  <strong>${a.name}</strong>${a.disabled ? html` <span class="badge">Disabled</span>` : ''}
  <span class="muted">Can see: ${a.scopes.join(', ')} · connected ${formatTime(a.connectedAt)}</span>
  <form class="actions" data-api="/api/me/apps/${encodeURIComponent(a.clientId)}/revoke"
    data-confirm="Disconnect ${a.name}? It will be signed out." novalidate>
    ${errorBox()}
    <button type="submit" class="secondary">Disconnect</button>
  </form>
</li>`)}
</ul>
</section>`;
}

function accountSection(account: AccountInfo): Html {
  const p = account.profile;
  const cooldown = p.usernameChangeAvailableAt
    ? html`You can change it again after ${formatTime(p.usernameChangeAvailableAt)}.`
    : html`You can change it once every ${Math.round(config.USERNAME_CHANGE_COOLDOWN / 86_400_000)} days; the old name stays reserved for you for ${Math.round(config.USERNAME_HOLD / 86_400_000)} days.`;
  return html`<section id="profile" aria-labelledby="h-profile">
<h2 id="h-profile">Profile</h2>
${p.picture ? html`<p><img src="${p.picture}" alt="Your avatar" width="64" height="64" referrerpolicy="no-referrer"></p>` : ''}
<form id="profile-form" data-api="/api/me/profile" novalidate>
  ${errorBox()}
  <label for="name">Display name</label>
  <input id="name" name="name" type="text" maxlength="${config.PROFILE_NAME_MAX_LENGTH}" autocomplete="name" value="${p.name ?? ''}">
  <label for="picture">Avatar URL</label>
  <input id="picture" name="picture" type="url" maxlength="${config.PICTURE_URL_MAX_LENGTH}" inputmode="url"
    placeholder="https://…" value="${p.picture ?? ''}" aria-describedby="picture-help">
  <p id="picture-help" class="muted">An https:// image address. Leave empty for none.</p>
  <button type="submit">Save profile</button>
</form>
<form id="username-form" data-api="/api/me/username" novalidate>
  ${errorBox()}
  <label for="username">Username</label>
  <input id="username" name="username" type="text" required minlength="3" maxlength="30"
    pattern="[A-Za-z0-9][A-Za-z0-9_\\-]{2,29}" autocomplete="username" value="${p.username}"
    autocapitalize="none" autocorrect="off" spellcheck="false" aria-describedby="username-help">
  <p id="username-help" class="muted">${cooldown}</p>
  <button type="submit" class="secondary">Change username</button>
</form>
</section>`;
}

function emailsSection(account: AccountInfo): Html {
  const others = (email: string) => account.emails.filter((e) => e.email !== email);
  const canRemove = account.emails.length > 1;
  return html`<section id="emails" aria-labelledby="h-emails">
<h2 id="h-emails">Email addresses</h2>
<ul data-list="emails">
${account.emails.map((e) => html`<li data-email="${e.email}">
  <strong>${e.email}</strong>${e.primary ? html` <span class="badge" data-primary>Primary</span>` : ''}
  ${e.primary ? '' : html`<form data-api="/api/me/emails/primary" novalidate>
    ${errorBox()}
    <input type="hidden" name="email" value="${e.email}">
    <button type="submit" class="secondary">Make primary</button>
  </form>`}
  ${canRemove ? html`<form data-api="/api/me/emails/remove" data-confirm="Remove ${e.email} from your account?" novalidate>
    ${errorBox()}
    <input type="hidden" name="email" value="${e.email}">
    ${e.primary ? html`<label for="new-primary-${e.email}">New primary address</label>
    <select id="new-primary-${e.email}" name="newPrimary" required>
      ${others(e.email).map((o) => html`<option value="${o.email}">${o.email}</option>`)}
    </select>` : ''}
    <button type="submit" class="secondary">Remove</button>
  </form>` : ''}
</li>`)}
</ul>
${account.pendingEmails.map((pe) => html`<form data-api="/api/me/emails/verify" data-pending="${pe.email}" novalidate>
  ${errorBox()}
  <p>We sent a ${config.CODE_LENGTH}-digit code to <strong>${pe.email}</strong> (valid until ${formatTime(pe.expiresAt)}).</p>
  <input type="hidden" name="email" value="${pe.email}">
  <label for="code-${pe.email}">Verification code</label>
  <input id="code-${pe.email}" name="code" type="text" required inputmode="numeric" autocomplete="one-time-code"
    pattern="[0-9]*" maxlength="${config.CODE_LENGTH}">
  <button type="submit">Verify</button>
</form>`)}
${account.emails.length < config.MAX_EMAILS_PER_ACCOUNT
    ? html`<form id="add-email-form" data-api="/api/me/emails" novalidate>
  ${errorBox()}
  <label for="new-email">Add an email address</label>
  <input id="new-email" name="email" type="email" required autocomplete="email" spellcheck="false">
  <button type="submit" class="secondary">Send code</button>
</form>`
    : html`<p class="muted">You have the maximum of ${config.MAX_EMAILS_PER_ACCOUNT} addresses.</p>`}
</section>`;
}

function sessionsSection(sessions: SessionInfo[], currentSessionId: string): Html {
  return html`<section id="sessions" aria-labelledby="h-sessions">
<h2 id="h-sessions">Where you're signed in</h2>
<ul data-list="sessions">
${sessions.map((s) => {
    const current = s.id === currentSessionId;
    return html`<li data-session="${s.id}">
  <strong>${shortAgent(s.userAgent)}</strong>${current ? html` <span class="badge" data-current>This device</span>` : ''}
  <br><span class="muted">${s.ip ?? 'unknown IP'} · signed in ${formatTime(s.authTime)} · last active ${formatTime(s.lastSeenAt)}</span>
  <form data-api="/api/me/sessions/${s.id}/revoke" ${current ? html`data-next="/login"` : ''} novalidate>
    ${errorBox()}
    <button type="submit" class="secondary">${current ? 'Sign out' : 'Revoke'}</button>
  </form>
</li>`;
  })}
</ul>
${sessions.length > 1 ? html`<form id="revoke-others-form" data-api="/api/me/sessions/revoke-others"
  data-confirm="Sign out of every other device?" novalidate>
  ${errorBox()}
  <button type="submit" class="secondary">Sign out everywhere else</button>
</form>` : ''}
</section>`;
}

function signInSection(account: AccountInfo, passkeys: Html | undefined, social?: Html): Html {
  const has = account.hasPassword;
  return html`<section id="sign-in" aria-labelledby="h-sign-in">
<h2 id="h-sign-in">Sign-in methods</h2>
<h3>Password</h3>
<form id="password-form" data-api="/api/me/password" data-match="newPassword confirm" novalidate>
  ${errorBox()}
  <input type="text" name="username" autocomplete="username" value="${account.profile.username}" hidden>
  ${has ? html`<label for="current-password">Current password</label>
  <input id="current-password" name="currentPassword" type="password" required autocomplete="current-password">` : ''}
  <label for="new-password">${has ? 'New password' : 'Password'}</label>
  <input id="new-password" name="newPassword" type="password" required autocomplete="new-password"
    minlength="${config.PASSWORD_MIN_LENGTH}" maxlength="${config.PASSWORD_MAX_LENGTH}" aria-describedby="new-password-help">
  <p id="new-password-help" class="muted">At least ${config.PASSWORD_MIN_LENGTH} characters. Your other sessions will be signed out.</p>
  <label for="confirm-password">Confirm password</label>
  <input id="confirm-password" name="confirm" type="password" required autocomplete="new-password">
  <button type="submit" class="secondary">${has ? 'Change password' : 'Set a password'}</button>
</form>
<!-- slot: passkeys (phase 3); fallback lists non-password credentials -->
<div data-slot="passkeys">${passkeys ?? credentialList(account.credentials.filter((c) => c.type !== 'password'))}</div>
<!-- slot: social (phase 7) -->
<div data-slot="social">${social ?? ''}</div>
</section>`;
}

/** Generic credential list (no management actions): the passkeys slot's fallback. */
export function credentialList(credentials: CredentialInfo[]): Html {
  return html`<h3>Other sign-in methods</h3>
${credentials.length === 0
    ? html`<p class="muted">No passkeys or linked accounts yet.</p>`
    : html`<ul data-list="credentials">
${credentials.map((c) => html`<li data-credential="${c.id}"><strong>${c.label ?? c.type}</strong>
  <span class="muted">(${c.type}) · added ${formatTime(c.createdAt)}${c.lastUsedAt ? html` · last used ${formatTime(c.lastUsedAt)}` : ''}</span></li>`)}
</ul>`}`;
}

export const PROFILE_JS = defineAsset('profile.js', String.raw`(function () {
  'use strict';
  if (!window.bcn) return;
  var MISMATCH = 'The passwords don\'t match.';

  document.querySelectorAll('form[data-api]').forEach(function (form) {
    form.addEventListener('submit', async function (event) {
      event.preventDefault();
      var data = bcn.formFields(form);
      var match = (form.getAttribute('data-match') || '').split(' ');
      if (match.length === 2) {
        if (data[match[0]] !== data[match[1]]) { bcn.showError(form, MISMATCH); return; }
        delete data[match[1]];
      }
      if (data.code) data.code = data.code.replace(/\s+/g, '');
      var question = form.getAttribute('data-confirm');
      if (question && !window.confirm(question)) return;
      var res = await bcn.submit(form, form.getAttribute('data-api'), data);
      if (!res.ok) {
        if (res.error === 'reauth_required' && res.reauthUrl) window.location.assign(res.reauthUrl);
        // Signed out meanwhile: reloading refreshes the session or goes to /login.
        else if (res.error === 'unauthorized') window.location.reload();
        return;
      }
      var next = form.getAttribute('data-next');
      if (next) window.location.assign(next);
      else window.location.reload();
    });
  });
})();
`);
