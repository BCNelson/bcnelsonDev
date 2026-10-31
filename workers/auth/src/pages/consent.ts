/**
 * OIDC pages (routes/oidc.ts): the consent screen, the authorize error page,
 * and RP-initiated logout's confirmation and signed-out pages. Plain HTML
 * forms; no scripts needed.
 */

import { html } from 'hono/html';
import type { Html } from './layout';

/** What each scope means, in the user's terms. */
export const SCOPE_DESCRIPTIONS: Record<string, string> = {
  openid: 'Know who you are on this site (a stable account id)',
  profile: 'See your username, display name and picture',
  email: 'See your primary email address',
  roles: 'See your roles on this site',
  offline_access: 'Stay connected when you are not using it',
};

export interface ConsentPageOptions {
  clientName: string;
  /** Host of the redirect URI, so the user sees where they'll be sent. */
  clientHost: string;
  username: string;
  scopes: string[];
  consentToken: string;
}

export function consentPage(opts: ConsentPageOptions): Html {
  return html`<h1>Allow ${opts.clientName}?</h1>
<p><strong>${opts.clientName}</strong> <span class="muted">(${opts.clientHost})</span> wants to use your
account <strong>${opts.username}</strong> to:</p>
<ul>
${opts.scopes.map((s) => html`<li>${SCOPE_DESCRIPTIONS[s] ?? s}</li>`)}
</ul>
<form method="post" action="/authorize/consent">
  <input type="hidden" name="consent_token" value="${opts.consentToken}">
  <button type="submit" name="decision" value="allow">Allow</button>
  <button type="submit" name="decision" value="deny" class="secondary">Cancel</button>
</form>
<p class="foot muted">Not you? <a href="/logout">Sign out</a> first.</p>`;
}

export function oidcErrorPage(opts: { error: string; description: string }): Html {
  return html`<h1>Can't sign you in to that application</h1>
<div class="error" role="alert">${opts.description}</div>
<p class="muted">Error code: ${opts.error}. If you followed a link from another site, let its owner know.</p>`;
}

export interface LogoutPageOptions {
  /** Shown as "… and return to <name>" when a valid post-logout redirect is known. */
  clientName?: string;
  postLogoutRedirectUri?: string;
  state?: string;
  clientId?: string;
}

/** GET /logout: confirm before signing out (a GET alone must not log anyone out). */
export function logoutConfirmPage(opts: LogoutPageOptions): Html {
  return html`<h1>Sign out?</h1>
<p>${opts.clientName ? html`<strong>${opts.clientName}</strong> asked to sign you out.` : 'Sign out of this site on this browser.'}</p>
<form method="post" action="/logout/end-session">
  ${opts.postLogoutRedirectUri ? html`<input type="hidden" name="post_logout_redirect_uri" value="${opts.postLogoutRedirectUri}">` : ''}
  ${opts.state !== undefined ? html`<input type="hidden" name="state" value="${opts.state}">` : ''}
  ${opts.clientId ? html`<input type="hidden" name="client_id" value="${opts.clientId}">` : ''}
  <button type="submit">Sign out</button>
</form>`;
}

export function signedOutPage(): Html {
  return html`<h1>Signed out</h1>
<p>You have been signed out on this browser.</p>`;
}
