/**
 * Social login UI (design §6.7): provider buttons for /login and /signup,
 * the callback outcome pages (error, "an account with this email exists",
 * link confirmation), the social signup page and the profile section.
 *
 * Provider buttons are plain links (GET /oauth/:provider/start): CSP
 * form-action is 'self' and some browsers apply it to the redirect chain.
 */

import { html } from 'hono/html';
import { config } from '../config';
import type { OAuthCredentialInfo } from '../do/user/oauth';
import { defineAsset } from './assets';
import { errorBox, type Html } from './layout';

/** User-facing text for social login outcomes (also `?error=` codes on these pages). */
export const OAUTH_MESSAGES: Record<string, string> = {
  provider_error: "Sign-in was cancelled or the provider couldn't complete it. Please try again.",
  state_invalid: 'That sign-in attempt expired or was started in another browser. Please try again.',
  exchange_failed: "We couldn't confirm your account with the provider. Please try again.",
  account_disabled: 'This account has been disabled. Contact the site owner if you think this is a mistake.',
  identity_taken: 'That account is already linked to a different bcnelson.dev account.',
  link_session_changed: 'You signed in or out while linking. Please start linking again from your profile.',
  too_many: `You can link at most ${config.MAX_OAUTH_IDENTITIES_PER_ACCOUNT} accounts.`,
  rate_limited: 'Too many requests. Please wait a minute and try again.',
  signup_expired: 'That sign-up expired. Please start again.',
  link_expired: 'That link request expired or was for a different account. Sign in with the provider again to retry.',
  not_found: "That linked account doesn't exist anymore. Reload the page.",
  last_method: "You can't remove your only way to sign in. Add a password, a passkey or another account first.",
  username_taken: 'That username is taken.',
  invalid_username: 'Usernames are 3–30 characters: letters, numbers, - and _, starting with a letter or number.',
  invalid_email: 'Enter a valid email address.',
  email_taken: 'That email address already belongs to an account. Sign in to it and link from your profile.',
  turnstile_failed: 'Please complete the verification and try again.',
  invalid_code: "That code isn't right. Check the email and try again.",
  code_expired: 'That code has expired. Send a new one.',
  too_many_attempts: 'Too many wrong codes. Send a new one.',
  not_verified: 'Verify your email first, or start again.',
  signup_failed: "We couldn't create your account. Please start again.",
  bad_request: 'The request was missing something. Please reload the page and try again.',
};

export interface ProviderButton {
  id: string;
  label: string;
}

/** `/oauth/<id>/start?...` */
export function startUrl(providerId: string, returnTo: string, intent: 'login' | 'link' = 'login'): string {
  const params = new URLSearchParams({ return_to: returnTo });
  if (intent === 'link') params.set('intent', 'link');
  return `/oauth/${encodeURIComponent(providerId)}/start?${params.toString()}`;
}

/** The /login and /signup social slot: one link per enabled provider, or nothing. */
export function socialButtons(providers: ProviderButton[], returnTo: string, verb = 'Continue'): Html | undefined {
  if (providers.length === 0) return undefined;
  return html`<div class="social-buttons">
  ${providers.map((p) => html`<a class="button secondary" data-provider="${p.id}" href="${startUrl(p.id, returnTo)}">${verb} with ${p.label}</a>`)}
</div>`;
}

/** A callback/flow failure with a way back. */
export function oauthErrorPage(code: string, loginUrl: string): Html {
  const message = OAUTH_MESSAGES[code] ?? OAUTH_MESSAGES.exchange_failed!;
  return html`<h1>Couldn't sign you in</h1>
${errorBox(message)}
<p class="foot"><a href="${loginUrl}">Back to sign in</a></p>`;
}

/** Unknown identity whose verified email belongs to an account: sign in first, then link. */
export function emailExistsPage(opts: { providerLabel: string; email: string; loginUrl: string; cancelUrl: string }): Html {
  return html`<h1>You already have an account</h1>
<p>An account with <strong>${opts.email}</strong> already exists.
  To use ${opts.providerLabel} to sign in, sign in to that account once and confirm linking.</p>
<a class="button" href="${opts.loginUrl}">Sign in to link ${opts.providerLabel}</a>
<p class="foot muted"><a href="${opts.cancelUrl}">Not now</a></p>`;
}

/** Signed in as the matching account: confirm the link (a plain form post, no JS). */
export function linkConfirmPage(opts: {
  providerLabel: string;
  email: string | null;
  username: string;
  returnTo: string;
  error?: string;
}): Html {
  return html`<h1>Link ${opts.providerLabel}?</h1>
${errorBox(opts.error ? OAUTH_MESSAGES[opts.error] : undefined)}
<p>Link the ${opts.providerLabel} account${opts.email ? html` <strong>${opts.email}</strong>` : ''} to
  <strong>${opts.username}</strong>? You'll be able to sign in with ${opts.providerLabel} from now on.</p>
<form method="post" action="/oauth/social/link">
  <input type="hidden" name="return_to" value="${opts.returnTo}">
  <button type="submit">Link ${opts.providerLabel}</button>
</form>
<form method="post" action="/oauth/social/link/cancel">
  <input type="hidden" name="return_to" value="${opts.returnTo}">
  <button type="submit" class="secondary">Don't link</button>
</form>`;
}

export interface OAuthSignupPageOptions {
  providerLabel: string;
  /** Provider email; fixed when verified, a prefill otherwise. */
  email: string | null;
  emailVerified: boolean;
  usernameSuggestion: string;
  returnTo: string;
  turnstileSiteKey: string;
}

/**
 * Social signup. Verified provider email: one step (username → create).
 * Otherwise: username + email + Turnstile → code → create, like /signup.
 * Driven by oauth-signup.js (needs JS).
 */
export function oauthSignupPage(opts: OAuthSignupPageOptions): Html {
  const usernameField = html`<label for="username">Username</label>
  <input id="username" name="username" type="text" required minlength="3" maxlength="30"
    pattern="[A-Za-z0-9][A-Za-z0-9_\\-]{2,29}" autocomplete="username" value="${opts.usernameSuggestion}"
    autocapitalize="none" autocorrect="off" spellcheck="false" aria-describedby="username-help" autofocus>
  <p id="username-help" class="muted">3–30 characters: letters, numbers, - and _.</p>`;
  const verified = opts.emailVerified && opts.email;
  return html`<h1>Create your account</h1>
<noscript><p class="error">Creating an account needs JavaScript.</p></noscript>
<p class="muted">You're signing up with ${opts.providerLabel}. Choose a username to finish.</p>
<div id="oauth-signup" data-verified="${verified ? '1' : '0'}" data-return-to="${opts.returnTo}">
${verified
    ? html`<form id="oauth-signup-complete" novalidate>
  ${errorBox()}
  ${usernameField}
  <label for="email">Email</label>
  <input id="email" type="email" value="${opts.email}" readonly aria-describedby="email-help">
  <p id="email-help" class="muted">Verified by ${opts.providerLabel}.</p>
  <button type="submit">Create account</button>
</form>`
    : html`<form id="oauth-signup-start" novalidate>
  ${errorBox()}
  ${usernameField}
  <label for="email">Email</label>
  <input id="email" name="email" type="email" required autocomplete="email" spellcheck="false" value="${opts.email ?? ''}">
  <p class="muted">We'll send a code to confirm this address.</p>
  <div id="oauth-signup-turnstile" class="turnstile" data-sitekey="${opts.turnstileSiteKey}"></div>
  <button type="submit">Send code</button>
</form>
<form id="oauth-signup-verify" novalidate hidden>
  ${errorBox()}
  <p>We sent a ${config.CODE_LENGTH}-digit code to <strong id="oauth-signup-email"></strong>.
    If that address already has an account, we sent a sign-in link instead.</p>
  <label for="code">Verification code</label>
  <input id="code" name="code" type="text" required inputmode="numeric" autocomplete="one-time-code"
    pattern="[0-9]*" maxlength="${config.CODE_LENGTH}">
  <button type="submit">Verify and create account</button>
  <button type="button" class="secondary" data-action="restart">Send a new code</button>
</form>`}
</div>`;
}

export const OAUTH_SIGNUP_JS = defineAsset('oauth-signup.js', String.raw`(function () {
  'use strict';
  var root = document.getElementById('oauth-signup');
  if (!root || !window.bcn) return;
  var returnTo = root.getAttribute('data-return-to') || '';

  async function complete(form, data) {
    data.return_to = returnTo;
    var res = await bcn.submit(form, '/oauth/social/signup/complete', data);
    if (res.ok) window.location.assign(res.redirect);
    return res;
  }

  var direct = document.getElementById('oauth-signup-complete');
  if (direct) {
    direct.addEventListener('submit', async function (event) {
      event.preventDefault();
      await complete(direct, { username: bcn.formFields(direct).username || '' });
    });
    return;
  }

  var start = document.getElementById('oauth-signup-start');
  var verify = document.getElementById('oauth-signup-verify');
  if (!start || !verify) return;
  var widget = document.getElementById('oauth-signup-turnstile');
  bcn.turnstile.render(widget);

  start.addEventListener('submit', async function (event) {
    event.preventDefault();
    var data = bcn.formFields(start);
    data.turnstile = bcn.turnstile.token(widget);
    var res = await bcn.submit(start, '/oauth/social/signup/start', data);
    bcn.turnstile.reset(widget);
    if (!res.ok) return;
    document.getElementById('oauth-signup-email').textContent = data.email;
    verify.reset();
    start.hidden = true;
    verify.hidden = false;
    verify.querySelector('input[name=code]').focus();
  });

  verify.addEventListener('submit', async function (event) {
    event.preventDefault();
    var code = (bcn.formFields(verify).code || '').replace(/\s+/g, '');
    var res = await bcn.submit(verify, '/oauth/social/signup/verify', { code: code });
    if (!res.ok) return;
    await complete(verify, {});
  });

  verify.querySelector('[data-action=restart]').addEventListener('click', function () {
    bcn.showError(start, '');
    verify.hidden = true;
    start.hidden = false;
  });
})();
`);

// --- profile -----------------------------------------------------------------

function formatDate(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}

/**
 * The profile page's "Linked accounts" section: each linked identity with
 * Unlink (a `form[data-api]` that profile.js posts as JSON; reauth_required
 * sends the browser to re-login), plus "Link <provider>" links for enabled
 * providers.
 */
export function oauthSection(
  linked: (OAuthCredentialInfo & { providerLabel: string })[],
  linkable: ProviderButton[],
  returnTo: string,
): Html {
  return html`<section id="linked-accounts" aria-labelledby="linked-accounts-title">
  <h3 id="linked-accounts-title">Linked accounts</h3>
  <p class="muted">Sign in with an account you already have elsewhere.</p>
  ${linked.length === 0 ? html`<p class="muted" data-empty>No linked accounts.</p>` : ''}
  <ul class="passkey-list">
    ${linked.map((l) => html`<li data-oauth-id="${l.id}" data-provider="${l.provider}">
      <strong>${l.providerLabel}</strong>
      <span class="muted">${l.email ? html`${l.email} · ` : ''}Linked <time datetime="${new Date(l.createdAt).toISOString()}">${formatDate(l.createdAt)}</time>
        · ${l.lastUsedAt
          ? html`Last used <time datetime="${new Date(l.lastUsedAt).toISOString()}">${formatDate(l.lastUsedAt)}</time>`
          : 'Never used'}</span>
      <form class="actions" data-api="/oauth/social/unlink" data-confirm="Unlink ${l.providerLabel}? You won't be able to sign in with it anymore." novalidate>
        ${errorBox()}
        <input type="hidden" name="credentialId" value="${l.id}">
        <button type="submit" class="secondary">Unlink</button>
      </form>
    </li>`)}
  </ul>
  ${linkable.map((p) => html`<a class="button secondary" data-link-provider="${p.id}" href="${startUrl(p.id, returnTo, 'link')}">Link ${p.label}</a>`)}
</section>`;
}
