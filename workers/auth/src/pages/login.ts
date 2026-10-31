/**
 * GET /login page: username-or-email + password, with slots for passkey and
 * social sign-in. The form also works without JS (POST → 303 redirects).
 */

import { html } from 'hono/html';
import { defineAsset } from './assets';
import { errorBox, type Html } from './layout';

/** User-facing text for /login/password error codes (also used for ?error= on no-JS fallback). */
export const LOGIN_MESSAGES: Record<string, string> = {
  invalid_credentials: 'Incorrect username, email or password.',
  turnstile_required: 'Please complete the verification below and try again.',
  locked: 'Too many failed attempts. Please wait a few minutes and try again.',
  rate_limited: 'Too many requests. Please wait a minute and try again.',
  bad_request: 'Enter your username or email and your password.',
  account_disabled: 'This account has been disabled. Contact the site owner if you think this is a mistake.',
};

/** Informational text for ?notice= codes (e.g. after a password reset). */
export const LOGIN_NOTICES: Record<string, string> = {
  password_updated: 'Password updated. Please sign in with your new password.',
};

export interface LoginPageOptions {
  returnTo: string;
  /** Error code from ?error= (no-JS fallback); only known codes are shown. */
  error?: string;
  /** Notice code from ?notice=; only LOGIN_NOTICES codes are shown. */
  notice?: string;
  turnstileSiteKey: string;
  /**
   * Extra sign-in methods. `passkey`: e.g. a "Sign in with a passkey" button
   * (the identifier input already has autocomplete="username webauthn" for
   * conditional UI). `social`: provider buttons; use links or GET forms, since
   * CSP form-action is 'self' and some browsers apply it to redirects.
   */
  slots?: { passkey?: Html; social?: Html };
  /** Extra page scripts (e.g. passkey login JS), loaded after login.js. */
  scripts?: string[];
  /**
   * Re-authentication (GET /login?reauth=1, design §6.5): shown even when
   * signed in, with a "Confirm it's you" note and the identifier prefilled.
   * The form posts to /login/password?reauth=1 so no-JS errors come back here.
   */
  reauth?: { identifier?: string };
}

export function loginPage(opts: LoginPageOptions): Html {
  const message = opts.error ? LOGIN_MESSAGES[opts.error] : undefined;
  const rt = encodeURIComponent(opts.returnTo);
  const hasAlt = Boolean(opts.slots?.passkey || opts.slots?.social);
  const notice = opts.notice ? LOGIN_NOTICES[opts.notice] : undefined;
  const reauth = opts.reauth;
  const prefill = reauth?.identifier ?? '';
  return html`<h1>${reauth ? "Confirm it's you" : 'Sign in'}</h1>
${reauth ? html`<p class="muted">For your security, sign in again to continue.</p>` : ''}
${notice ? html`<div class="notice" role="status">${notice}</div>` : ''}
<form id="login-form" method="post" action="${reauth ? '/login/password?reauth=1' : '/login/password'}" novalidate>
  <input type="hidden" name="return_to" value="${opts.returnTo}">
  ${errorBox(message)}
  <label for="identifier">Username or email</label>
  <input id="identifier" name="identifier" type="text" required autocomplete="username webauthn"
    autocapitalize="none" autocorrect="off" spellcheck="false" value="${prefill}" ${prefill ? '' : html`autofocus`}>
  <div class="label-row">
    <label for="password">Password</label>
    <a href="/password/forgot?return_to=${rt}">Forgot password?</a>
  </div>
  <input id="password" name="password" type="password" required autocomplete="current-password" ${prefill ? html`autofocus` : ''}>
  <div id="login-turnstile" class="turnstile" data-sitekey="${opts.turnstileSiteKey}"
    ${opts.error === 'turnstile_required' ? '' : html`hidden`}></div>
  <button type="submit">Sign in</button>
</form>
${hasAlt ? html`<div class="divider">or</div>` : ''}
<!-- slot: passkey sign-in (phase 3) -->
<div data-slot="passkey-login">${opts.slots?.passkey ?? ''}</div>
<!-- slot: social sign-in (phase 7) -->
<div data-slot="social-login">${opts.slots?.social ?? ''}</div>
<p class="foot muted">New here? <a href="/signup?return_to=${rt}">Create an account</a></p>`;
}

export const LOGIN_JS = defineAsset('login.js', String.raw`(function () {
  'use strict';
  var form = document.getElementById('login-form');
  if (!form || !window.bcn) return;
  var widget = document.getElementById('login-turnstile');
  if (widget && !widget.hidden) bcn.turnstile.render(widget);

  form.addEventListener('submit', async function (event) {
    event.preventDefault();
    var data = bcn.formFields(form);
    data.turnstile = bcn.turnstile.token(widget);
    var res = await bcn.submit(form, '/login/password', data);
    if (res.ok) { window.location.assign(res.redirect); return; }
    if (res.error === 'turnstile_required') bcn.turnstile.render(widget);
    else bcn.turnstile.reset(widget);
  });
})();
`);
