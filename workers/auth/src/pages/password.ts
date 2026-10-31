/**
 * Password reset pages (design §6.6):
 *   GET /password/forgot  email + Turnstile → POST /password/forgot
 *   GET /password/reset   new password      → POST /password/reset
 * The reset token travels only in the hidden `token` field; scripts read it
 * from the form, never from the URL. Both forms also post without JS
 * (303 redirects), though Turnstile needs JS to render.
 */

import { html } from 'hono/html';
import { config } from '../config';
import { defineAsset } from './assets';
import { errorBox, type Html } from './layout';

/** User-facing text for /password/* error codes (also used for ?error= on no-JS fallback). */
export const PASSWORD_PAGE_MESSAGES: Record<string, string> = {
  bad_request: 'The request was missing something. Please reload the page and try again.',
  invalid_email: 'Enter a valid email address.',
  turnstile_failed: 'Please complete the verification and try again.',
  rate_limited: 'Too many requests. Please wait a minute and try again.',
  invalid_token: 'This reset link is invalid, expired or already used. Request a new one.',
  weak_password: `Use ${config.PASSWORD_MIN_LENGTH}–${config.PASSWORD_MAX_LENGTH} characters.`,
  password_mismatch: "The passwords don't match.",
};

const RESET_MINUTES = Math.round(config.RESET_TTL / 60_000);

export interface ForgotPageOptions {
  returnTo: string;
  turnstileSiteKey: string;
  /** No-JS fallback after a successful post: show the confirmation instead of the form. */
  sent?: boolean;
  error?: string;
}

export function forgotPage(opts: ForgotPageOptions): Html {
  const message = opts.error ? PASSWORD_PAGE_MESSAGES[opts.error] : undefined;
  const rt = encodeURIComponent(opts.returnTo);
  return html`<h1>Reset your password</h1>
<form id="forgot-form" method="post" action="/password/forgot" novalidate ${opts.sent ? html`hidden` : ''}>
  <input type="hidden" name="return_to" value="${opts.returnTo}">
  ${errorBox(message)}
  <p class="muted">Enter an email address on your account and we'll send you a link to choose a new password.</p>
  <label for="email">Email</label>
  <input id="email" name="email" type="email" required autocomplete="email" spellcheck="false" autofocus>
  <div id="forgot-turnstile" class="turnstile" data-sitekey="${opts.turnstileSiteKey}"></div>
  <button type="submit">Send reset link</button>
</form>
<div id="forgot-sent" class="notice" role="status" tabindex="-1" ${opts.sent ? '' : html`hidden`}>
  If an account uses that address, we've sent it a link to reset your password.
  The link expires in ${RESET_MINUTES} minutes. Check your spam folder if it doesn't arrive.
</div>
<p class="foot muted"><a href="/login?return_to=${rt}">Back to sign in</a></p>`;
}

export interface ResetPageOptions {
  /** The raw token from the email link; rendered only into the hidden field. */
  token: string;
  /** The token is unusable: show the error and a link to request a new one, no form. */
  invalid?: boolean;
  error?: string;
}

export function resetPage(opts: ResetPageOptions): Html {
  if (opts.invalid) {
    return html`<h1>Choose a new password</h1>
${errorBox(PASSWORD_PAGE_MESSAGES.invalid_token)}
<p class="foot muted"><a href="/password/forgot">Request a new link</a> · <a href="/login">Sign in</a></p>`;
  }
  const message = opts.error ? PASSWORD_PAGE_MESSAGES[opts.error] : undefined;
  return html`<h1>Choose a new password</h1>
<form id="reset-form" method="post" action="/password/reset" novalidate>
  <input type="hidden" name="token" value="${opts.token}">
  ${errorBox(message)}
  <label for="new-password">New password</label>
  <input id="new-password" name="password" type="password" required autocomplete="new-password"
    minlength="${config.PASSWORD_MIN_LENGTH}" maxlength="${config.PASSWORD_MAX_LENGTH}"
    aria-describedby="password-help" autofocus>
  <p id="password-help" class="muted">At least ${config.PASSWORD_MIN_LENGTH} characters. You'll be signed out everywhere.</p>
  <label for="confirm-password">Confirm password</label>
  <input id="confirm-password" name="confirm" type="password" required autocomplete="new-password">
  <button type="submit">Set password</button>
</form>
<p class="foot muted"><a href="/login">Back to sign in</a></p>`;
}

export const FORGOT_JS = defineAsset('password-forgot.js', String.raw`(function () {
  'use strict';
  var form = document.getElementById('forgot-form');
  var sent = document.getElementById('forgot-sent');
  if (!form || !sent || !window.bcn) return;
  var widget = document.getElementById('forgot-turnstile');
  bcn.turnstile.render(widget);

  form.addEventListener('submit', async function (event) {
    event.preventDefault();
    var data = bcn.formFields(form);
    data.turnstile = bcn.turnstile.token(widget);
    var res = await bcn.submit(form, '/password/forgot', data);
    bcn.turnstile.reset(widget);
    if (!res.ok) return;
    form.hidden = true;
    sent.hidden = false;
    sent.focus();
  });
})();
`);

export const RESET_JS = defineAsset('password-reset.js', String.raw`(function () {
  'use strict';
  var form = document.getElementById('reset-form');
  if (!form || !window.bcn) return;

  form.addEventListener('submit', async function (event) {
    event.preventDefault();
    var data = bcn.formFields(form);
    if (data.password !== data.confirm) {
      bcn.showError(form, 'The passwords don\'t match.');
      return;
    }
    var res = await bcn.submit(form, '/password/reset', { token: data.token, password: data.password });
    if (res.ok) window.location.assign(res.redirect);
  });
})();
`);
