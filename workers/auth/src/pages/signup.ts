/**
 * GET /signup page, three steps driven by signup.js (needs JS):
 *   1. username + email + Turnstile → POST /signup/start
 *   2. emailed code                 → POST /signup/verify
 *   3. password (or passkey slot)   → POST /signup/complete
 * Going back to step 1 with the same username and email re-sends a code.
 */

import { html } from 'hono/html';
import { config } from '../config';
import { defineAsset } from './assets';
import { errorBox, type Html } from './layout';

export interface SignupPageOptions {
  returnTo: string;
  turnstileSiteKey: string;
  /**
   * `passkey`: a "Create a passkey instead" control on step 3. Its script reads
   * the signupId from #signup-complete's data-signup-id (set by signup.js
   * after verification) and finishes via POST /signup/complete.
   */
  /** `social`: provider links (routes/oauth.ts socialLoginSlot), shown with step 1. */
  slots?: { passkey?: Html; social?: Html };
  scripts?: string[];
}

export function signupPage(opts: SignupPageOptions): Html {
  const rt = encodeURIComponent(opts.returnTo);
  return html`<h1>Create an account</h1>
<noscript><p class="error">Creating an account needs JavaScript.</p></noscript>
<p class="steps" id="signup-steps" aria-live="polite">Step 1 of 3</p>

<form id="signup-start" novalidate>
  ${errorBox()}
  <label for="username">Username</label>
  <input id="username" name="username" type="text" required minlength="3" maxlength="30"
    pattern="[A-Za-z0-9][A-Za-z0-9_\\-]{2,29}" autocomplete="username"
    autocapitalize="none" autocorrect="off" spellcheck="false" aria-describedby="username-help" autofocus>
  <p id="username-help" class="muted">3–30 characters: letters, numbers, - and _.</p>
  <label for="email">Email</label>
  <input id="email" name="email" type="email" required autocomplete="email" spellcheck="false">
  <div id="signup-turnstile" class="turnstile" data-sitekey="${opts.turnstileSiteKey}"></div>
  <button type="submit">Send code</button>
  <!-- slot: social signup (phase 7) -->
  ${opts.slots?.social ? html`<div class="divider">or</div><div data-slot="social-signup">${opts.slots.social}</div>` : ''}
</form>

<form id="signup-verify" novalidate hidden>
  ${errorBox()}
  <p>We sent a ${config.CODE_LENGTH}-digit code to <strong id="signup-email"></strong>.
    If that address already has an account, we sent a sign-in link instead.</p>
  <label for="code">Verification code</label>
  <input id="code" name="code" type="text" required inputmode="numeric" autocomplete="one-time-code"
    pattern="[0-9]*" maxlength="${config.CODE_LENGTH}">
  <button type="submit">Verify</button>
  <button type="button" class="secondary" data-action="restart">Send a new code</button>
</form>

<form id="signup-complete" novalidate hidden>
  ${errorBox()}
  <input type="hidden" name="return_to" value="${opts.returnTo}">
  <input type="text" name="username" autocomplete="username" hidden>
  <label for="new-password">Password</label>
  <input id="new-password" name="password" type="password" required autocomplete="new-password"
    minlength="${config.PASSWORD_MIN_LENGTH}" maxlength="${config.PASSWORD_MAX_LENGTH}" aria-describedby="password-help">
  <p id="password-help" class="muted">At least ${config.PASSWORD_MIN_LENGTH} characters.</p>
  <label for="confirm-password">Confirm password</label>
  <input id="confirm-password" name="confirm" type="password" required autocomplete="new-password">
  <button type="submit">Create account</button>
  <!-- slot: passkey signup (phase 3) -->
  <div data-slot="passkey-signup">${opts.slots?.passkey ?? ''}</div>
</form>

<p class="foot muted">Already have an account? <a href="/login?return_to=${rt}">Sign in</a></p>`;
}

export const SIGNUP_JS = defineAsset('signup.js', String.raw`(function () {
  'use strict';
  var start = document.getElementById('signup-start');
  var verify = document.getElementById('signup-verify');
  var complete = document.getElementById('signup-complete');
  if (!start || !verify || !complete || !window.bcn) return;
  var steps = document.getElementById('signup-steps');
  var widget = document.getElementById('signup-turnstile');
  var forms = [start, verify, complete];
  var signupId = null;

  bcn.turnstile.render(widget);

  function show(form) {
    forms.forEach(function (f) { f.hidden = f !== form; });
    steps.textContent = 'Step ' + (forms.indexOf(form) + 1) + ' of 3';
    var first = form.querySelector('input:not([type=hidden]):not([hidden])');
    if (first) first.focus();
  }

  start.addEventListener('submit', async function (event) {
    event.preventDefault();
    var data = bcn.formFields(start);
    data.turnstile = bcn.turnstile.token(widget);
    var res = await bcn.submit(start, '/signup/start', data);
    bcn.turnstile.reset(widget);
    if (!res.ok) return;
    signupId = res.signupId;
    document.getElementById('signup-email').textContent = data.email;
    complete.querySelector('input[name=username]').value = data.username;
    verify.reset();
    show(verify);
  });

  verify.addEventListener('submit', async function (event) {
    event.preventDefault();
    var code = (bcn.formFields(verify).code || '').replace(/\s+/g, '');
    var res = await bcn.submit(verify, '/signup/verify', { signupId: signupId, code: code });
    if (!res.ok) return;
    complete.setAttribute('data-signup-id', signupId);
    show(complete);
  });

  verify.querySelector('[data-action=restart]').addEventListener('click', function () {
    bcn.showError(start, '');
    show(start);
  });

  complete.addEventListener('submit', async function (event) {
    event.preventDefault();
    var data = bcn.formFields(complete);
    if (data.password !== data.confirm) {
      bcn.showError(complete, 'The passwords don\'t match.');
      return;
    }
    var res = await bcn.submit(complete, '/signup/complete', {
      signupId: signupId, password: data.password, return_to: data.return_to,
    });
    if (res.ok) window.location.assign(res.redirect);
  });
})();
`);
