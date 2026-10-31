/**
 * Passkey UI (design §6.3): the /login slot (button + conditional-UI
 * autofill), the signup step-3 slot, and the profile page's passkey section.
 *
 * Client JS is hand-written (no @simplewebauthn/browser): webauthn.js defines
 * `window.bcnPasskey` with base64url <-> ArrayBuffer conversion, `create`
 * and `get` wrappers that take the server's JSON options and return JSON
 * responses, and feature checks. Like app.js it must stay free of backticks
 * and dollar-brace sequences.
 */

import { html } from 'hono/html';
import { config } from '../config';
import type { PasskeyInfo } from '../do/user/passkeys';
import { defineAsset } from './assets';
import { errorBox, type Html } from './layout';

/** window.bcnPasskey; load before any passkey page script. */
export const WEBAUTHN_JS = defineAsset('webauthn.js', String.raw`(function () {
  'use strict';

  function toBuffer(s) {
    var b64 = s.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4) b64 += '=';
    var bin = atob(b64);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }

  function toB64url(buf) {
    var bytes = new Uint8Array(buf);
    var bin = '';
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function descriptors(list) {
    return (list || []).map(function (d) {
      var out = { type: d.type || 'public-key', id: toBuffer(d.id) };
      if (d.transports) out.transports = d.transports;
      return out;
    });
  }

  function supported() {
    return !!(window.PublicKeyCredential && navigator.credentials && navigator.credentials.create);
  }

  async function conditionalAvailable() {
    if (!supported() || typeof PublicKeyCredential.isConditionalMediationAvailable !== 'function') return false;
    try { return await PublicKeyCredential.isConditionalMediationAvailable(); } catch (e) { return false; }
  }

  async function create(options) {
    var publicKey = Object.assign({}, options, {
      challenge: toBuffer(options.challenge),
      user: Object.assign({}, options.user, { id: toBuffer(options.user.id) }),
      excludeCredentials: descriptors(options.excludeCredentials),
    });
    var cred = await navigator.credentials.create({ publicKey: publicKey });
    var r = cred.response;
    return {
      id: cred.id,
      rawId: toB64url(cred.rawId),
      type: cred.type,
      authenticatorAttachment: cred.authenticatorAttachment || undefined,
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
      response: {
        clientDataJSON: toB64url(r.clientDataJSON),
        attestationObject: toB64url(r.attestationObject),
        transports: typeof r.getTransports === 'function' ? r.getTransports() : [],
      },
    };
  }

  /** opts: { mediation: 'conditional' | undefined, signal: AbortSignal | undefined } */
  async function get(options, opts) {
    opts = opts || {};
    var publicKey = Object.assign({}, options, {
      challenge: toBuffer(options.challenge),
      allowCredentials: descriptors(options.allowCredentials),
    });
    var request = { publicKey: publicKey };
    if (opts.mediation) request.mediation = opts.mediation;
    if (opts.signal) request.signal = opts.signal;
    var cred = await navigator.credentials.get(request);
    var r = cred.response;
    return {
      id: cred.id,
      rawId: toB64url(cred.rawId),
      type: cred.type,
      authenticatorAttachment: cred.authenticatorAttachment || undefined,
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
      response: {
        clientDataJSON: toB64url(r.clientDataJSON),
        authenticatorData: toB64url(r.authenticatorData),
        signature: toB64url(r.signature),
        userHandle: r.userHandle ? toB64url(r.userHandle) : undefined,
      },
    };
  }

  /** User cancelled, timed out, or we aborted: not worth an error message. */
  function isCancel(err) {
    return !!err && (err.name === 'NotAllowedError' || err.name === 'AbortError');
  }

  window.bcnPasskey = {
    supported: supported,
    conditionalAvailable: conditionalAvailable,
    create: create,
    get: get,
    isCancel: isCancel,
    toBuffer: toBuffer,
    toB64url: toB64url,
  };
})();
`);

// --- /login ------------------------------------------------------------------

/** The /login passkey slot: a button, shown by passkey-login.js when WebAuthn is available. */
export function passkeyLoginSlot(): Html {
  return html`<div id="passkey-login" hidden>
  <button type="button" class="secondary" data-action="passkey-login">Sign in with a passkey</button>
</div>`;
}

/**
 * Runs the button (modal) and conditional-UI (autofill on #identifier)
 * ceremonies. Errors go to #login-form's error box; return_to comes from its
 * hidden input.
 */
export const PASSKEY_LOGIN_JS = defineAsset('passkey-login.js', String.raw`(function () {
  'use strict';
  var box = document.getElementById('passkey-login');
  var form = document.getElementById('login-form');
  if (!box || !form || !window.bcn || !window.bcnPasskey || !bcnPasskey.supported()) return;
  var button = box.querySelector('[data-action=passkey-login]');
  var pending = null;
  box.hidden = false;

  function returnTo() {
    var input = form.querySelector('input[name=return_to]');
    return input ? input.value : '';
  }

  async function finish(credential) {
    bcn.setBusy(form, true);
    button.disabled = true;
    try {
      var res = await bcn.postJson('/passkey/login/verify', { credential: credential, return_to: returnTo() });
      if (res.ok) { window.location.assign(res.redirect); return true; }
      bcn.showError(form, res.message);
      return false;
    } finally {
      bcn.setBusy(form, false);
      button.disabled = false;
    }
  }

  async function ceremony(conditional) {
    var options = await bcn.postJson('/passkey/login/options', {});
    if (!options.ok) { if (!conditional) bcn.showError(form, options.message); return; }
    var controller = new AbortController();
    pending = controller;
    var credential;
    try {
      credential = await bcnPasskey.get(options.options, {
        mediation: conditional ? 'conditional' : undefined,
        signal: controller.signal,
      });
    } catch (err) {
      var aborted = pending !== controller;
      if (!aborted) pending = null;
      if (!bcnPasskey.isCancel(err)) bcn.showError(form, 'Your browser couldn\'t use a passkey. Try again or use your password.');
      // Re-arm autofill after a cancelled button ceremony (not when the button aborted autofill).
      if (!conditional && !aborted) startConditional();
      return;
    }
    if (pending === controller) pending = null;
    var ok = await finish(credential);
    if (!ok) startConditional();
  }

  async function startConditional() {
    if (!(await bcnPasskey.conditionalAvailable())) return;
    ceremony(true);
  }

  button.addEventListener('click', function () {
    bcn.showError(form, '');
    if (pending) pending.abort();
    pending = null;
    ceremony(false).catch(function () {});
  });

  startConditional().catch(function () {});
})();
`);

// --- /signup -------------------------------------------------------------------

/** The signup step-3 slot: "Use a passkey instead" (shown by passkey-signup.js when supported). */
export function passkeySignupSlot(): Html {
  return html`<div id="passkey-signup" hidden>
  <div class="divider">or</div>
  <button type="button" class="secondary" data-action="passkey-signup">Use a passkey instead</button>
  <p class="muted">Sign in with your fingerprint, face or screen lock instead of a password.</p>
</div>`;
}

/** Registers a passkey for the verified signup and finishes via POST /signup/complete. */
export const PASSKEY_SIGNUP_JS = defineAsset('passkey-signup.js', String.raw`(function () {
  'use strict';
  var box = document.getElementById('passkey-signup');
  var complete = document.getElementById('signup-complete');
  if (!box || !complete || !window.bcn || !window.bcnPasskey || !bcnPasskey.supported()) return;
  var button = box.querySelector('[data-action=passkey-signup]');
  box.hidden = false;

  button.addEventListener('click', async function () {
    var signupId = complete.getAttribute('data-signup-id');
    if (!signupId) return;
    bcn.showError(complete, '');
    bcn.setBusy(complete, true);
    try {
      var options = await bcn.postJson('/passkey/register/options', { signupId: signupId });
      if (!options.ok) { bcn.showError(complete, options.message); return; }
      var credential;
      try {
        credential = await bcnPasskey.create(options.options);
      } catch (err) {
        if (!bcnPasskey.isCancel(err)) bcn.showError(complete, 'Your browser couldn\'t create a passkey. Try again or choose a password.');
        return;
      }
      var fields = bcn.formFields(complete);
      var res = await bcn.postJson('/signup/complete', {
        signupId: signupId, credential: credential, return_to: fields.return_to,
      });
      if (res.ok) { window.location.assign(res.redirect); return; }
      bcn.showError(complete, res.message);
    } finally {
      bcn.setBusy(complete, false);
    }
  });
})();
`);

// --- profile ---------------------------------------------------------------------

export interface PasskeySectionOptions {
  /** Where to send the user when a change needs a fresh login (the 401 body's reauthUrl otherwise). */
  reauthUrl?: string;
}

function formatDate(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}

/**
 * The profile page's passkey section: list (label, added, last used) with
 * rename/delete, and "Add a passkey". Render it with PASSKEY_SECTION_SCRIPTS
 * in the page's scripts. Changes need a recent login (REAUTH_WINDOW); on
 * reauth_required the script shows the message and a sign-in link.
 */
export function passkeySection(passkeys: PasskeyInfo[], opts: PasskeySectionOptions = {}): Html {
  return html`<section id="passkeys" class="passkeys" aria-labelledby="passkeys-title"
  data-max="${config.MAX_PASSKEYS_PER_ACCOUNT}" ${opts.reauthUrl ? html`data-reauth-url="${opts.reauthUrl}"` : ''}>
  <h3 id="passkeys-title">Passkeys</h3>
  ${errorBox()}
  <p class="muted">Sign in with your fingerprint, face, screen lock or security key.</p>
  ${passkeys.length === 0 ? html`<p class="muted" data-empty>You don't have any passkeys yet.</p>` : ''}
  <ul class="passkey-list">
    ${passkeys.map((p) => html`<li data-passkey-id="${p.id}" data-label="${p.label}">
      <strong>${p.label}</strong>
      <span class="muted">Added <time datetime="${new Date(p.createdAt).toISOString()}">${formatDate(p.createdAt)}</time>
        · ${p.lastUsedAt
          ? html`Last used <time datetime="${new Date(p.lastUsedAt).toISOString()}">${formatDate(p.lastUsedAt)}</time>`
          : 'Never used'}${p.backedUp ? ' · Synced' : ''}</span>
      <span class="actions">
        <button type="button" class="secondary" data-action="rename">Rename</button>
        <button type="button" class="secondary" data-action="delete">Delete</button>
      </span>
    </li>`)}
  </ul>
  <button type="button" data-action="add" hidden>Add a passkey</button>
  <p class="muted" data-unsupported hidden>This browser doesn't support passkeys.</p>
</section>`;
}

/** Add / rename / delete for passkeySection; reloads the page after each change. */
export const PASSKEY_MANAGE_JS = defineAsset('passkey-manage.js', String.raw`(function () {
  'use strict';
  var section = document.getElementById('passkeys');
  if (!section || !window.bcn || !window.bcnPasskey) return;
  var add = section.querySelector('[data-action=add]');

  function handle(res) {
    // Signed out meanwhile: reloading the page refreshes the session or goes to /login.
    if (res.ok || res.error === 'unauthorized') { window.location.reload(); return; }
    if (res.error === 'reauth_required') {
      var url = section.getAttribute('data-reauth-url') || res.reauthUrl;
      bcn.showError(section, res.message);
      if (url) {
        var box = section.querySelector('[data-error]');
        var link = document.createElement('a');
        link.href = url;
        link.textContent = ' Sign in again';
        box.appendChild(link);
      }
      return;
    }
    bcn.showError(section, res.message);
  }

  async function run(fn) {
    bcn.showError(section, '');
    bcn.setBusy(section, true);
    try { await fn(); } finally { bcn.setBusy(section, false); }
  }

  if (bcnPasskey.supported()) add.hidden = false;
  else section.querySelector('[data-unsupported]').hidden = false;

  add.addEventListener('click', function () {
    run(async function () {
      var options = await bcn.postJson('/passkey/register/options', {});
      if (!options.ok) { handle(options); return; }
      var credential;
      try {
        credential = await bcnPasskey.create(options.options);
      } catch (err) {
        if (err && err.name === 'InvalidStateError') bcn.showError(section, 'That device already has a passkey for this account.');
        else if (!bcnPasskey.isCancel(err)) bcn.showError(section, 'Your browser couldn\'t create a passkey. Please try again.');
        return;
      }
      handle(await bcn.postJson('/passkey/register/verify', { credential: credential }));
    });
  });

  section.querySelectorAll('[data-passkey-id]').forEach(function (item) {
    var id = item.getAttribute('data-passkey-id');
    var path = '/passkey/credentials/' + encodeURIComponent(id);
    item.querySelector('[data-action=rename]').addEventListener('click', function () {
      var label = window.prompt('Name this passkey', item.getAttribute('data-label') || '');
      if (label === null) return;
      run(async function () { handle(await bcn.postJson(path + '/rename', { label: label })); });
    });
    item.querySelector('[data-action=delete]').addEventListener('click', function () {
      if (!window.confirm('Delete the passkey "' + (item.getAttribute('data-label') || '') + '"? You won\'t be able to sign in with it anymore.')) return;
      run(async function () { handle(await bcn.postJson(path + '/delete', {})); });
    });
  });
})();
`);

/** Scripts the profile page must load (in this order) when it renders passkeySection. */
export const PASSKEY_SECTION_SCRIPTS: readonly string[] = [WEBAUTHN_JS, PASSKEY_MANAGE_JS];
