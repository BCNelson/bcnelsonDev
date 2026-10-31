/**
 * Shared client script (/assets/app.js), loaded on every page before the page
 * script. Defines `window.bcn`:
 *
 *   bcn.formFields(form)          → { name: value } of the form's string fields
 *   bcn.postJson(url, data)       → parsed JSON, always an object with `ok`
 *                                   (network/server failures become ok:false + message)
 *   bcn.submit(form, url, data)   → postJson with the form busy, errors shown in its [data-error]
 *   bcn.showError(form, message)  → fill/clear the form's [data-error] box
 *   bcn.setBusy(form, busy)
 *   bcn.turnstile.render(el) / .reset(el) / .token(el)
 *                                 → explicit Turnstile widget in `el` (site key from data-sitekey)
 *
 * Plain ES2017, no modules or build step. Keep it free of backticks and
 * dollar-brace sequences: it lives in a TS template literal.
 */

import { defineAsset } from '../assets';

const SOURCE = String.raw`(function () {
  'use strict';

  var NETWORK = 'Network error. Check your connection and try again.';
  var SERVER = 'Something went wrong. Please try again.';

  function formFields(form) {
    var out = {};
    new FormData(form).forEach(function (value, key) {
      if (typeof value === 'string') out[key] = value;
    });
    return out;
  }

  async function postJson(url, data) {
    var res;
    try {
      res = await fetch(url, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify(data || {}),
      });
    } catch (e) {
      return { ok: false, error: 'network', message: NETWORK };
    }
    var body = null;
    try { body = await res.json(); } catch (e) { body = null; }
    if (!body || typeof body !== 'object') body = { ok: false, error: 'server', message: SERVER };
    if (!res.ok) body.ok = false;
    if (body.ok === false && !body.message) body.message = SERVER;
    body.status = res.status;
    return body;
  }

  function showError(form, message) {
    var box = form && form.querySelector('[data-error]');
    if (!box) return;
    box.textContent = message || '';
    box.hidden = !message;
    if (message) box.focus();
  }

  function setBusy(form, busy) {
    form.setAttribute('aria-busy', busy ? 'true' : 'false');
    form.querySelectorAll('button').forEach(function (b) { b.disabled = !!busy; });
  }

  async function submit(form, url, data) {
    showError(form, '');
    setBusy(form, true);
    try {
      var res = await postJson(url, data);
      if (!res.ok) showError(form, res.message);
      return res;
    } finally {
      setBusy(form, false);
    }
  }

  var widgets = new WeakMap();
  var turnstile = {
    render: function (el) {
      if (!el || !window.turnstile) return;
      var key = el.getAttribute('data-sitekey');
      if (!key) return;
      el.hidden = false;
      if (widgets.has(el)) { window.turnstile.reset(widgets.get(el)); return; }
      widgets.set(el, window.turnstile.render(el, { sitekey: key, theme: 'auto', 'response-field': false }));
    },
    reset: function (el) {
      if (el && widgets.has(el) && window.turnstile) window.turnstile.reset(widgets.get(el));
    },
    token: function (el) {
      if (!el || !widgets.has(el) || !window.turnstile) return '';
      return window.turnstile.getResponse(widgets.get(el)) || '';
    },
  };

  window.bcn = {
    formFields: formFields,
    postJson: postJson,
    submit: submit,
    showError: showError,
    setBusy: setBusy,
    turnstile: turnstile,
  };
})();
`;

/** Path of the shared client script. */
export const APP_JS = defineAsset('app.js', SOURCE);
