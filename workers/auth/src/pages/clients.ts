/**
 * GET /admin/clients: the OAuth/OIDC client registry (design §9). Server-
 * rendered list with an edit form per client and a create form; clients.js
 * posts each form to its data-api URL and shows a new secret once.
 */

import { html } from 'hono/html';
import { config } from '../config';
import type { OAuthClientInfo } from '../oidc/clients';
import { ADMIN_STYLES } from './admin';
import { defineAsset } from './assets';
import { errorBox, type Html } from './layout';

export const CLIENTS_STYLES = `${ADMIN_STYLES}
.client{margin:16px 0;padding:12px 0;border-top:1px solid var(--border)}
.client h2{margin:0 0 4px;font-size:1.1rem}
.client code,.secret code{word-break:break-all}
textarea{width:100%;min-height:64px;padding:8px 12px;font:inherit;color:var(--fg);background:var(--bg);border:1px solid var(--border);border-radius:8px}
.checks label{display:inline-flex;gap:6px;align-items:center;margin:4px 16px 4px 0;font-weight:400}
.checks input{width:auto}
.client .actions{display:flex;flex-wrap:wrap;gap:8px}
.client .actions button,.client form>button,.create>button{width:auto}
.secret{margin:12px 0;padding:10px 12px;border-radius:8px;border:1px solid var(--accent)}
`;

function scopeChecks(selected: readonly string[]): Html {
  return html`<div class="checks">${config.OIDC_SCOPES.map((s) => html`<label><input type="checkbox" name="allowed_scopes" value="${s}" ${selected.includes(s) ? html`checked` : ''}${s === 'openid' ? html` disabled` : ''}>${s}</label>`)}</div>`;
}

function fields(c: OAuthClientInfo | null): Html {
  const id = c?.clientId ?? 'new';
  return html`<label for="name-${id}">Name</label>
<input id="name-${id}" name="name" required value="${c?.name ?? ''}" maxlength="${config.OIDC_CLIENT_NAME_MAX_LENGTH}">
<label for="ru-${id}">Redirect URIs (one per line, exact match)</label>
<textarea id="ru-${id}" name="redirect_uris" required spellcheck="false">${(c?.redirectUris ?? []).join('\n')}</textarea>
<label for="plru-${id}">Post-logout redirect URIs</label>
<textarea id="plru-${id}" name="post_logout_redirect_uris" spellcheck="false">${(c?.postLogoutRedirectUris ?? []).join('\n')}</textarea>
<label>Allowed scopes</label>
${scopeChecks(c?.allowedScopes ?? ['openid', 'profile', 'email'])}
<div class="checks"><label><input type="checkbox" name="first_party" ${c?.firstParty ? html`checked` : ''}>First party (this site's own apps: may redirect to the site, skips the consent screen)</label></div>`;
}

function clientBlock(c: OAuthClientInfo): Html {
  const api = `/api/admin/clients/${encodeURIComponent(c.clientId)}`;
  return html`<section class="client">
  <h2>${c.name} ${c.disabledAt !== null ? html`<span class="pill off">disabled</span>` : ''}</h2>
  <p class="muted"><code>${c.clientId}</code> · ${c.confidential ? 'confidential' : 'public (PKCE only)'}${c.firstParty ? ' · first party' : ''} · created ${new Date(c.createdAt).toISOString().slice(0, 10)}</p>
  <details>
    <summary>Edit</summary>
    <form data-api="${api}" novalidate>
      ${errorBox()}
      ${fields(c)}
      <button type="submit">Save</button>
    </form>
  </details>
  <div class="actions">
    ${c.confidential ? html`<form data-api="${api}/rotate-secret" data-confirm="Rotate the secret for ${c.name}? The old one stops working at once." novalidate>${errorBox()}<button type="submit" class="secondary">Rotate secret</button></form>` : ''}
    <form data-api="${api}/disable" ${c.disabledAt === null ? html`data-confirm="Disable ${c.name}? Its sign-ins and tokens stop working."` : ''} novalidate>
      ${errorBox()}
      <input type="hidden" name="disabled" value="${c.disabledAt === null ? 'true' : 'false'}">
      <button type="submit" class="secondary">${c.disabledAt === null ? 'Disable' : 'Enable'}</button>
    </form>
  </div>
</section>`;
}

export function clientsPage(opts: { clients: OAuthClientInfo[]; issuer: string }): Html {
  return html`<h1>OAuth clients</h1>
<p class="muted"><a href="/admin">← Users</a> · Discovery: <code>${opts.issuer}/.well-known/openid-configuration</code></p>
<div class="secret" data-secret hidden></div>
${opts.clients.length === 0 ? html`<p class="muted">No clients registered yet.</p>` : opts.clients.map(clientBlock)}
<section class="client create">
  <h2>Register a client</h2>
  <form data-api="/api/admin/clients" novalidate>
    ${errorBox()}
    <label for="cid-new">Client id (optional; generated when empty)</label>
    <input id="cid-new" name="client_id" autocomplete="off" spellcheck="false">
    ${fields(null)}
    <div class="checks"><label><input type="checkbox" name="confidential" checked>Confidential (server-side app with a client secret)</label></div>
    <button type="submit">Register</button>
  </form>
</section>`;
}

/**
 * Posts each [data-api] form as JSON; shows a returned client_secret once,
 * otherwise reloads. Plain ES2017; no backticks or dollar-brace.
 */
export const CLIENTS_JS = defineAsset('clients.js', String.raw`(function () {
  'use strict';
  if (!window.bcn) return;
  var secretBox = document.querySelector('[data-secret]');

  function showSecret(res) {
    secretBox.textContent = '';
    var p = document.createElement('p');
    p.textContent = 'Client secret for ' + res.client.clientId + ' (copy it now; it will not be shown again):';
    var code = document.createElement('code');
    code.textContent = res.client_secret;
    var link = document.createElement('a');
    link.href = '/admin/clients';
    link.textContent = 'Done';
    secretBox.appendChild(p);
    secretBox.appendChild(code);
    secretBox.appendChild(document.createElement('br'));
    secretBox.appendChild(link);
    secretBox.hidden = false;
    secretBox.scrollIntoView({ block: 'start' });
  }

  document.querySelectorAll('form[data-api]').forEach(function (form) {
    form.addEventListener('submit', async function (event) {
      event.preventDefault();
      var question = form.getAttribute('data-confirm');
      if (question && !window.confirm(question)) return;
      var data = bcn.formFields(form);
      var scopes = form.querySelectorAll('input[name="allowed_scopes"]');
      if (scopes.length) {
        data.allowed_scopes = ['openid'];
        scopes.forEach(function (i) { if (i.checked && i.value !== 'openid') data.allowed_scopes.push(i.value); });
      }
      ['first_party', 'confidential'].forEach(function (name) {
        if (form.querySelector('input[name="' + name + '"]')) data[name] = name in data;
      });
      var res = await bcn.submit(form, form.getAttribute('data-api'), data);
      if (!res.ok) {
        if (res.reauthUrl) {
          var box = form.querySelector('[data-error]');
          var a = document.createElement('a');
          a.href = '/login?reauth=1&return_to=' + encodeURIComponent(window.location.href);
          a.textContent = ' Sign in again';
          box.appendChild(a);
        }
        return;
      }
      if (res.client_secret) showSecret(res);
      else window.location.reload();
    });
  });
})();
`);
