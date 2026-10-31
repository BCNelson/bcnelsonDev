/**
 * GET /admin page (design §8): the user directory with search and
 * pagination (server-rendered, plain GET links, so it works without JS), and
 * a per-user detail panel filled by admin.js from /api/admin/users/:id with
 * role toggles, disable/enable, revoke sessions, directory rebuild and the
 * recent audit log.
 */

import { html } from 'hono/html';
import { config } from '../config';
import type { DirectoryEntry } from '../do/index/directory';
import { defineAsset } from './assets';
import { errorBox, type Html } from './layout';

export interface AdminPageOptions {
  users: DirectoryEntry[];
  q: string;
  /** Cursor for this page ('' on the first). */
  cursor: string;
  nextCursor: string | null;
  /** The signed-in admin, so the page can mark "you". */
  actorUserId: string;
}

export const ADMIN_STYLES = `
main.card{max-width:980px}
header.site{max-width:980px}
.admin-search{display:flex;gap:8px;align-items:flex-end}
.admin-search .grow{flex:1}
.empty{margin-top:16px}
.admin-search button{width:auto;margin-top:0}
table.users{width:100%;border-collapse:collapse;margin:16px 0;font-size:.92rem}
table.users th,table.users td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--border);vertical-align:top}
table.users th{color:var(--muted);font-weight:600}
table.users button{width:auto;margin:0;padding:2px 10px;font-size:.875rem}
.pill{display:inline-block;margin:0 4px 2px 0;padding:0 8px;border:1px solid var(--border);border-radius:999px;font-size:.8rem}
.pill.off{color:var(--error-fg);border-color:var(--error-fg)}
.pager{display:flex;gap:16px;justify-content:space-between}
.detail{margin-top:24px;padding-top:16px;border-top:1px solid var(--border)}
.detail h2{margin:0 0 8px;font-size:1.2rem}
.detail h3{margin:20px 0 6px;font-size:1rem}
.detail dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;margin:0}
.detail dt{color:var(--muted)}
.detail dd{margin:0;word-break:break-all}
.detail .actions{display:flex;flex-wrap:wrap;gap:8px}
.detail .actions button{width:auto;margin-top:8px}
.roles label{display:inline-flex;gap:6px;align-items:center;margin:4px 16px 4px 0;font-weight:400}
.roles input{width:auto}
ul.log{list-style:none;margin:0;padding:0;font-size:.85rem}
ul.log li{padding:4px 0;border-bottom:1px solid var(--border);word-break:break-all}
.notice{margin:12px 0;padding:10px 12px;border-radius:8px;border:1px solid var(--border)}
@media (max-width:700px){table.users .wide{display:none}}
`;

function day(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}

function pageLink(q: string, cursor: string): string {
  const params = new URLSearchParams();
  if (q) params.set('q', q);
  if (cursor) params.set('cursor', cursor);
  const s = params.toString();
  return s ? `/admin?${s}` : '/admin';
}

function userRow(u: DirectoryEntry, actorUserId: string): Html {
  return html`<tr>
  <td><button type="button" class="secondary" data-user-id="${u.userId}">${u.username}</button>${u.userId === actorUserId ? html` <span class="muted">(you)</span>` : ''}</td>
  <td>${u.primaryEmail ?? ''}</td>
  <td>${u.roles.map((r) => html`<span class="pill">${r}</span>`)}${u.disabledAt !== null ? html`<span class="pill off">disabled</span>` : ''}</td>
  <td class="wide">${day(u.createdAt)}</td>
</tr>`;
}

export function adminPage(opts: AdminPageOptions): Html {
  return html`<h1>Admin</h1>
<p class="muted"><a href="/admin/clients">OAuth clients</a></p>
<form class="admin-search" method="get" action="/admin" role="search">
  <div class="grow">
    <label for="admin-q">Search username or email (prefix)</label>
    <input id="admin-q" name="q" type="search" value="${opts.q}" autocomplete="off" spellcheck="false">
  </div>
  <button type="submit">Search</button>
</form>
<div id="admin-root" data-actor="${opts.actorUserId}" data-roles="${config.ROLES.join(',')}">
${opts.users.length === 0
    ? html`<p class="muted empty">No users found.</p>`
    : html`<table class="users">
<thead><tr><th>Username</th><th>Primary email</th><th>Roles</th><th class="wide">Created</th></tr></thead>
<tbody>${opts.users.map((u) => userRow(u, opts.actorUserId))}</tbody>
</table>`}
<div class="pager">
  <span>${opts.cursor ? html`<a href="${pageLink(opts.q, '')}">First page</a>` : ''}</span>
  <span>${opts.nextCursor ? html`<a href="${pageLink(opts.q, opts.nextCursor)}">Next page</a>` : ''}</span>
</div>
<form id="admin-backfill" class="actions" novalidate>
  ${errorBox()}
  <button type="submit" class="secondary">Backfill missing directory entries</button>
  <span class="muted" data-backfill-status></span>
</form>
<section id="admin-detail" class="detail" hidden aria-live="polite">
  <form id="admin-detail-form" novalidate>
    ${errorBox()}
    <div class="notice" data-notice hidden></div>
    <h2 data-field="username"></h2>
    <dl>
      <dt>User id</dt><dd data-field="userId"></dd>
      <dt>Name</dt><dd data-field="name"></dd>
      <dt>Emails</dt><dd data-field="emails"></dd>
      <dt>Created</dt><dd data-field="createdAt"></dd>
      <dt>Status</dt><dd data-field="status"></dd>
      <dt>Credentials</dt><dd data-field="credentials"></dd>
    </dl>
    <h3>Roles</h3>
    <div class="roles" data-roles-box></div>
    <div class="actions">
      <button type="button" data-action="roles">Save roles</button>
      <button type="button" class="secondary" data-action="disable">Disable account</button>
      <button type="button" class="secondary" data-action="revoke">Revoke all sessions</button>
      <button type="button" class="secondary" data-action="rebuild">Rebuild directory entry</button>
    </div>
    <h3>Active sessions</h3>
    <ul class="log" data-sessions></ul>
    <h3>Recent audit log</h3>
    <ul class="log" data-audit></ul>
  </form>
</section>
</div>`;
}

/**
 * Detail panel logic. Builds DOM with textContent only (no innerHTML).
 * Plain ES2017; no backticks or dollar-brace (it lives in a TS template literal).
 */
export const ADMIN_JS = defineAsset('admin.js', String.raw`(function () {
  'use strict';
  var root = document.getElementById('admin-root');
  if (!root || !window.bcn) return;
  var actor = root.getAttribute('data-actor');
  var allRoles = (root.getAttribute('data-roles') || '').split(',').filter(Boolean);
  var panel = document.getElementById('admin-detail');
  var form = document.getElementById('admin-detail-form');
  var current = null;

  async function getJson(url) {
    var res;
    try {
      res = await fetch(url, { credentials: 'same-origin', headers: { Accept: 'application/json' } });
    } catch (e) {
      return { ok: false, message: 'Network error. Check your connection and try again.' };
    }
    var body = null;
    try { body = await res.json(); } catch (e) { body = null; }
    if (!body || typeof body !== 'object') body = { ok: false, message: 'Something went wrong. Please try again.' };
    if (!res.ok) body.ok = false;
    return body;
  }

  function el(tag, text, cls) {
    var node = document.createElement(tag);
    if (text !== undefined && text !== null) node.textContent = String(text);
    if (cls) node.className = cls;
    return node;
  }

  function when(ms) { return ms ? new Date(ms).toLocaleString() : ''; }

  function field(name, value) {
    var node = form.querySelector('[data-field="' + name + '"]');
    if (node) node.textContent = value === null || value === undefined ? '' : String(value);
  }

  function notice(message) {
    var box = form.querySelector('[data-notice]');
    box.textContent = message || '';
    box.hidden = !message;
  }

  function reauth(res, target) {
    if (res.error === 'unauthorized') { window.location.reload(); return true; }
    if (res.error !== 'reauth_required') return false;
    bcn.showError(target, res.message);
    var box = target.querySelector('[data-error]');
    var button = el('button', 'Sign in again', 'secondary');
    button.type = 'button';
    button.addEventListener('click', function () {
      window.location.assign(res.reauthUrl || '/login?reauth=1');
    });
    box.appendChild(document.createElement('br'));
    box.appendChild(button);
    return true;
  }

  function render(data) {
    var u = data.user;
    current = u;
    field('username', u.username + (u.userId === actor ? ' (you)' : ''));
    field('userId', u.userId);
    field('name', u.name || '');
    field('emails', u.emails.join(', '));
    field('createdAt', when(u.createdAt));
    field('status', u.disabledAt ? 'Disabled since ' + when(u.disabledAt) : 'Active');
    field('credentials', u.credentials.map(function (c) { return c.type + (c.label ? ' (' + c.label + ')' : ''); }).join(', ') || 'none');

    var box = form.querySelector('[data-roles-box]');
    box.textContent = '';
    allRoles.forEach(function (role) {
      var label = el('label');
      var input = document.createElement('input');
      input.type = 'checkbox';
      input.name = 'role';
      input.value = role;
      input.checked = u.roles.indexOf(role) !== -1;
      label.appendChild(input);
      label.appendChild(document.createTextNode(role));
      box.appendChild(label);
    });

    form.querySelector('[data-action="disable"]').textContent = u.disabledAt ? 'Enable account' : 'Disable account';

    var sessions = form.querySelector('[data-sessions]');
    sessions.textContent = '';
    if (!u.sessions.length) sessions.appendChild(el('li', 'None', 'muted'));
    u.sessions.forEach(function (s) {
      sessions.appendChild(el('li', when(s.lastSeenAt) + ' · ' + s.amr.join(',') + ' · ' + (s.ip || '') + ' · ' + (s.userAgent || '')));
    });

    var audit = form.querySelector('[data-audit]');
    audit.textContent = '';
    if (!u.audit.length) audit.appendChild(el('li', 'None', 'muted'));
    u.audit.forEach(function (a) {
      audit.appendChild(el('li', when(a.at) + ' · ' + a.event + (a.detail === null ? '' : ' · ' + JSON.stringify(a.detail))));
    });
    panel.hidden = false;
  }

  async function load(userId) {
    bcn.showError(form, '');
    notice('');
    var res = await getJson('/api/admin/users/' + encodeURIComponent(userId));
    if (!res.ok) { panel.hidden = false; bcn.showError(form, res.message || 'Could not load the user.'); return; }
    render(res);
    panel.scrollIntoView({ block: 'start' });
  }

  async function act(path, data, done) {
    if (!current) return;
    notice('');
    var res = await bcn.submit(form, '/api/admin/users/' + encodeURIComponent(current.userId) + path, data);
    if (!res.ok) { reauth(res, form); return; }
    var id = current.userId;
    await load(id);
    notice(done(res));
  }

  root.addEventListener('click', function (event) {
    var target = event.target.closest('[data-user-id]');
    if (target) load(target.getAttribute('data-user-id'));
  });

  form.addEventListener('click', function (event) {
    var button = event.target.closest('[data-action]');
    if (!button || !current) return;
    var action = button.getAttribute('data-action');
    if (action === 'roles') {
      var roles = [];
      form.querySelectorAll('input[name="role"]').forEach(function (i) { if (i.checked) roles.push(i.value); });
      act('/roles', { roles: roles }, function (r) { return 'Roles saved: ' + (r.roles.join(', ') || 'none') + '. They apply on the next token refresh.'; });
    } else if (action === 'disable') {
      var disable = !current.disabledAt;
      if (disable && !window.confirm('Disable ' + current.username + ' and sign them out everywhere?')) return;
      act('/disable', { disabled: disable }, function () { return disable ? 'Account disabled.' : 'Account enabled.'; });
    } else if (action === 'revoke') {
      if (!window.confirm('Sign ' + current.username + ' out of every session?')) return;
      act('/revoke-sessions', {}, function (r) { return 'Revoked ' + r.revoked + ' session(s).'; });
    } else if (action === 'rebuild') {
      act('/rebuild-directory', {}, function () { return 'Directory entry rebuilt. Reload the list to see it.'; });
    }
  });

  form.addEventListener('submit', function (event) { event.preventDefault(); });

  var backfill = document.getElementById('admin-backfill');
  if (backfill) {
    backfill.addEventListener('submit', async function (event) {
      event.preventDefault();
      var status = backfill.querySelector('[data-backfill-status]');
      status.textContent = '';
      var res = await bcn.submit(backfill, '/api/admin/directory/rebuild', {});
      if (!res.ok) { reauth(res, backfill); return; }
      status.textContent = 'Rebuilt ' + res.rebuilt + ', ' + res.remaining + ' remaining.';
    });
  }
})();
`);
