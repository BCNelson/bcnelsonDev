/**
 * Admin page and API (design §8). Everything here goes through requireAdmin:
 * a live session with the `admin` role; POSTs also need a login within
 * REAUTH_WINDOW (else 403 reauth_required). Mutations are audit-logged on
 * the target user with the acting admin's id.
 *
 * GET  /admin?q=&cursor=                          page
 * GET  /api/admin/users?q=&cursor=&limit=         { ok, users: DirectoryEntry[], nextCursor }
 * GET  /api/admin/users/:id                       { ok, user: AdminUserDetail, directory: DirectoryEntry | null }
 * POST /api/admin/users/:id/roles       { roles }    { ok, roles, changed }   400 invalid_role · 409 last_admin
 * POST /api/admin/users/:id/disable     { disabled } { ok, disabledAt, revokedSessions }   409 last_admin | cannot_disable_self
 * POST /api/admin/users/:id/revoke-sessions          { ok, revoked }
 * POST /api/admin/users/:id/rebuild-directory        { ok, directory }
 * POST /api/admin/directory/rebuild                  { ok, rebuilt, remaining }  (backfill missing rows)
 * Errors: `{ ok: false, error, message }`; 401 unauthenticated, 403 forbidden | reauth_required, 404 not_found.
 */

import { Hono } from 'hono';
import type { Context } from 'hono';
import type { ClientErrorStatusCode } from 'hono/utils/http-status';
import { config } from '../config';
import type { Env } from '../env';
import { type AdminEnv, requireAdmin } from '../http/admin';
import type { AppContext } from '../http';
import { readBody } from '../http/body';
import { html } from 'hono/html';
import { ADMIN_JS, ADMIN_STYLES, adminPage } from '../pages/admin';
import { renderPage } from '../pages/layout';
import { PROFILE_SLOTS } from './profile';

type AdminContext = Context<AdminEnv>;

const USER_ID = /^usr_[0-9A-HJKMNP-TV-Z]{26}$/;
const MAX_QUERY = 100;

export const adminRoutes = new Hono<AdminEnv>();

adminRoutes.use('/admin', requireAdmin({ mode: 'page' }));
adminRoutes.use('/api/admin/*', requireAdmin({ mode: 'api' }));

// Profile page: links for admins (roles are the live ones from getAccount).
PROFILE_SLOTS.admin = ({ account }) =>
  account.profile.roles.includes('admin')
    ? { html: html`<nav class="admin-links" aria-label="Administration"><a href="/admin">Admin: users</a> · <a href="/admin/clients">Admin: applications</a></nav>` }
    : null;

function indexStub(env: Env) {
  return env.USER_INDEX.get(env.USER_INDEX.idFromName('index'));
}

function userStub(env: Env, userId: string) {
  return env.USER.get(env.USER.idFromName(userId));
}

function fail(c: AdminContext, status: ClientErrorStatusCode, error: string, message: string): Response {
  return c.json({ ok: false, error, message }, status);
}

function notFound(c: AdminContext): Response {
  return fail(c, 404, 'not_found', 'No such user.');
}

function listQuery(c: AdminContext): { q: string; cursor: string } {
  const q = (c.req.query('q') ?? '').trim().slice(0, MAX_QUERY);
  const rawCursor = c.req.query('cursor') ?? '';
  return { q, cursor: USER_ID.test(rawCursor) ? rawCursor : '' };
}

/** The :id param when it is a well-formed user id of a real account, else null. */
async function targetUser(c: AdminContext): Promise<string | null> {
  const id = c.req.param('id') ?? '';
  if (!USER_ID.test(id)) return null;
  return (await indexStub(c.env).isKnownUser(id)) ? id : null;
}

adminRoutes.get('/admin', async (c) => {
  const { q, cursor } = listQuery(c);
  const page = await indexStub(c.env).listDirectory({ q, cursor });
  return renderPage(c as unknown as AppContext, {
    title: 'Admin',
    body: adminPage({ users: page.users, q, cursor, nextCursor: page.nextCursor, actorUserId: c.get('admin').userId }),
    scripts: [ADMIN_JS],
    styles: ADMIN_STYLES,
  });
});

adminRoutes.get('/api/admin/users', async (c) => {
  const { q, cursor } = listQuery(c);
  const limit = Number(c.req.query('limit') ?? config.ADMIN_PAGE_SIZE) || config.ADMIN_PAGE_SIZE;
  const page = await indexStub(c.env).listDirectory({ q, cursor, limit });
  return c.json({ ok: true, users: page.users, nextCursor: page.nextCursor });
});

adminRoutes.get('/api/admin/users/:id', async (c) => {
  const id = await targetUser(c);
  if (!id) return notFound(c);
  const user = await userStub(c.env, id).getAdminDetail();
  if (!user) return notFound(c);
  const directory = await indexStub(c.env).getDirectoryEntry(id);
  return c.json({ ok: true, user, directory });
});

adminRoutes.post('/api/admin/users/:id/roles', async (c) => {
  const id = await targetUser(c);
  if (!id) return notFound(c);
  const body = await readBody(c as unknown as AppContext);
  let roles: unknown = body?.json?.roles;
  if (roles === undefined && body?.fields.roles !== undefined) {
    roles = body.fields.roles.split(',').map((r) => r.trim()).filter(Boolean);
  }
  if (!Array.isArray(roles)) return fail(c, 400, 'bad_request', 'Send { roles: string[] }.');
  const result = await userStub(c.env, id).setRoles(roles as string[], c.get('admin').userId);
  if (result.ok) return c.json({ ok: true, roles: result.roles, changed: result.changed });
  switch (result.reason) {
    case 'invalid_role':
      return fail(c, 400, 'invalid_role', `Roles must be from: ${config.ROLES.join(', ')}.`);
    case 'last_admin':
      return fail(c, 409, 'last_admin', 'This is the last active admin; grant admin to someone else first.');
    default:
      return notFound(c);
  }
});

adminRoutes.post('/api/admin/users/:id/disable', async (c) => {
  const id = await targetUser(c);
  if (!id) return notFound(c);
  const body = await readBody(c as unknown as AppContext);
  const raw = body?.json?.disabled ?? body?.fields.disabled;
  const disabled = raw === true || raw === 'true' ? true : raw === false || raw === 'false' ? false : null;
  if (disabled === null) return fail(c, 400, 'bad_request', 'Send { disabled: boolean }.');
  const result = await userStub(c.env, id).setDisabled(disabled, c.get('admin').userId);
  if (result.ok) return c.json({ ok: true, disabledAt: result.disabledAt, revokedSessions: result.revokedSessions });
  switch (result.reason) {
    case 'self':
      return fail(c, 409, 'cannot_disable_self', "You can't disable your own account.");
    case 'last_admin':
      return fail(c, 409, 'last_admin', 'This is the last active admin; grant admin to someone else first.');
    default:
      return notFound(c);
  }
});

adminRoutes.post('/api/admin/users/:id/revoke-sessions', async (c) => {
  const id = await targetUser(c);
  if (!id) return notFound(c);
  const revoked = await userStub(c.env, id).revokeSessionsByAdmin(c.get('admin').userId);
  return c.json({ ok: true, revoked });
});

adminRoutes.post('/api/admin/users/:id/rebuild-directory', async (c) => {
  const id = await targetUser(c);
  if (!id) return notFound(c);
  if (!(await userStub(c.env, id).syncDirectory())) return notFound(c);
  return c.json({ ok: true, directory: await indexStub(c.env).getDirectoryEntry(id) });
});

/** Backfill: re-sync up to ADMIN_BACKFILL_BATCH accounts that have no directory row yet. */
adminRoutes.post('/api/admin/directory/rebuild', async (c) => {
  const index = indexStub(c.env);
  const { userIds, remaining } = await index.missingDirectoryEntries(config.ADMIN_BACKFILL_BATCH);
  let rebuilt = 0;
  for (const id of userIds) {
    if (await userStub(c.env, id).syncDirectory()) rebuilt++;
  }
  // Ids without a profile (shouldn't happen) stay missing; count them as remaining.
  return c.json({ ok: true, rebuilt, remaining: remaining + (userIds.length - rebuilt) });
});
