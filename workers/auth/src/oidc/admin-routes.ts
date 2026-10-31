/**
 * Admin page and API for the OAuth client registry (design §9). Same guard
 * as the rest of /admin (requireAdmin: live admin session; POSTs need a
 * login within REAUTH_WINDOW). Mounted after routes/admin.ts, whose
 * /api/admin/* middleware may already have run; `adminOnly` then skips the
 * second DO round trip.
 *
 * GET  /admin/clients                              page
 * GET  /api/admin/clients                          { ok, clients }
 * POST /api/admin/clients                          { client_id?, name, redirect_uris, post_logout_redirect_uris,
 *                                                    allowed_scopes, first_party, confidential }
 *                                                  → { ok, client, client_secret? }  (secret shown once)
 * GET  /api/admin/clients/:id                      { ok, client }
 * POST /api/admin/clients/:id                      same fields minus client_id/confidential → { ok, client }
 * POST /api/admin/clients/:id/rotate-secret        { ok, client, client_secret }
 * POST /api/admin/clients/:id/disable { disabled } { ok, client }
 * Errors: `{ ok: false, error, message }`.
 */

import { Hono, type MiddlewareHandler } from 'hono';
import type { Context } from 'hono';
import type { ClientErrorStatusCode } from 'hono/utils/http-status';
import { type AdminEnv, type RequireAdminOptions, requireAdmin } from '../http/admin';
import type { AppContext } from '../http';
import { readBody } from '../http/body';
import { CLIENTS_JS, CLIENTS_STYLES, clientsPage } from '../pages/clients';
import { renderPage } from '../pages/layout';
import { indexStub } from '../routes/auth-common';
import { CLIENT_ID_PATTERN, clientInfo, newClientSecret, validateClientFields, validateClientId } from './clients';

type AdminContext = Context<AdminEnv>;

export const clientAdminRoutes = new Hono<AdminEnv>();

function adminOnly(opts: RequireAdminOptions): MiddlewareHandler<AdminEnv> {
  const guard = requireAdmin(opts);
  return async (c, next) => {
    if (c.get('admin')) {
      await next();
      return;
    }
    return guard(c, next);
  };
}

clientAdminRoutes.use('/admin/clients', adminOnly({ mode: 'page' }));
clientAdminRoutes.use('/api/admin/clients', adminOnly({ mode: 'api' }));
clientAdminRoutes.use('/api/admin/clients/*', adminOnly({ mode: 'api' }));

function fail(c: AdminContext, status: ClientErrorStatusCode, error: string, message: string): Response {
  return c.json({ ok: false, error, message }, status);
}

async function input(c: AdminContext): Promise<Record<string, unknown> | null> {
  const body = await readBody(c as unknown as AppContext);
  if (!body) return null;
  return body.json ?? body.fields;
}

function clientIdParam(c: AdminContext): string | null {
  const id = c.req.param('id') ?? '';
  return CLIENT_ID_PATTERN.test(id) ? id : null;
}

clientAdminRoutes.get('/admin/clients', async (c) => {
  const clients = (await indexStub(c.env).listOAuthClients()).map(clientInfo);
  return renderPage(c as unknown as AppContext, {
    title: 'OAuth clients',
    body: clientsPage({ clients, issuer: c.env.ISSUER }),
    scripts: [CLIENTS_JS],
    styles: CLIENTS_STYLES,
  });
});

clientAdminRoutes.get('/api/admin/clients', async (c) => {
  const clients = (await indexStub(c.env).listOAuthClients()).map(clientInfo);
  return c.json({ ok: true, clients });
});

clientAdminRoutes.post('/api/admin/clients', async (c) => {
  const data = await input(c);
  if (!data) return fail(c, 400, 'bad_request', 'Send the client fields as JSON or a form.');
  const fields = validateClientFields(data, c.env);
  if (!fields.ok) return fail(c, 400, fields.error, fields.message);
  const clientId = validateClientId(data.client_id, fields.value.firstParty, c.env);
  if (!clientId.ok) return fail(c, 400, clientId.error, clientId.message);
  const confidential = data.confidential === true || data.confidential === 'true' || data.confidential === 'on';
  const secret = confidential ? await newClientSecret() : null;
  const result = await indexStub(c.env).createOAuthClient({
    ...fields.value, clientId: clientId.value, confidential, secretHash: secret?.hash ?? null,
  });
  if (!result.ok) return fail(c, 409, 'client_exists', 'A client with that id already exists.');
  const body: Record<string, unknown> = { ok: true, client: clientInfo(result.client) };
  if (secret) body.client_secret = secret.secret;
  return c.json(body, 201);
});

clientAdminRoutes.get('/api/admin/clients/:id', async (c) => {
  const id = clientIdParam(c);
  const client = id ? await indexStub(c.env).getOAuthClient(id) : null;
  if (!client) return fail(c, 404, 'not_found', 'No such client.');
  return c.json({ ok: true, client: clientInfo(client) });
});

clientAdminRoutes.post('/api/admin/clients/:id', async (c) => {
  const id = clientIdParam(c);
  if (!id) return fail(c, 404, 'not_found', 'No such client.');
  const data = await input(c);
  if (!data) return fail(c, 400, 'bad_request', 'Send the client fields as JSON or a form.');
  const fields = validateClientFields(data, c.env);
  if (!fields.ok) return fail(c, 400, fields.error, fields.message);
  // The id rule depends on first_party, so re-check it when that changes.
  const idOk = validateClientId(id, fields.value.firstParty, c.env);
  if (!idOk.ok) return fail(c, 400, idOk.error, idOk.message);
  const result = await indexStub(c.env).updateOAuthClient(id, fields.value);
  if (!result.ok) return fail(c, 404, 'not_found', 'No such client.');
  return c.json({ ok: true, client: clientInfo(result.client) });
});

clientAdminRoutes.post('/api/admin/clients/:id/rotate-secret', async (c) => {
  const id = clientIdParam(c);
  if (!id) return fail(c, 404, 'not_found', 'No such client.');
  const secret = await newClientSecret();
  const result = await indexStub(c.env).setOAuthClientSecret(id, secret.hash);
  if (!result.ok) return fail(c, 404, 'not_found', 'No such confidential client.');
  return c.json({ ok: true, client: clientInfo(result.client), client_secret: secret.secret });
});

clientAdminRoutes.post('/api/admin/clients/:id/disable', async (c) => {
  const id = clientIdParam(c);
  if (!id) return fail(c, 404, 'not_found', 'No such client.');
  const data = await input(c);
  const raw = data?.disabled;
  const disabled = raw === true || raw === 'true' ? true : raw === false || raw === 'false' ? false : null;
  if (disabled === null) return fail(c, 400, 'bad_request', 'Send { disabled: boolean }.');
  const result = await indexStub(c.env).setOAuthClientDisabled(id, disabled);
  if (!result.ok) return fail(c, 404, 'not_found', 'No such client.');
  return c.json({ ok: true, client: clientInfo(result.client) });
});
