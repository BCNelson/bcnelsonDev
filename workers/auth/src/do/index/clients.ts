/**
 * OAuth/OIDC client registry (design §9), table `oauth_clients`
 * (USER_INDEX_MIGRATIONS 8). Input is validated by the Worker
 * (oidc/clients.ts validateClientFields); this module only stores it.
 */

import type { ClientFields, OAuthClientRecord } from '../../oidc/clients';
import { parseStringArray } from '../sessions';
import type { IndexContext } from './context';

type ClientRow = {
  client_id: string;
  name: string;
  redirect_uris: string;
  post_logout_redirect_uris: string;
  allowed_scopes: string;
  first_party: number;
  confidential: number;
  client_secret_hash: string | null;
  created_at: number;
  updated_at: number;
  disabled_at: number | null;
};

function toRecord(r: ClientRow): OAuthClientRecord {
  return {
    clientId: r.client_id,
    name: r.name,
    redirectUris: parseStringArray(r.redirect_uris),
    postLogoutRedirectUris: parseStringArray(r.post_logout_redirect_uris),
    allowedScopes: parseStringArray(r.allowed_scopes),
    firstParty: r.first_party === 1,
    confidential: r.confidential === 1,
    secretHash: r.client_secret_hash,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
    disabledAt: r.disabled_at,
  };
}

export type CreateClientResult = { ok: true; client: OAuthClientRecord } | { ok: false; reason: 'exists' };
export type ClientChangeResult = { ok: true; client: OAuthClientRecord } | { ok: false; reason: 'not_found' };

export function getClient(ctx: Pick<IndexContext, 'sql'>, clientId: string): OAuthClientRecord | null {
  const row = ctx.sql.exec<ClientRow>('SELECT * FROM oauth_clients WHERE client_id = ?', clientId).toArray()[0];
  return row ? toRecord(row) : null;
}

export function listClients(ctx: Pick<IndexContext, 'sql'>): OAuthClientRecord[] {
  return ctx.sql.exec<ClientRow>('SELECT * FROM oauth_clients ORDER BY created_at, client_id').toArray().map(toRecord);
}

/** Register a client. `secretHash` is required for confidential clients and ignored otherwise. */
export function createClient(
  ctx: IndexContext,
  input: ClientFields & { clientId: string; confidential: boolean; secretHash: string | null },
): CreateClientResult {
  if (input.confidential && !input.secretHash) throw new Error('createClient: confidential client needs a secret');
  return ctx.storage.transactionSync((): CreateClientResult => {
    if (getClient(ctx, input.clientId)) return { ok: false, reason: 'exists' };
    ctx.sql.exec(
      `INSERT INTO oauth_clients (client_id, name, redirect_uris, post_logout_redirect_uris, allowed_scopes,
         first_party, confidential, client_secret_hash, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      input.clientId, input.name, JSON.stringify(input.redirectUris), JSON.stringify(input.postLogoutRedirectUris),
      JSON.stringify(input.allowedScopes), input.firstParty ? 1 : 0, input.confidential ? 1 : 0,
      input.confidential ? input.secretHash : null, ctx.now, ctx.now,
    );
    return { ok: true, client: getClient(ctx, input.clientId)! };
  });
}

/** Replace a client's editable fields (not its id, type or secret). */
export function updateClient(ctx: IndexContext, clientId: string, fields: ClientFields): ClientChangeResult {
  const cursor = ctx.sql.exec(
    `UPDATE oauth_clients SET name = ?, redirect_uris = ?, post_logout_redirect_uris = ?, allowed_scopes = ?,
       first_party = ?, updated_at = ? WHERE client_id = ?`,
    fields.name, JSON.stringify(fields.redirectUris), JSON.stringify(fields.postLogoutRedirectUris),
    JSON.stringify(fields.allowedScopes), fields.firstParty ? 1 : 0, ctx.now, clientId,
  );
  const client = cursor.rowsWritten > 0 ? getClient(ctx, clientId) : null;
  return client ? { ok: true, client } : { ok: false, reason: 'not_found' };
}

/** Replace a confidential client's secret hash. Not found for public clients. */
export function setClientSecret(ctx: IndexContext, clientId: string, secretHash: string): ClientChangeResult {
  const cursor = ctx.sql.exec(
    'UPDATE oauth_clients SET client_secret_hash = ?, updated_at = ? WHERE client_id = ? AND confidential = 1',
    secretHash, ctx.now, clientId,
  );
  const client = cursor.rowsWritten > 0 ? getClient(ctx, clientId) : null;
  return client ? { ok: true, client } : { ok: false, reason: 'not_found' };
}

/** Disable (keeps the row, so the id is never reused) or re-enable. */
export function setClientDisabled(ctx: IndexContext, clientId: string, disabled: boolean): ClientChangeResult {
  const cursor = disabled
    ? ctx.sql.exec(
      'UPDATE oauth_clients SET disabled_at = COALESCE(disabled_at, ?), updated_at = ? WHERE client_id = ?',
      ctx.now, ctx.now, clientId,
    )
    : ctx.sql.exec(
      'UPDATE oauth_clients SET disabled_at = NULL, updated_at = ? WHERE client_id = ?', ctx.now, clientId,
    );
  const client = cursor.rowsWritten > 0 ? getClient(ctx, clientId) : null;
  return client ? { ok: true, client } : { ok: false, reason: 'not_found' };
}
