/**
 * SQLite schemas for the Durable Objects (design §4), as numbered
 * migrations. Kept free of `cloudflare:workers` imports so tests can apply
 * them to a plain SQLite database.
 */

import type { Migration } from './migrations';

/** Placeholder keeping migration numbers stable while features land in parallel. */
const noop: Migration = () => {};

/** UserIndex (design §4.1). */
export const USER_INDEX_MIGRATIONS: readonly Migration[] = [
  // 1: initial schema
  `
  CREATE TABLE handles (
    username_norm TEXT PRIMARY KEY,
    user_id       TEXT,
    status        TEXT NOT NULL CHECK (status IN ('pending','active','held')),
    expires_at    INTEGER
  );
  CREATE TABLE emails (
    email_norm    TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL,
    status        TEXT NOT NULL CHECK (status IN ('active','held')),
    expires_at    INTEGER
  );
  CREATE TABLE identities (
    provider          TEXT NOT NULL,
    provider_subject  TEXT NOT NULL,
    user_id           TEXT NOT NULL,
    PRIMARY KEY (provider, provider_subject)
  );
  CREATE TABLE pending_signups (
    signup_id     TEXT PRIMARY KEY,
    username      TEXT NOT NULL,
    username_norm TEXT NOT NULL,
    email         TEXT NOT NULL,
    email_norm    TEXT NOT NULL,
    code_hash     TEXT NOT NULL,
    attempts      INTEGER NOT NULL DEFAULT 0,
    verified_at   INTEGER,
    expires_at    INTEGER NOT NULL
  );
  CREATE TABLE challenges (
    challenge     TEXT PRIMARY KEY,
    purpose       TEXT NOT NULL,
    expires_at    INTEGER NOT NULL
  );
  CREATE INDEX handles_user ON handles (user_id);
  CREATE INDEX emails_user ON emails (user_id);
  `,
  // 2: signup (phase 2). user_id is chosen at start so a passkey can be registered
  // for it before the account exists; code_expires_at is the current code's expiry
  // (expires_at stays the whole signup's). send_limits counts code/notice emails
  // per `email:<norm>` and `ip:<ip>` key; rows expire with their window.
  `
  ALTER TABLE pending_signups ADD COLUMN user_id TEXT;
  ALTER TABLE pending_signups ADD COLUMN code_expires_at INTEGER;
  CREATE INDEX pending_signups_username ON pending_signups (username_norm);
  CREATE TABLE send_limits (
    key           TEXT NOT NULL,
    at            INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL
  );
  CREATE INDEX send_limits_key_at ON send_limits (key, at);
  `,  // 3: passkeys. A challenge carries JSON `data` for its ceremony
  // (e.g. the signup or user a registration is for).
  `
  ALTER TABLE challenges ADD COLUMN data TEXT;
  `,
  // 4: RESERVED for profile. Replace this no-op with the real migration.
  noop,
  // 5: RESERVED for password reset / maintenance. Replace this no-op with the real migration.
  noop,
  // 6: roles / admin. `users` is the admin directory: a copy of each User DO's
  // summary, pushed by the User side (do/user/admin.ts syncDirectory). is_admin
  // mirrors roles so the last-admin guard can count cheaply.
  `
  CREATE TABLE users (
    user_id       TEXT PRIMARY KEY,
    username      TEXT NOT NULL,
    username_norm TEXT NOT NULL,
    primary_email TEXT,
    roles         TEXT NOT NULL DEFAULT '[]',
    is_admin      INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL,
    disabled_at   INTEGER,
    updated_at    INTEGER NOT NULL
  );
  CREATE INDEX users_username ON users (username_norm);
  CREATE INDEX users_email ON users (primary_email);
  CREATE INDEX users_admin ON users (is_admin);
  `,
  // 7: social login (do/index/identities.ts). `identities` (migration 1) maps
  // (provider, subject) → user. oauth_pending holds the two in-between states a
  // social login can end in, keyed by SHA-256 of a random handle kept in an
  // HttpOnly cookie: kind 'signup' (choose a username; signup_id is the
  // pending_signups row once one is reserved) and kind 'link' (the provider
  // email matches user_id's account; linking waits for that user to sign in).
  // `data` is JSON: name, picture, username suggestion.
  `
  CREATE INDEX identities_user ON identities (user_id);
  CREATE TABLE oauth_pending (
    id_hash          TEXT PRIMARY KEY,
    kind             TEXT NOT NULL CHECK (kind IN ('signup','link')),
    provider         TEXT NOT NULL,
    provider_subject TEXT NOT NULL,
    email            TEXT,
    email_verified   INTEGER NOT NULL DEFAULT 0,
    user_id          TEXT,
    signup_id        TEXT,
    data             TEXT,
    expires_at       INTEGER NOT NULL
  );
  `,
  // 8: oidc. OAuth/OIDC client registry (do/index/clients.ts). redirect_uris,
  // post_logout_redirect_uris and allowed_scopes are JSON string arrays;
  // client_secret_hash is SHA-256 of the secret (confidential clients only).
  `
  CREATE TABLE oauth_clients (
    client_id                 TEXT PRIMARY KEY,
    name                      TEXT NOT NULL,
    redirect_uris             TEXT NOT NULL,
    post_logout_redirect_uris TEXT NOT NULL DEFAULT '[]',
    allowed_scopes            TEXT NOT NULL,
    first_party               INTEGER NOT NULL DEFAULT 0,
    confidential              INTEGER NOT NULL DEFAULT 0,
    client_secret_hash        TEXT,
    created_at                INTEGER NOT NULL,
    updated_at                INTEGER NOT NULL,
    disabled_at               INTEGER
  );
  `,
];

/** User (design §4.2). */
export const USER_MIGRATIONS: readonly Migration[] = [
  // 1: initial schema
  `
  CREATE TABLE profile (
    user_id      TEXT PRIMARY KEY,
    username     TEXT NOT NULL,
    name         TEXT,
    picture      TEXT,
    roles        TEXT NOT NULL DEFAULT '[]',
    created_at   INTEGER NOT NULL,
    username_changed_at INTEGER
  );
  CREATE TABLE emails (
    email        TEXT PRIMARY KEY,
    verified_at  INTEGER NOT NULL,
    is_primary   INTEGER NOT NULL DEFAULT 0
  );
  CREATE TABLE pending_emails (
    email        TEXT PRIMARY KEY,
    code_hash    TEXT NOT NULL,
    attempts     INTEGER NOT NULL DEFAULT 0,
    expires_at   INTEGER NOT NULL
  );
  CREATE TABLE credentials (
    id           TEXT PRIMARY KEY,
    type         TEXT NOT NULL,
    label        TEXT,
    data         TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER
  );
  CREATE TABLE sessions (
    id           TEXT PRIMARY KEY,
    secret_hash  TEXT NOT NULL,
    prev_secret_hash TEXT,
    prev_valid_until INTEGER,
    created_at   INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    auth_time    INTEGER NOT NULL,
    amr          TEXT NOT NULL,
    user_agent   TEXT,
    ip           TEXT,
    expires_at   INTEGER NOT NULL,
    revoked_at   INTEGER
  );
  CREATE TABLE login_attempts (
    method          TEXT PRIMARY KEY,
    failures        INTEGER NOT NULL DEFAULT 0,
    last_failure_at INTEGER,
    locked_until    INTEGER
  );
  CREATE TABLE action_limits (
    action       TEXT NOT NULL,
    at           INTEGER NOT NULL
  );
  CREATE TABLE tokens (
    token_hash   TEXT PRIMARY KEY,
    purpose      TEXT NOT NULL,
    email        TEXT,
    expires_at   INTEGER NOT NULL,
    used_at      INTEGER
  );
  CREATE TABLE audit_log (
    at           INTEGER NOT NULL,
    event        TEXT NOT NULL,
    detail       TEXT
  );
  CREATE INDEX action_limits_action_at ON action_limits (action, at);
  CREATE INDEX audit_log_at ON audit_log (at);
  `,  // 2: passkeys. passkey_ids maps a WebAuthn credential ID (base64url) to its
  // credentials row (cred_…) so login finds the passkey without scanning JSON.
  `
  CREATE TABLE passkey_ids (
    credential_id TEXT PRIMARY KEY,
    cred_id       TEXT NOT NULL UNIQUE
  );
  `,
  // 3: RESERVED for profile. Replace this no-op with the real migration.
  noop,
  // 4: password reset / maintenance. `maintenance` records when each housekeeping
  // task last ran (user/maintenance.ts); tokens_purpose serves reset-token lookups.
  `
  CREATE TABLE maintenance (
    task         TEXT PRIMARY KEY,
    last_run_at  INTEGER NOT NULL
  );
  CREATE INDEX tokens_purpose ON tokens (purpose, used_at);
  `,
  // 5: roles / admin. A disabled account can't start or refresh sessions.
  `
  ALTER TABLE profile ADD COLUMN disabled_at INTEGER;
  `,
  // 6: RESERVED for social login. Replace this no-op with the real migration.
  noop,
  // 7: oidc (do/user/oidc.ts). oauth_grants: remembered consent per client.
  // oauth_requests: pending consent screens (single-use token). oauth_codes:
  // authorization codes (single use; kept after use to detect replay).
  // oauth_tokens: one row per code exchange, bound to the browser session;
  // secret_hash is the rotating client refresh secret (offline_access only).
  `
  CREATE TABLE oauth_grants (
    client_id    TEXT PRIMARY KEY,
    scopes       TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL
  );
  CREATE TABLE oauth_requests (
    token_hash   TEXT PRIMARY KEY,
    session_id   TEXT NOT NULL,
    request      TEXT NOT NULL,
    expires_at   INTEGER NOT NULL
  );
  CREATE TABLE oauth_codes (
    code_hash      TEXT PRIMARY KEY,
    client_id      TEXT NOT NULL,
    redirect_uri   TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    nonce          TEXT,
    scopes         TEXT NOT NULL,
    session_id     TEXT NOT NULL,
    auth_time      INTEGER NOT NULL,
    expires_at     INTEGER NOT NULL,
    used_at        INTEGER,
    token_id       TEXT
  );
  CREATE TABLE oauth_tokens (
    id               TEXT PRIMARY KEY,
    client_id        TEXT NOT NULL,
    session_id       TEXT NOT NULL,
    scopes           TEXT NOT NULL,
    secret_hash      TEXT,
    prev_secret_hash TEXT,
    created_at       INTEGER NOT NULL,
    last_used_at     INTEGER NOT NULL,
    expires_at       INTEGER NOT NULL,
    revoked_at       INTEGER
  );
  CREATE INDEX oauth_tokens_session ON oauth_tokens (session_id);
  `,
];
