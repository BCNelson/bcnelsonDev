/**
 * Every limit, TTL and list the auth system uses. Nothing is hard-coded at its
 * point of use; change a value here and it applies everywhere.
 */

const SECOND = 1000;
const MINUTE = 60 * SECOND;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

export const config = {
  // tokens & sessions
  ACCESS_TOKEN_TTL: 15 * MINUTE,
  REFRESH_TOKEN_TTL: 60 * DAY,
  REFRESH_GRACE: 30 * SECOND,
  REAUTH_WINDOW: 10 * MINUTE,
  ACCESS_COOKIE: 'bcn_at',
  REFRESH_COOKIE: '__Host-bcn_rt',
  /** Used when the auth origin isn't https (local dev), since __Host- requires Secure. */
  REFRESH_COOKIE_INSECURE: 'bcn_rt',
  AUDIENCE: 'bcnelson.dev',

  // http
  MAX_RETURN_TO_LENGTH: 2048,
  /** Seconds browsers may cache a CORS preflight. */
  CORS_MAX_AGE: 600,
  /** Longest string accepted for any single request field (bounds hashing work). */
  MAX_FIELD_LENGTH: 1024,
  /** Seconds browsers/CDN may cache /assets/*.js. */
  ASSET_MAX_AGE: 300,

  // turnstile
  TURNSTILE_SITEVERIFY_URL: 'https://challenges.cloudflare.com/turnstile/v0/siteverify',
  TURNSTILE_TIMEOUT: 5 * SECOND,

  // signup & verification codes
  SIGNUP_TTL: 30 * MINUTE,
  CODE_TTL: 15 * MINUTE,
  CODE_LENGTH: 6,
  CODE_MAX_ATTEMPTS: 5,
  RESET_TTL: 30 * MINUTE,
  WEBAUTHN_CHALLENGE_TTL: 5 * MINUTE,
  /** Signup code/notice emails per client IP: [max count, window]. Per-email uses ACTION_LIMITS.verification_send. */
  SIGNUP_SENDS_PER_IP: [20, HOUR] as readonly [number, number],

  // identifiers
  USERNAME_PATTERN: /^[a-z0-9][a-z0-9_-]{2,29}$/,
  USERNAME_CHANGE_COOLDOWN: 30 * DAY,
  USERNAME_HOLD: 30 * DAY,
  RESERVED_USERNAMES: [
    'admin', 'administrator', 'root', 'support', 'help', 'auth', 'api', 'www', 'mail',
    'security', 'null', 'undefined', 'me', 'system', 'profile', 'login', 'logout',
    'signup', 'settings', 'example',
  ] as readonly string[],

  // emails
  MAX_EMAILS_PER_ACCOUNT: 5,
  MAX_PENDING_EMAILS: 3,
  EMAIL_HOLD: 7 * DAY,

  // profile
  /** Longest display name (code points). */
  PROFILE_NAME_MAX_LENGTH: 100,
  /** Longest avatar URL (https only). */
  PICTURE_URL_MAX_LENGTH: 2048,

  // per-user password backoff
  TURNSTILE_AFTER_FAILURES: 3,
  BACKOFF_AFTER_FAILURES: 5,
  BACKOFF_BASE: 30 * SECOND,
  BACKOFF_MAX: 15 * MINUTE,
  ALERT_AFTER_FAILURES: 10,

  // per-user action limits: [max count, window]
  ACTION_LIMITS: {
    password_reset: [3, HOUR],
    verification_send: [5, HOUR],
    email_add: [10, DAY],
  } as Record<string, readonly [number, number]>,

  // passwords
  PASSWORD_MIN_LENGTH: 8,
  PASSWORD_MAX_LENGTH: 128,

  // roles
  ROLES: ['admin', 'beta'] as readonly string[],

  // password reset / maintenance
  /** Revoked or expired sessions are deleted this long after revocation/expiry. */
  SESSION_RETENTION: 30 * DAY,
  /** audit_log rows older than this are deleted. */
  AUDIT_RETENTION: 365 * DAY,
  /** User DO pruning runs (from createSession) at most this often. */
  PRUNE_INTERVAL: DAY,
  /** Subdomain names of bcnelson.dev; never valid as usernames (design §5). */
  SUBDOMAIN_NAMES: [
    'auth', 'www', 'api', 'example', 'mail', 'profile', 'admin', 'status', 'blog', 'dev',
    'staging', 'test', 'app', 'cdn', 'static', 'assets',
  ] as readonly string[],

  // roles / admin
  /** Users per page on the admin directory (default / maximum). */
  ADMIN_PAGE_SIZE: 25,
  ADMIN_MAX_PAGE_SIZE: 100,
  /** Recent audit_log entries shown per user on the admin page. */
  ADMIN_AUDIT_LIMIT: 50,
  /** Directory backfill: User DOs re-synced per rebuild request. */
  ADMIN_BACKFILL_BATCH: 25,

  // passkeys
  /** WebAuthn relying-party display name (the RP ID comes from env.RP_ID). */
  PASSKEY_RP_NAME: 'bcnelson.dev',
  /** Label for a new passkey whose AAGUID isn't in the known-authenticator map. */
  PASSKEY_DEFAULT_LABEL: 'Passkey',
  PASSKEY_LABEL_MAX_LENGTH: 64,
  MAX_PASSKEYS_PER_ACCOUNT: 20,

  // social login
  /** Lifetime of the signed state/PKCE cookie between /oauth/:provider/start and the callback. */
  OAUTH_STATE_TTL: 10 * MINUTE,
  /** Signed state cookie (Path=/oauth, HttpOnly). */
  OAUTH_STATE_COOKIE: 'bcn_oauth',
  /** Pending social signup / pending link handle cookies (Path=/oauth, HttpOnly). */
  OAUTH_SIGNUP_COOKIE: 'bcn_oauth_signup',
  OAUTH_LINK_COOKIE: 'bcn_oauth_link',
  /** How long an "email matches an existing account, sign in to link" offer stays usable. */
  OAUTH_LINK_TTL: 15 * MINUTE,
  /** A social signup (choosing a username, optional email code) lives as long as a normal signup. */
  OAUTH_SIGNUP_TTL: 30 * MINUTE,
  /** Timeout for provider token/API requests. */
  OAUTH_HTTP_TIMEOUT: 10 * SECOND,
  /** User-Agent sent to provider APIs (GitHub requires one). */
  OAUTH_USER_AGENT: 'bcnelson.dev-auth',
  /** Linked social identities per account. */
  MAX_OAUTH_IDENTITIES_PER_ACCOUNT: 10,

  // oidc
  /** Scopes the OpenID provider supports (design §9). */
  OIDC_SCOPES: ['openid', 'profile', 'email', 'roles', 'offline_access'] as readonly string[],
  /** Authorization code lifetime (single use). */
  OIDC_CODE_TTL: 60 * SECOND,
  /** Used/expired codes are kept this long so a replay can still revoke what the code issued. */
  OIDC_CODE_RETENTION: DAY,
  /** Pending consent screen (single-use consent token) lifetime. */
  OIDC_CONSENT_TTL: 10 * MINUTE,
  /** Client access tokens (aud = client_id). */
  OIDC_ACCESS_TOKEN_TTL: 10 * MINUTE,
  OIDC_ID_TOKEN_TTL: 10 * MINUTE,
  /** Client refresh tokens (offline_access): rotating, sliding expiry. */
  OIDC_REFRESH_TOKEN_TTL: 30 * DAY,
  /** Longest state / nonce / other authorize parameter accepted. */
  OIDC_MAX_PARAM_LENGTH: 512,
  /** Largest /oauth/token request body (bytes). */
  OIDC_MAX_TOKEN_BODY: 8 * 1024,
  OIDC_MAX_REDIRECT_URIS: 10,
  OIDC_CLIENT_NAME_MAX_LENGTH: 80,
} as const;

export type Config = typeof config;
