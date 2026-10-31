/**
 * @bcnelson/auth-client — verify bcnelson.dev access JWTs inside other Workers.
 * Create one client at module scope so its JWKS cache lives for the isolate.
 */
import { jwtVerify } from 'jose';
import { createJwksCache } from './jwks.js';
import type { AccessClaims, AuthClientOptions, AuthUser, FetchLike } from './types.js';

export type { AccessClaims, AuthClientOptions, AuthUser, FetcherLike, FetchLike } from './types.js';

const DEFAULT_ISSUER = 'https://auth.bcnelson.dev';
const DEFAULT_AUDIENCE = 'bcnelson.dev';
const DEFAULT_COOKIE = 'bcn_at';
const JWKS_PATH = '/.well-known/jwks.json';

export interface AuthClient {
  /** The verified user, or null when the token is missing or invalid. */
  getUser(request: Request): Promise<AuthUser | null>;
  /** The user, or a 302 to /refresh (HTML navigations) / 401 JSON response. */
  requireUser(request: Request): Promise<AuthUser | Response>;
  /** Like requireUser, plus a 403 JSON response when the user lacks `role`. */
  requireRole(request: Request, role: string): Promise<AuthUser | Response>;
  loginUrl(returnTo: string): string;
  refreshUrl(returnTo: string): string;
}

export function createAuthClient(options: AuthClientOptions = {}): AuthClient {
  const issuer = (options.issuer ?? DEFAULT_ISSUER).replace(/\/+$/, '');
  const audience = options.audience ?? DEFAULT_AUDIENCE;
  const cookieName = options.cookieName ?? DEFAULT_COOKIE;
  const clockTolerance = options.clockToleranceSec ?? 30;

  // Service bindings ignore the host, but the URL must still be absolute.
  const service = options.service;
  const doFetch: FetchLike = service
    ? (input, init) => service.fetch(input, init)
    : (options.fetch ?? ((input, init) => fetch(input, init)));
  const jwks = createJwksCache(
    issuer + JWKS_PATH,
    doFetch,
    options.jwksTtlMs ?? 10 * 60 * 1000,
    options.jwksCooldownMs ?? 30 * 1000,
  );

  const withReturnTo = (path: string, returnTo: string) =>
    `${issuer}${path}?return_to=${encodeURIComponent(returnTo)}`;
  const loginUrl = (returnTo: string) => withReturnTo('/login', returnTo);
  const refreshUrl = (returnTo: string) => withReturnTo('/refresh', returnTo);

  async function getUser(request: Request): Promise<AuthUser | null> {
    const token = readToken(request, cookieName);
    if (!token) return null;
    try {
      const { payload } = await jwtVerify(token, jwks.getKey, {
        issuer,
        audience,
        algorithms: ['EdDSA', 'Ed25519'],
        clockTolerance,
        requiredClaims: ['sub', 'sid', 'exp'],
      });
      return toUser(payload as AccessClaims);
    } catch {
      return null;
    }
  }

  async function requireUser(request: Request): Promise<AuthUser | Response> {
    const user = await getUser(request);
    if (user) return user;
    if (isNavigation(request)) {
      return new Response(null, { status: 302, headers: { location: refreshUrl(request.url), 'cache-control': 'no-store' } });
    }
    return json({ error: 'unauthenticated' }, 401);
  }

  async function requireRole(request: Request, role: string): Promise<AuthUser | Response> {
    const result = await requireUser(request);
    if (result instanceof Response || result.hasRole(role)) return result;
    return json({ error: 'forbidden', role }, 403);
  }

  return { getUser, requireUser, requireRole, loginUrl, refreshUrl };
}

/** Bearer header first (SPA API calls), then the access cookie. */
function readToken(request: Request, cookieName: string): string | null {
  const auth = request.headers.get('authorization');
  if (auth?.toLowerCase().startsWith('bearer ')) return auth.slice(7).trim() || null;
  const cookie = request.headers.get('cookie');
  if (!cookie) return null;
  for (const part of cookie.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1 || part.slice(0, eq).trim() !== cookieName) continue;
    return part.slice(eq + 1).trim() || null;
  }
  return null;
}

function isNavigation(request: Request): boolean {
  const method = request.method.toUpperCase();
  if (method !== 'GET' && method !== 'HEAD') return false;
  return (request.headers.get('accept') ?? '').includes('text/html');
}

function toUser(claims: AccessClaims): AuthUser {
  const roles = Array.isArray(claims.roles) ? claims.roles : [];
  return {
    id: claims.sub,
    sessionId: claims.sid,
    username: claims.preferred_username,
    name: claims.name,
    picture: claims.picture,
    email: claims.email,
    roles,
    amr: Array.isArray(claims.amr) ? claims.amr : [],
    authTime: claims.auth_time,
    hasRole: (role) => roles.includes(role),
    claims,
  };
}

function json(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
  });
}
