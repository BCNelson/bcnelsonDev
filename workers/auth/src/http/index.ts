/**
 * Request security helpers (design §10): Origin checks, return_to validation,
 * CORS for subdomain callers, client IP.
 */

import type { Context, MiddlewareHandler } from 'hono';
import { config } from '../config';
import type { Env } from '../env';

/** Hono environment shared by every route module. */
export type AppEnv = { Bindings: Env };
export type AppContext = Context<AppEnv>;

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/** True for local dev domains, where http and non-default ports are allowed. */
export function isDevDomain(domain: string): boolean {
  return domain === 'localhost' || domain.endsWith('.localhost');
}

/** Parsed ALLOWED_ORIGINS. */
export function allowedOrigins(env: Env): string[] {
  return env.ALLOWED_ORIGINS.split(',')
    .map((o) => o.trim())
    .filter(Boolean);
}

/** True when `origin` is exactly https://<COOKIE_DOMAIN> or https://*.<COOKIE_DOMAIN> (http too in dev). */
export function isSiteOrigin(origin: string | null | undefined, env: Env): boolean {
  if (!origin) return false;
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    return false;
  }
  // An Origin header is scheme://host[:port] only; reject paths, userinfo, trailing slashes.
  if (url.origin !== origin) return false;
  return isSiteUrl(url, env);
}

/** True when the request may change state: safe methods always, others need an allowed Origin. */
export function checkOrigin(
  method: string,
  origin: string | null | undefined,
  env: Env,
  allowSiteOrigins = false,
): boolean {
  if (SAFE_METHODS.has(method.toUpperCase())) return true;
  if (!origin) return false;
  if (allowedOrigins(env).includes(origin)) return true;
  return allowSiteOrigins && isSiteOrigin(origin, env);
}

export interface OriginCheckOptions {
  /** Paths that also accept any site origin (https://*.<COOKIE_DOMAIN>), e.g. /logout. */
  sitePaths?: string[];
}

/** Rejects state-changing requests whose Origin isn't allowed (SameSite doesn't stop siblings). */
export function originCheck(options: OriginCheckOptions = {}): MiddlewareHandler<AppEnv> {
  const sitePaths = new Set(options.sitePaths ?? []);
  return async (c, next) => {
    const allowSite = sitePaths.has(c.req.path);
    if (!checkOrigin(c.req.method, c.req.header('Origin'), c.env, allowSite)) {
      return c.json({ error: 'forbidden_origin' }, 403);
    }
    await next();
  };
}

/** Default landing page after login/logout. */
export function defaultReturnTo(env: Env): string {
  const scheme = isDevDomain(env.COOKIE_DOMAIN) ? 'http' : 'https';
  return `${scheme}://${env.COOKIE_DOMAIN}/`;
}

/**
 * Returns `raw` normalized if it points at the site (https://<COOKIE_DOMAIN> or a
 * subdomain), otherwise the default. Guards against open redirects.
 */
export function validateReturnTo(raw: string | null | undefined, env: Env): string {
  const fallback = defaultReturnTo(env);
  if (!raw || raw.length > config.MAX_RETURN_TO_LENGTH) return fallback;
  // URL parsing strips tabs/newlines and treats backslashes as slashes; refuse them outright.
  if (/[\u0000- \u007f\\]/.test(raw)) return fallback;
  if (!/^https?:\/\/[^/]/i.test(raw)) return fallback;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return fallback;
  }
  return isSiteUrl(url, env) ? url.href : fallback;
}

function isSiteUrl(url: URL, env: Env): boolean {
  const domain = env.COOKIE_DOMAIN.toLowerCase();
  const dev = isDevDomain(domain);
  if (url.protocol !== 'https:' && !(dev && url.protocol === 'http:')) return false;
  if (url.username || url.password) return false;
  if (url.port && !dev) return false;
  const host = url.hostname;
  return host === domain || host.endsWith(`.${domain}`);
}

export interface CorsOptions {
  methods: string[];
}

/**
 * CORS with credentials for any site origin. Answers preflights; other requests
 * get the headers added. Requests from other origins pass through without them.
 */
export function siteCors(options: CorsOptions): MiddlewareHandler<AppEnv> {
  const methods = options.methods.join(', ');
  return async (c, next) => {
    const origin = c.req.header('Origin');
    const allowed = isSiteOrigin(origin, c.env);
    if (c.req.method === 'OPTIONS') {
      if (!allowed) return c.body(null, 403);
      return c.body(null, 204, {
        'Access-Control-Allow-Origin': origin!,
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Allow-Methods': methods,
        'Access-Control-Allow-Headers': c.req.header('Access-Control-Request-Headers') ?? '',
        'Access-Control-Max-Age': String(config.CORS_MAX_AGE),
        Vary: 'Origin',
      });
    }
    await next();
    c.header('Vary', 'Origin', { append: true });
    if (allowed) {
      c.header('Access-Control-Allow-Origin', origin!);
      c.header('Access-Control-Allow-Credentials', 'true');
    }
  };
}

/** Client IP as seen by Cloudflare. */
export function clientIp(request: Request): string | undefined {
  return request.headers.get('CF-Connecting-IP') ?? undefined;
}
