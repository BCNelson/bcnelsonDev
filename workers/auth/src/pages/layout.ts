/**
 * Page framework for server-rendered HTML (login, signup, profile, ...).
 *
 * - Markup: `hono/html` tagged templates. Every interpolation is escaped;
 *   nested `html` results are not. Use `raw()` only for trusted constants.
 * - Styles: one inline stylesheet (STYLES), allowed by a per-response nonce.
 * - Scripts: no inline scripts. Page JS is registered with `defineAsset`
 *   (pages/assets.ts), served from GET /assets/<name>, and listed in
 *   `scripts`. /assets/app.js (window.bcn helpers) always loads first.
 * - Data for scripts goes in data-* attributes, never in script bodies.
 * - CSP: script-src 'self' + Turnstile; frames only from Turnstile.
 */

import { html, raw } from 'hono/html';
import type { HtmlEscapedString } from 'hono/utils/html';
import { randomToken } from '../crypto/ids';
import type { Env } from '../env';
import { defaultReturnTo, type AppContext } from '../http';
import { APP_JS } from './client/app';

export type Html = HtmlEscapedString | Promise<HtmlEscapedString>;

export const TURNSTILE_ORIGIN = 'https://challenges.cloudflare.com';
const TURNSTILE_SCRIPT = `${TURNSTILE_ORIGIN}/turnstile/v0/api.js?render=explicit`;

export interface LayoutOptions {
  title: string;
  body: Html;
  env: Env;
  /** Per-response nonce for the inline stylesheet (renderPage supplies it). */
  nonce: string;
  /** Asset paths from defineAsset, loaded after /assets/app.js. */
  scripts?: string[];
  /** Load the Turnstile API (explicit rendering; see bcn.turnstile). */
  turnstile?: boolean;
  /** Extra page CSS appended to STYLES. Trusted constants only (not escaped). */
  styles?: string;
}

/** The full document around a page body. */
export function layout(opts: LayoutOptions): Html {
  const scripts = [APP_JS, ...(opts.scripts ?? [])];
  return html`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="robots" content="noindex">
<title>${opts.title} · ${opts.env.COOKIE_DOMAIN}</title>
<style nonce="${opts.nonce}">${raw(STYLES + (opts.styles ?? ''))}</style>
${opts.turnstile ? html`<script src="${TURNSTILE_SCRIPT}" defer></script>` : ''}
${scripts.map((src) => html`<script src="${src}" defer></script>`)}
</head>
<body>
<header class="site"><a href="${defaultReturnTo(opts.env)}">${opts.env.COOKIE_DOMAIN}</a></header>
<main class="card">
${opts.body}
</main>
</body>
</html>`;
}

/** Content-Security-Policy for pages. Passkeys need nothing extra (fetch to 'self'). */
export function contentSecurityPolicy(nonce: string): string {
  return [
    "default-src 'none'",
    `script-src 'self' ${TURNSTILE_ORIGIN}`,
    `style-src 'nonce-${nonce}'`,
    "img-src 'self' data: https:",
    "connect-src 'self'",
    `frame-src ${TURNSTILE_ORIGIN}`,
    "form-action 'self'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
  ].join('; ');
}

export interface PageOptions {
  title: string;
  body: Html;
  scripts?: string[];
  turnstile?: boolean;
  status?: 200 | 400 | 403 | 404 | 409 | 429;
  /** Extra page CSS (trusted constant), e.g. a wider card. */
  styles?: string;
}

/** Render a page with the layout and the security headers. */
export function renderPage(c: AppContext, opts: PageOptions): Response | Promise<Response> {
  const nonce = randomToken(16);
  c.header('Content-Security-Policy', contentSecurityPolicy(nonce));
  c.header('X-Content-Type-Options', 'nosniff');
  c.header('X-Frame-Options', 'DENY');
  // return_to rides in URLs; don't leak it to third parties.
  c.header('Referrer-Policy', 'no-referrer');
  c.header('Cache-Control', 'no-store');
  return c.html(layout({ ...opts, env: c.env, nonce }), opts.status ?? 200);
}

/**
 * Error/status box. Scripts fill it via bcn.showError; `message` pre-fills it
 * for no-JS fallbacks. role=alert so screen readers announce changes.
 */
export function errorBox(message?: string): Html {
  return html`<div class="error" role="alert" data-error tabindex="-1" ${message ? '' : raw('hidden')}>${message ?? ''}</div>`;
}

const STYLES = `
:root{--bg:#f6f7f9;--fg:#16181d;--muted:#5b6170;--card:#fff;--border:#d5d9e0;--accent:#1a56db;--accent-fg:#fff;--error-bg:#fdecec;--error-fg:#9b1c1c;--focus:#93b4f5;color-scheme:light dark}
@media (prefers-color-scheme:dark){:root{--bg:#111318;--fg:#e8eaee;--muted:#a0a6b3;--card:#1b1e25;--border:#343944;--accent:#6b9bff;--accent-fg:#0b1020;--error-bg:#3a1717;--error-fg:#ffb4b4;--focus:#3d5fa8}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
header.site{max-width:420px;margin:0 auto;padding:24px 16px 0}
header.site a{color:var(--fg);font-weight:600;text-decoration:none}
main.card{max-width:420px;margin:16px auto 48px;padding:24px;background:var(--card);border:1px solid var(--border);border-radius:12px}
@media (max-width:460px){main.card{margin:12px 16px 32px;padding:20px 16px}}
h1{margin:0 0 16px;font-size:1.5rem;line-height:1.25}
p{margin:0 0 12px}
.muted{color:var(--muted);font-size:.9rem}
form{margin:0}
label{display:block;margin:12px 0 4px;font-weight:600;font-size:.95rem}
.label-row{display:flex;justify-content:space-between;align-items:baseline;gap:8px}
.label-row a{font-size:.875rem}
input{width:100%;padding:10px 12px;font:inherit;color:var(--fg);background:var(--bg);border:1px solid var(--border);border-radius:8px}
input:focus-visible,button:focus-visible,a:focus-visible{outline:3px solid var(--focus);outline-offset:1px}
button{display:inline-flex;justify-content:center;align-items:center;gap:8px;width:100%;margin-top:16px;padding:10px 16px;font:inherit;font-weight:600;border-radius:8px;border:1px solid var(--accent);background:var(--accent);color:var(--accent-fg);cursor:pointer}
button.secondary{background:transparent;color:var(--accent)}
button[disabled]{opacity:.6;cursor:progress}
a{color:var(--accent)}
.error{margin:12px 0;padding:10px 12px;border-radius:8px;background:var(--error-bg);color:var(--error-fg)}
.notice{margin:12px 0;padding:10px 12px;border-radius:8px;border:1px solid var(--border);background:var(--bg)}
.error[hidden],[hidden]{display:none!important}
.turnstile{margin-top:16px;min-height:65px}
.divider{display:flex;align-items:center;gap:12px;margin:20px 0 4px;color:var(--muted);font-size:.875rem}
.divider::before,.divider::after{content:"";flex:1;border-top:1px solid var(--border)}
.steps{margin:0 0 16px;color:var(--muted);font-size:.875rem}
.foot{margin-top:20px;text-align:center}
.passkey-list{list-style:none;margin:0 0 8px;padding:0}
.passkey-list li{display:flex;flex-wrap:wrap;align-items:baseline;gap:4px 8px;padding:10px 0;border-top:1px solid var(--border)}
.passkey-list li .muted{flex:1 1 100%}
.passkey-list .actions{display:flex;gap:8px}
.passkey-list .actions button{width:auto;margin-top:4px;padding:4px 12px;font-size:.875rem}
a.button{display:flex;justify-content:center;align-items:center;gap:8px;width:100%;margin-top:12px;padding:10px 16px;font-weight:600;border-radius:8px;border:1px solid var(--accent);background:var(--accent);color:var(--accent-fg);text-decoration:none}
a.button.secondary{background:transparent;color:var(--accent)}
.social-buttons a.button:first-child{margin-top:16px}
.badge{display:inline-block;margin-left:4px;padding:0 8px;border:1px solid var(--accent);border-radius:999px;color:var(--accent);font-size:.75rem;font-weight:600;line-height:1.5rem;vertical-align:middle}
.admin-links{margin:0 0 12px;font-size:.9rem}
`;
