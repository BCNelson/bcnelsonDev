/**
 * Static page JS served from GET /assets/<name>. Each page module registers
 * its script with `defineAsset` at import time and passes the returned path
 * to renderPage's `scripts`. Keeping JS out of the HTML lets the CSP forbid
 * inline scripts.
 */

import { Hono } from 'hono';
import { config } from '../config';
import type { AppEnv } from '../http';

const assets = new Map<string, string>();

const NAME = /^[a-z0-9-]+\.js$/;

/** Register `source` as /assets/<name> and return that path. Names must be unique. */
export function defineAsset(name: string, source: string): string {
  if (!NAME.test(name)) throw new Error(`Invalid asset name: ${name}`);
  if (assets.has(name) && assets.get(name) !== source) throw new Error(`Duplicate asset: ${name}`);
  assets.set(name, source);
  return `/assets/${name}`;
}

export const assetRoutes = new Hono<AppEnv>();

assetRoutes.get('/assets/:name', (c) => {
  const source = assets.get(c.req.param('name'));
  if (source === undefined) return c.json({ error: 'not_found' }, 404);
  return c.body(source, 200, {
    'Content-Type': 'text/javascript; charset=utf-8',
    'Cache-Control': `public, max-age=${config.ASSET_MAX_AGE}`,
    'X-Content-Type-Options': 'nosniff',
  });
});
