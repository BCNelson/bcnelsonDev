/**
 * The Hono app, separate from the Worker entry (index.ts) so tests can build
 * it without `cloudflare:workers`' WorkerEntrypoint.
 */

import { Hono } from 'hono';
import { originCheck, type AppEnv } from './http';
import { assetRoutes } from './pages/assets';
import { adminRoutes } from './routes/admin';
import { loginRoutes } from './routes/login';
import { meRoutes } from './routes/me';
import { profileRoutes } from './routes/profile';
import { passkeyRoutes } from './routes/passkey';
import { passwordRoutes } from './routes/password';
import { sessionRoutes } from './routes/session';
import { signupRoutes } from './routes/signup';
import { oauthRoutes } from './routes/oauth';
import { wellknownRoutes } from './routes/wellknown';
import { clientAdminRoutes } from './oidc/admin-routes';
import { isOidcBackChannel, oidcRoutes } from './routes/oidc';

export function createApp(): Hono<AppEnv> {
  const app = new Hono<AppEnv>();

  // State-changing requests need an allowed Origin; /logout also accepts site origins.
  // POST /oauth/token and /userinfo are back-channel (no cookies) and skip it.
  const origin = originCheck({ sitePaths: ['/logout'] });
  app.use('*', (c, next) => (isOidcBackChannel(c.req.method, c.req.path) ? next() : origin(c, next)));

  app.route('/', wellknownRoutes);
  app.route('/', assetRoutes);
  app.route('/', sessionRoutes);
  app.route('/', signupRoutes);
  app.route('/', loginRoutes);
  app.route('/', adminRoutes);
  app.route('/', passwordRoutes);
  app.route('/', passkeyRoutes);
  app.route('/', profileRoutes);
  app.route('/', meRoutes);
  // After adminRoutes, so its /api/admin/* guard runs first.
  app.route('/', clientAdminRoutes);
  app.route('/', oidcRoutes);
  app.route('/', oauthRoutes);

  app.notFound((c) => c.json({ error: 'not_found' }, 404));
  return app;
}
