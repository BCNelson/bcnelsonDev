/**
 * Auth Worker entry: Hono app, Durable Object classes, and the RPC entrypoint
 * for service-binding consumers.
 */

import { WorkerEntrypoint } from 'cloudflare:workers';
import type { JSONWebKeySet } from 'jose';
import { createApp } from './app';
import type { Env } from './env';
import { getJwks } from './tokens';

export { UserIndex } from './do/user-index';
export { User } from './do/user';

const app = createApp();

/** RPC entrypoint for other Workers (service binding with `entrypoint: "AuthService"`). */
export class AuthService extends WorkerEntrypoint<Env> {
  async jwks(): Promise<JSONWebKeySet> {
    return getJwks(this.env);
  }

  override async fetch(request: Request): Promise<Response> {
    return app.fetch(request, this.env, this.ctx);
  }
}

export default {
  fetch: (request, env, ctx) => app.fetch(request, env, ctx),
} satisfies ExportedHandler<Env>;
