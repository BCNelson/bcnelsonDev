/// <reference types="@cloudflare/workers-types" />
/**
 * Custom Cloudflare Worker entry point.
 * Handles /peer/* routes for WebRTC signaling and delegates everything else to Astro.
 */

import astro from '@astrojs/cloudflare/entrypoints/server';
import { PeerServer, handlePeerRequest, type PeerServerEnv } from './lib/peer-server';

// Re-export PeerServer for Cloudflare DO binding
export { PeerServer };

export default {
  async fetch(request: Request, env: PeerServerEnv, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // Handle /peer/* routes
    if (url.pathname.startsWith('/peer')) {
      return handlePeerRequest(request, env);
    }

    // Let Astro handle everything else
    return astro.fetch(request, env as unknown as Env, ctx);
  },
} satisfies ExportedHandler<PeerServerEnv>;
