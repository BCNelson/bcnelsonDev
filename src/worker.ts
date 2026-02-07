/// <reference types="@cloudflare/workers-types" />
/**
 * Custom Cloudflare Worker entry point.
 * Handles /peer/* routes for WebRTC signaling and delegates everything else to Astro.
 */

import type { SSRManifest } from 'astro';
import { createExports as createAstroExports } from '@astrojs/cloudflare/entrypoints/server.js';
import { PeerServer, handlePeerRequest, type PeerServerEnv } from './lib/peer-server';

// Re-export PeerServer for Cloudflare DO binding
export { PeerServer };

interface Env extends PeerServerEnv {
  ASSETS: Fetcher;
}

// Create exports for Astro Cloudflare adapter
export function createExports(manifest: SSRManifest) {
  const astroExports = createAstroExports(manifest);
  const astroFetch = astroExports.default.fetch;

  const fetch = async (request: Request, env: Env, ctx: ExecutionContext): Promise<Response> => {
    const url = new URL(request.url);

    // Handle /peer/* routes
    if (url.pathname.startsWith('/peer')) {
      return handlePeerRequest(request, env);
    }

    // Let Astro handle everything else
    return astroFetch(request, env, ctx);
  };

  return {
    default: { fetch },
    PeerServer,
  };
}
