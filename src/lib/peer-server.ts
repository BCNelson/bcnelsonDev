/// <reference types="@cloudflare/workers-types" />
/**
 * PeerJS-compatible signaling server using Cloudflare Durable Objects.
 *
 * Architecture: One Durable Object per peer ID, each holding one WebSocket connection.
 * Messages are routed via DO-to-DO calls for peer-to-peer signaling.
 */

// Crockford Base32 alphabet (excludes I, L, O, U to avoid visual confusion)
const CROCKFORD_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

function generateShortId(bits: number = 40): string {
  const bytes = Math.ceil(bits / 8);
  const array = new Uint8Array(bytes);
  crypto.getRandomValues(array);

  let num = 0n;
  for (let i = 0; i < array.length; i++) {
    num = (num << 8n) | BigInt(array[i]);
  }

  const chars = Math.ceil(bits / 5);
  let result = '';
  for (let i = 0; i < chars; i++) {
    const index = Number(num & 31n);
    result = CROCKFORD_ALPHABET[index] + result;
    num = num >> 5n;
  }

  return result;
}

interface PeerMessage {
  type: 'OPEN' | 'HEARTBEAT' | 'CANDIDATE' | 'OFFER' | 'ANSWER' | 'LEAVE' | 'EXPIRE' | 'ERROR';
  src?: string;
  dst?: string;
  payload?: unknown;
}

export interface PeerServerEnv {
  PEER_SERVER: DurableObjectNamespace;
}

// PeerJS-compatible signaling server Durable Object
export class PeerServer implements DurableObject {
  private peerId: string | null = null;
  private env: PeerServerEnv;
  private ctx: DurableObjectState;

  constructor(ctx: DurableObjectState, env: PeerServerEnv) {
    this.ctx = ctx;
    this.env = env;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    // Handle relay messages from other DOs
    if (url.pathname === '/relay') {
      const msg = await request.json() as PeerMessage;
      const webSockets = this.ctx.getWebSockets();

      for (const ws of webSockets) {
        try {
          ws.send(JSON.stringify(msg));
        } catch {
          // WebSocket might be closed
        }
      }

      return new Response('OK');
    }

    // Handle WebSocket upgrade
    if (request.headers.get('Upgrade') === 'websocket') {
      const peerId = url.searchParams.get('id');

      if (!peerId) {
        return new Response('Missing peer ID', { status: 400 });
      }

      this.peerId = peerId;

      // Close any existing connections (one connection per peer)
      const existingWs = this.ctx.getWebSockets();
      for (const ws of existingWs) {
        try {
          ws.close(1000, 'New connection');
        } catch {
          // Ignore close errors
        }
      }

      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);

      this.ctx.acceptWebSocket(server);

      // Send OPEN message to confirm connection
      server.send(JSON.stringify({
        type: 'OPEN',
        payload: { peerId }
      }));

      return new Response(null, {
        status: 101,
        webSocket: client,
      });
    }

    return new Response('Expected WebSocket', { status: 400 });
  }

  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    if (typeof message !== 'string') {
      return;
    }

    let data: PeerMessage;
    try {
      data = JSON.parse(message);
    } catch {
      return;
    }

    if (data.type === 'HEARTBEAT') {
      return;
    }

    if (data.dst) {
      try {
        const targetId = this.env.PEER_SERVER.idFromName(data.dst);
        const targetStub = this.env.PEER_SERVER.get(targetId);

        await targetStub.fetch(new Request('http://internal/relay', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            ...data,
            src: this.peerId
          })
        }));
      } catch {
        ws.send(JSON.stringify({
          type: 'ERROR',
          payload: { msg: 'Could not reach peer' }
        }));
      }
    }
  }

  async webSocketClose(): Promise<void> {
    this.peerId = null;
  }

  async webSocketError(): Promise<void> {
    this.peerId = null;
  }
}

// CORS headers
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

// Handle /peer/* routes
export function handlePeerRequest(request: Request, env: PeerServerEnv): Response | Promise<Response> {
  const url = new URL(request.url);
  let pathname = url.pathname;

  // Remove /peer prefix
  if (pathname.startsWith('/peer')) {
    pathname = pathname.slice(5) || '/';
  }

  // Handle CORS preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  // Generate new peer ID
  if (pathname === '/id' || pathname === '/peerjs/id') {
    const id = generateShortId(40);
    return new Response(JSON.stringify({ id }), {
      headers: {
        'Content-Type': 'application/json',
        ...corsHeaders
      }
    });
  }

  // WebSocket connection endpoint
  if (pathname === '/' || pathname === '/peerjs') {
    const peerId = url.searchParams.get('id');

    if (!peerId) {
      return new Response('Missing peer ID', {
        status: 400,
        headers: corsHeaders
      });
    }

    const id = env.PEER_SERVER.idFromName(peerId);
    const stub = env.PEER_SERVER.get(id);

    const doUrl = new URL(request.url);
    doUrl.pathname = '/';

    return stub.fetch(new Request(doUrl, request));
  }

  return new Response('Not found', {
    status: 404,
    headers: corsHeaders
  });
}
