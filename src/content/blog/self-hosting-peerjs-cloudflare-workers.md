---
title: "Self-Hosting PeerJS on Cloudflare Workers"
description: "Build a PeerJS-compatible signaling server using Cloudflare Durable Objects for serverless WebRTC peer discovery."
pubDate: 2026-02-06
tags: ["webrtc", "cloudflare", "peerjs", "durable-objects", "typescript"]
tldr:
  - "One Durable Object per peer ID"
  - "~200 lines of TypeScript"
  - "Drop-in replacement for PeerJS server"
---

## The Problem With Browsers

Alice wants to call Bob. Simple, right?

Except browsers don't have phone numbers. There's no directory. Alice can't just dial `bob.local` and hope for the best. Both of them are hiding behind NATs, firewalls, and layers of networking that actively prevent incoming connections.

WebRTC solves the *connection* part—once two browsers know about each other, they can punch through most NATs and talk directly. But someone has to introduce them first.

That's what a signaling server does. It's the friend who says "Alice, meet Bob. Bob, Alice." Then it gets out of the way.

## How the Introduction Works

Let's walk through it.

### Alice Shows Up

Alice opens the page and gets assigned an ID—something like `7KXNQ3M2`. Short enough to read over the phone. I use Crockford Base32, which drops letters that look like numbers (no I, L, O, or U).

```typescript
const id = generateShortId(40);
return new Response(JSON.stringify({ id }));
```

Her browser opens a WebSocket to the signaling server. Behind the scenes, this spins up a Durable Object just for her:

```typescript
const id = env.PEER_SERVER.idFromName(peerId);
const stub = env.PEER_SERVER.get(id);
return stub.fetch(request);
```

One object, one peer, one WebSocket. The object attaches her ID to the connection (so it survives if the DO hibernates) and confirms she's in:

```typescript
this.ctx.acceptWebSocket(server);
server.serializeAttachment({ peerId });

server.send(JSON.stringify({ type: 'OPEN', payload: { peerId } }));
```

Alice is connected. Now she waits.

### Bob Comes Knocking

Alice texts Bob her ID. He types it in, and his browser wants to connect. It creates an *offer*—a blob describing what kind of call this is (video? audio? data?)—and sends it to the signaling server addressed to Alice:

```json
{ "type": "OFFER", "src": "RTKP5WN9", "dst": "7KXNQ3M2", "payload": { "sdp": "..." } }
```

Bob's Durable Object receives this. It needs to get the message to Alice's Durable Object. Here's the trick: it just *calls her directly*:

```typescript
const { peerId } = ws.deserializeAttachment() as { peerId: string };
const targetStub = this.env.PEER_SERVER.get(
  this.env.PEER_SERVER.idFromName(data.dst)
);

await targetStub.fetch(new Request('http://internal/relay', {
  method: 'POST',
  body: JSON.stringify({ ...data, src: peerId })
}));
```

Alice's DO receives this at `/relay` and shoves it down her WebSocket. The offer lands in her browser.

### The Dance

Alice's browser crafts an *answer* and sends it back the same way. Then comes the real work: ICE candidates.

Both browsers start probing. "Can you reach me at this IP? What about this port? Through this TURN server?" Each candidate bounces through the signaling server:

```json
{ "type": "CANDIDATE", "src": "7KXNQ3M2", "dst": "RTKP5WN9", "payload": { "candidate": "..." } }
```

Eventually, one path works. The browsers connect directly. Video starts flowing.

The signaling server's job is done. Alice and Bob are talking peer-to-peer now—no middleman, no relay, just two browsers that finally found each other.

### When It Doesn't Work

Sometimes the NAT punching fails. Symmetric NATs, strict corporate firewalls, carrier-grade NAT—there are plenty of network configurations that refuse to cooperate.

When that happens, you need a TURN server to relay the actual media traffic. The signaling server can't help here; it only handles the introduction. The data itself needs somewhere to bounce through.

If you want to understand the full picture of NAT traversal—STUN, TURN, ICE, and all the edge cases—Tailscale wrote [an excellent deep dive](https://tailscale.com/blog/how-nat-traversal-works). It's about their VPN, but the fundamentals apply to WebRTC too.

## Why Durable Objects?

The architecture writes itself:

- **One DO per peer** — Alice gets one, Bob gets one
- **One WebSocket per DO** — Simple state management
- **DO-to-DO calls** — No shared database, no pub/sub, no Redis

The neat part: Alice and Bob don't need to hit the same server. Cloudflare routes between DOs transparently. Alice could be connecting through Frankfurt, Bob through Tokyo. Doesn't matter.

## Wiring It Up

The `wrangler.json` config:

```json
{
  "durable_objects": {
    "bindings": [
      { "name": "PEER_SERVER", "class_name": "PeerServer" }
    ]
  },
  "migrations": [
    { "tag": "v1", "new_classes": ["PeerServer"] }
  ]
}
```

And the standard PeerJS client just works:

```typescript
const peer = new Peer({
  host: 'your-domain.com',
  path: '/peer',
  secure: true,
});
```

No special client. No forked library. Point it at your domain and go.

## That's It

~200 lines of TypeScript. A signaling server that scales globally, hibernates when idle, and works with vanilla PeerJS.

[Full source code](https://github.com/bcnelson/bcnelsonDev/blob/main/src/lib/peer-server.ts)
