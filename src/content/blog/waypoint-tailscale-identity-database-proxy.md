---
title: "Waypoint: Tailscale Identity Instead of Database Passwords"
description: "Why we built a database proxy at Redo that trusts Tailscale for identity, mints Postgres roles on the fly, and counts every byte."
pubDate: 2026-11-01
tags: ["tailscale", "postgres", "mongodb", "go", "databases"]
tldr:
  - "Tailscale already knows who is connecting, so the proxy asks it"
  - "No passwords on the client side"
  - "Auth and bandwidth limits live in one binary"
---

## The Password Problem

Here's how most teams give engineers access to a production database. Someone creates a user, by hand or in Terraform. The engineer gets a password and puts it in a `.pgpass` file, a password manager, or a Slack DM they promise to delete. Rotation is on someone's to-do list. Offboarding means remembering every database that person had access to.

At [Redo](https://redo.com), every engineer was already on our Tailscale tailnet, and the databases sat behind it. Tailscale knew exactly who was on the other end of each connection: which person, which device, which groups. Postgres had no idea. It just saw a username and a password.

So the identity question was already answered. We just needed something to carry that answer to the database.

That something is [Waypoint](https://gitlab.com/redo/open/waypoint), an MIT-licensed proxy written in Go. I wrote the long version of this story [on the Redo engineering blog](https://redo.com/eng-blog/waypoint). This is the short version.

## Ask Tailscale Who You Are

Waypoint joins the tailnet as its own node using `tsnet`. When a connection arrives, it asks the local Tailscale client who owns that address:

```go
who, err := lc.WhoIs(ctx, remoteAddr)
rules, err := tailcfg.UnmarshalCapJSON[CapRule](
    who.CapMap, "redo.com/cap/waypoint",
)
```

`WhoIs` returns the user, the device, and any *capability grants* the tailnet policy attaches to that connection. Grants are just JSON in the Tailscale ACL, so the access policy lives in the same place as the rest of our network policy:

```json
{
  "src": ["group:engineer"],
  "dst": ["tag:waypoint"],
  "app": {
    "redo.com/cap/waypoint": [{
      "backends": {
        "pg-production": {
          "pg": { "databases": { "redo": { "permissions": ["readonly"] } } },
          "limits": { "bandwidth": [{ "bytes": 1073741824, "period": "1h" }] }
        }
      }
    }]
  }
}
```

Read that as: engineers get read-only access to the `redo` database, capped at 1 GiB per hour. A smaller group gets `readwrite`. Nobody has a password. When someone leaves, removing them from the tailnet removes their database access too.

## Minting Roles Without Melting the Database

Postgres still needs a role to run queries as. The obvious approach is to create a fresh role for each connection, grant it privileges, and drop it later. On CockroachDB, that's a lot of schema changes on the connection path, and schema changes are expensive.

So Waypoint splits the work in two:

- **A shared group role** per preset, schema, and database, like `wp_grp_readonly_public_redo`. It holds all the `GRANT`s and is created once.
- **A thin login role** per user and device, like `wp_alice_macbook_redo`. It's just a member of the group.

Whether a group is ready is cached in Redis. Most connections skip the `GRANT`s entirely. When several replicas race to create the same group, a short Redis lock makes sure only one of them does the work. If the lock can't be taken, the client gets a clean error instead of hanging.

MongoDB Atlas doesn't allow creating users per connection, so there Waypoint authenticates the human with Tailscale and then logs in to the backend as one of two static users. The database logs lose the person's name, but Waypoint's logs keep it.

## Why Bandwidth Is in the Same Binary

The second half of Waypoint is a per-user bandwidth cap. That sounds like a separate project, but it needs the same two things as auth:

1. A trusted answer to "who is this?"
2. Shared state about that person across every proxy replica.

If you build those twice, once for auth and once in a rate limiter, you end up with two identity models that slowly drift apart. Putting both in one proxy means one identity, one source of truth.

How the counting works without a Redis call per packet is fun enough that it gets [its own post](/blog/sliding-window-bandwidth-limits-redis).

## The Tricky Part of MongoDB

With MongoDB, the wire protocol wasn't the tricky part. The driver was. A MongoDB driver connects to whatever replica set members the server lists in its `hello` reply, which would send it around the proxy. So Waypoint rewrites every address in that reply to point back at itself, `primary` and `me` included. Miss one, and the driver decides the server is lying and marks it down.

## Where It Is Now

Waypoint has been running in production at Redo since May 2026. It runs as two small replicas on EKS behind a Tailscale Service. Since the original writeup it has grown a few more modes:

- **Kubernetes**: proxies the API server and impersonates your Tailscale identity, so cluster RBAC just works
- **TCP**: a plain L4 proxy for anything else
- **Web console**: a browser SQL console on the tailnet with no login at all
- **Query logging**: optional, per listener, and it never blocks the relay

If you want to try it without a tailnet, the repo has a `console-demo` script. It starts a mock control plane and a throwaway Postgres.

One honest caveat: if you don't need per-user bandwidth limits, look at [Border0](https://www.border0.com/) first. Tailscale bought it, and it covers much of the identity side. The bandwidth cap is what kept us building our own.

The code is at [gitlab.com/redo/open/waypoint](https://gitlab.com/redo/open/waypoint).
