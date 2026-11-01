---
title: "Per-User Bandwidth Limits With a Sliding Window in Redis"
description: "How Waypoint caps each engineer at 1 GiB per hour across every proxy replica, without a Redis call per packet."
pubDate: 2026-11-01
tags: ["redis", "lua", "go", "rate-limiting", "databases"]
tldr:
  - "One atomic add per packet on the hot path"
  - "Flush to Redis every 10 seconds"
  - "~360 sub-buckets per window, ~0.28% worst-case error"
---

## The Requirement

[Waypoint](/blog/waypoint-tailscale-identity-database-proxy) is the database proxy we run at Redo. Every engineer gets read-only production access, with a limit: **1 GiB per hour, per person**. That's plenty for debugging. It's not enough to accidentally `SELECT *` the orders table onto your laptop.

The catch is that Waypoint runs as several replicas. Alice's laptop might have three connections open, each landing on a different replica. The limit is per person, not per connection or per replica, so the replicas have to agree on how much Alice has used.

## Things That Don't Work

**Divide the limit by the replica count.** Give each replica a third of the budget. Then Alice hits her limit after 333 MiB because all her traffic happened to land on one replica. Scaling up quietly shrinks everyone's limit.

**Token buckets with gossip.** Now you're building a distributed system inside your proxy. No thanks.

**Ask Redis on every packet.** Correct, and slow. A database result set is a lot of packets.

## Count Locally, Flush Occasionally

The hot path is one atomic add:

```go
cl.pendingBytes.Add(int64(n))
```

A background goroutine flushes `pendingBytes` to Redis every 10 seconds, and again when the connection closes. Redis sends back the window total. If it's over the limit, the connection is torn down.

That means a burst can overshoot by up to one flush interval of traffic. For a "don't download the whole database" guard, that's a fine trade.

## The Window

A fixed window ("bytes used since 2:00") has an ugly edge: you can spend the whole budget at 2:59 and again at 3:00. A true sliding window would need a timestamp per write. The middle ground is a sliding window made of sub-buckets.

Each user's window is a Redis hash. Field names are bucket IDs (time divided by bucket size), and values are bytes. Waypoint targets about 360 buckets per window, so a 1-hour window uses 10-second buckets:

```go
// Targets ~360 sub-buckets per period, with a minimum of 10 seconds.
func bucketSize(period time.Duration) int64 {
	size := int64(period.Seconds()) / 360
	// ...
}
```

The window total is the sum of every bucket newer than `now - period`. The worst-case error is one bucket out of 360, about 0.28%. Why 360? It's the smallest number where I stopped seeing a staircase in the monitoring graphs. There's no deeper science.

Memory is cheap too: a few hundred small hash fields per user, a few KB each.

## One Lua Script Does It All

The flush needs to add bytes, sum the live buckets, and delete expired ones, all atomically. That's a job for a Lua script:

```lua
-- KEYS[1] = waypoint:bw:3600:{alice}/pg-production
-- ARGV    = bytes, current_bucket, min_bucket, ttl
redis.call('HINCRBY', KEYS[1], ARGV[2], tonumber(ARGV[1]))
redis.call('EXPIRE',  KEYS[1], tonumber(ARGV[4]))

local all = redis.call('HGETALL', KEYS[1])
local total, expired = 0, {}
for i = 1, #all, 2 do
    if tonumber(all[i]) >= tonumber(ARGV[3]) then
        total = total + tonumber(all[i + 1])
    else
        expired[#expired + 1] = all[i]
    end
end
if #expired > 0 then redis.call('HDEL', KEYS[1], unpack(expired)) end
return total
```

The bucket cleanup happens as part of the write, so there's no separate sweeper job to run.

## Limits Within Limits

We wanted two caps: one per database, and one across all databases. The production script takes a list of keys from leaf to root and runs the same loop on each:

```
waypoint:bw:3600:{alice}/pg-production   ← per-backend cap
waypoint:bw:3600:{alice}                 ← global cap
```

The `{alice}` part is a Redis Cluster hash tag. Every key for one user lands in the same slot, so a single Lua script can touch all of them without `CROSSSLOT` errors.

Connection-count limits use the same key layout. Their script checks both levels and returns a decision code: `0` for OK, `1` for the per-backend limit, `2` for the global limit. Checking and incrementing in one script matters. Without it, a burst of connections all increment, all see the limit exceeded, and all fail.

Switching to hierarchical keys was a small patch, and it made all the limit math feel obvious. If I were starting over, I'd begin there.

## What It Costs

Redis (Valkey, in our case) is now a tier-zero dependency. If it's down, new connections are refused. We decided failing closed was the right call for production data access. Because the proxy sits in the same availability zone as Redis, the check on each new connection stays under a millisecond.

The code is in [`internal/restrict/redis.go`](https://gitlab.com/redo/open/waypoint/-/blob/main/internal/restrict/redis.go) if you want to read the real thing.
