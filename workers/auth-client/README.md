# @bcnelson/auth-client

Verifies `bcnelson.dev` access JWTs (the `bcn_at` cookie or a `Bearer` header) inside other
Cloudflare Workers. See `docs/auth-design.md` §3.

Create the client at module scope so the JWKS cache lives for the whole isolate.

## Worker (public JWKS over HTTPS)

```ts
import { createAuthClient } from '@bcnelson/auth-client';

const auth = createAuthClient(); // issuer https://auth.bcnelson.dev, audience bcnelson.dev

export default {
  async fetch(request: Request): Promise<Response> {
    const user = await auth.requireUser(request);
    if (user instanceof Response) return user; // 302 to /refresh, or 401 JSON
    return new Response(`Hello, ${user.username}`);
  },
};
```

## Worker with a service binding

```jsonc
// wrangler.jsonc
{ "services": [{ "binding": "AUTH", "service": "bcnelson-dev-auth" }] }
```

```ts
import { createAuthClient, type AuthClient } from '@bcnelson/auth-client';

interface Env { AUTH: Fetcher }

let auth: AuthClient | undefined;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    auth ??= createAuthClient({ service: env.AUTH }); // JWKS fetched via the binding
    const admin = await auth.requireRole(request, 'admin'); // 403 JSON without the role
    if (admin instanceof Response) return admin;
    return Response.json({ id: admin.id, roles: admin.roles });
  },
};
```

`getUser(request)` returns `AuthUser | null` without building a response.
`loginUrl(returnTo)` and `refreshUrl(returnTo)` build links to the auth Worker.

## SPA helper

```ts
import { getAccessToken } from '@bcnelson/auth-client/browser';

const token = await getAccessToken(); // null when signed out
if (!token) location.href = `https://auth.bcnelson.dev/login?return_to=${encodeURIComponent(location.href)}`;
await fetch('https://api.bcnelson.dev/things', { headers: { authorization: `Bearer ${token}` } });
```

The token is cached until shortly before `expires_at`, and concurrent calls share one request.
