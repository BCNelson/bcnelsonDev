import type { APIContext } from "astro";

export async function GET(context: APIContext) {
  const env = context.locals.runtime?.env as { TURNSTILE_SITE_KEY?: string } | undefined;
  const siteKey = env?.TURNSTILE_SITE_KEY ?? "";

  return new Response(JSON.stringify({ siteKey }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}
