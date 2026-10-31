import { env } from "cloudflare:workers";

export const prerender = false;

export async function GET() {
  const siteKey = env.TURNSTILE_SITE_KEY ?? "";

  return new Response(JSON.stringify({ siteKey }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}
