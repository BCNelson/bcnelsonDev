import * as pulumi from "@pulumi/pulumi";
import * as cloudflare from "@pulumi/cloudflare";

const config = new pulumi.Config();

// Site configuration
const domain = config.require("domain");
const contactEmail = config.require("contactEmail"); // e.g., pulumi config set contactEmail bradley@nel.family

// Cloudflare credentials (read automatically or from config)
const accountId = config.requireSecret("cloudflareAccountId");
const zoneId = config.requireSecret("cloudflareZoneId");
// Note: CLOUDFLARE_API_TOKEN is read automatically by the Cloudflare provider
// Set it with: pulumi config set --secret cloudflare:apiToken <token>

// Cloudflare Turnstile Widget for contact form bot protection
// Created before the Worker so we can bind the secret to the Worker
const turnstileWidget = new cloudflare.TurnstileWidget("bcnelson-dev-turnstile", {
  accountId: accountId,
  name: "bcnelson.dev Contact Form",
  domains: [domain, `www.${domain}`, "localhost"],
  mode: "managed",
});

// Enable Email Routing on the zone (required for send_email binding)
const emailRouting = new cloudflare.EmailRoutingSettings(
  "bcnelson-dev-email-routing",
  {
    zoneId: zoneId,
  }
);

// Email Routing destination address for contact form
// This triggers a verification email - you must click the link to verify
const contactEmailDestination = new cloudflare.EmailRoutingAddress(
  "contact-form-destination",
  {
    accountId: accountId,
    email: contactEmail,
  }
);

// Cloudflare Worker Script
// Note: The actual script content is deployed via `wrangler deploy`
// This resource manages bindings only - content is ignored to prevent overwriting wrangler deploys
const workerScript = new cloudflare.WorkersScript(
  "bcnelson-dev-worker",
  {
    accountId: accountId,
    scriptName: "bcnelson-dev",
    content:
      "export default { fetch() { return new Response('Deployed via Wrangler'); } }",
    mainModule: "index.js",
    compatibilityDate: "2025-01-01",
    compatibilityFlags: ["nodejs_compat"],
    bindings: [
      {
        name: "TURNSTILE_SECRET_KEY",
        type: "secret_text",
        text: turnstileWidget.secret,
      },
      {
        name: "TURNSTILE_SITE_KEY",
        type: "plain_text",
        text: turnstileWidget.sitekey,
      },
      {
        name: "CONTACT_EMAIL",
        type: "send_email",
        destinationAddress: contactEmail,
      },
    ],
    // Keep bindings when wrangler deploys new code
    keepBindings: ["secret_text", "plain_text", "send_email"],
  },
  {
    // Don't overwrite the actual site content deployed by wrangler
    ignoreChanges: ["content"],
  }
);

// Workers Custom Domain (routes traffic from domain to worker)
const workerDomain = new cloudflare.WorkersCustomDomain("bcnelson-dev-domain", {
  accountId: accountId,
  hostname: domain,
  service: workerScript.scriptName,
  zoneId: zoneId,
});

// www CNAME pointing to apex (redirect handled by Cloudflare automatically when proxied)
const wwwRecord = new cloudflare.DnsRecord("www-redirect", {
  zoneId: zoneId,
  name: "www",
  type: "CNAME",
  content: domain,
  proxied: true,
  ttl: 1,
});

// Cloudflare Web Analytics
// Note: autoInstall only works with Pages, not Workers
// The analytics script must be added manually to the site
const webAnalytics = new cloudflare.WebAnalyticsSite("bcnelson-dev-analytics", {
  accountId: accountId,
  host: domain,
  autoInstall: false,
});

// Exports
export const workerName = workerScript.scriptName;
export const workerUrl = pulumi.interpolate`https://${domain}`;
export const workersDevUrl = pulumi.interpolate`https://bcnelson-dev.${accountId}.workers.dev`;
export const webAnalyticsToken = webAnalytics.siteToken;
// Note: Turnstile keys are bound directly to the Worker, no need to export them
