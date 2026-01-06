import * as pulumi from "@pulumi/pulumi";
import * as cloudflare from "@pulumi/cloudflare";

const config = new pulumi.Config();
const domain = config.require("domain");

// Get credentials from Pulumi config secrets
const accountId = config.requireSecret("cloudflareAccountId");
const zoneId = config.requireSecret("cloudflareZoneId");
// Note: CLOUDFLARE_API_TOKEN is read automatically by the Cloudflare provider
// Set it with: pulumi config set --secret cloudflare:apiToken <token>

// Cloudflare Worker Script
// Note: The actual script content is deployed via `wrangler deploy` in CI
// This resource manages the worker's existence and settings
const workerScript = new cloudflare.WorkersScript("bcnelson-dev-worker", {
  accountId: accountId,
  scriptName: "bcnelson-dev",
  content: "export default { fetch() { return new Response('Deployed via Wrangler'); } }",
  mainModule: "index.js",
  compatibilityDate: "2025-01-01",
  compatibilityFlags: ["nodejs_compat"],
});

// Workers Custom Domain (routes traffic from domain to worker)
const workerDomain = new cloudflare.WorkerDomain("bcnelson-dev-domain", {
  accountId: accountId,
  hostname: domain,
  service: workerScript.scriptName,
  zoneId: zoneId,
});

// www redirect - CNAME to apex, handled by worker or page rule
const wwwRecord = new cloudflare.Record("www-redirect", {
  zoneId: zoneId,
  name: "www",
  type: "CNAME",
  content: domain,
  proxied: true,
  ttl: 1,
});

// Redirect www to apex domain
const wwwRedirectRule = new cloudflare.Ruleset("www-redirect-rule", {
  zoneId: zoneId,
  name: "Redirect www to apex",
  kind: "zone",
  phase: "http_request_dynamic_redirect",
  rules: [{
    action: "redirect",
    actionParameters: {
      fromValue: {
        statusCode: 301,
        targetUrl: {
          expression: `concat("https://${domain}", http.request.uri.path)`,
        },
      },
    },
    expression: `(http.host eq "www.${domain}")`,
    description: "Redirect www to apex domain",
    enabled: true,
  }],
});

// Cloudflare Web Analytics
const webAnalytics = new cloudflare.WebAnalyticsSite("bcnelson-dev-analytics", {
  accountId: accountId,
  host: domain,
  autoInstall: true,
});

// Exports
export const workerName = workerScript.scriptName;
export const workerUrl = pulumi.interpolate`https://${domain}`;
export const workersDevUrl = pulumi.interpolate`https://bcnelson-dev.${accountId}.workers.dev`;
export const webAnalyticsToken = webAnalytics.siteToken;
