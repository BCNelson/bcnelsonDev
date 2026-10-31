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

// The Worker itself, its code and all of its bindings are deployed by wrangler
// (see wrangler.json). Cloudflare ties bindings to a script version, so any
// Pulumi resource that sets them also uploads script content.
const workerName = "bcnelson-dev";

// Turnstile secret, bound to the Worker through Secrets Store in wrangler.json
const secretsStoreId = config.require("secretsStoreId");
const turnstileSecret = new cloudflare.SecretsStoreSecret("turnstile-secret", {
  accountId: accountId,
  storeId: secretsStoreId,
  name: "TURNSTILE_SECRET",
  value: turnstileWidget.secret,
  scopes: ["workers"],
});

// Workers Custom Domain (routes traffic from domain to worker)
const workerDomain = new cloudflare.WorkersCustomDomain("bcnelson-dev-domain", {
  accountId: accountId,
  hostname: domain,
  service: workerName,
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
export { workerName };
export const workerUrl = pulumi.interpolate`https://${domain}`;
export const webAnalyticsToken = webAnalytics.siteToken;
// Public key; wrangler.json sets it as the TURNSTILE_SITE_KEY var
export const turnstileSiteKey = turnstileWidget.sitekey;
