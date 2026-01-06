import * as pulumi from "@pulumi/pulumi";
import * as cloudflare from "@pulumi/cloudflare";

const config = new pulumi.Config();
const domain = config.require("domain");

// Get credentials from Pulumi config secrets
const accountId = config.requireSecret("cloudflareAccountId");
const zoneId = config.requireSecret("cloudflareZoneId");
// Note: CLOUDFLARE_API_TOKEN is read automatically by the Cloudflare provider
// Set it with: pulumi config set --secret cloudflare:apiToken <token>

// Cloudflare Pages Project
const pagesProject = new cloudflare.PagesProject("bcnelson-dev", {
  accountId: accountId,
  name: "bcnelson-dev",
  productionBranch: "main",
  buildConfig: {
    buildCommand: "npm run build",
    destinationDir: "dist",
    rootDir: "/",
  },
  source: {
    type: "github",
    config: {
      owner: "bcnelson",
      repoName: "bcnelsonDev",
      productionBranch: "main",
      productionDeploymentsEnabled: true,
      previewDeploymentsEnabled: true,
      previewBranchIncludes: ["*"],
      previewBranchExcludes: ["main"],
    },
  },
  deploymentConfigs: {
    production: {
      compatibilityDate: "2025-01-01",
      compatibilityFlags: ["nodejs_compat"],
      failOpen: false,
      environmentVariables: {
        NODE_VERSION: "20",
      },
    },
    preview: {
      compatibilityDate: "2025-01-01",
      compatibilityFlags: ["nodejs_compat"],
      failOpen: true,
    },
  },
});

// Custom domain for Pages
const pagesDomain = new cloudflare.PagesDomain("bcnelson-dev-domain", {
  accountId: accountId,
  projectName: pagesProject.name,
  domain: domain,
});

// DNS CNAME record pointing to Pages
const dnsRecord = new cloudflare.Record("bcnelson-dev-cname", {
  zoneId: zoneId,
  name: domain,
  type: "CNAME",
  content: pulumi.interpolate`${pagesProject.name}.pages.dev`,
  proxied: true,
  ttl: 1, // Auto TTL when proxied
});

// www redirect CNAME
const wwwRecord = new cloudflare.Record("www-redirect", {
  zoneId: zoneId,
  name: "www",
  type: "CNAME",
  content: domain,
  proxied: true,
  ttl: 1,
});

// Cloudflare Web Analytics
const webAnalytics = new cloudflare.WebAnalyticsSite("bcnelson-dev-analytics", {
  accountId: accountId,
  host: domain,
  autoInstall: true, // Cloudflare auto-injects the beacon script
});

// Exports
export const pagesProjectName = pagesProject.name;
export const pagesUrl = pulumi.interpolate`https://${pagesDomain.domain}`;
export const pagesDevUrl = pulumi.interpolate`https://${pagesProject.name}.pages.dev`;
export const webAnalyticsToken = webAnalytics.siteToken;
