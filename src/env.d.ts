/// <reference types="astro/client" />

// Bindings typed on Cloudflare.Env so `env` from "cloudflare:workers" sees them
declare namespace Cloudflare {
  interface Env {
    TURNSTILE_SECRET_KEY: string;
    TURNSTILE_SITE_KEY: string;
    CONTACT_EMAIL: {
      send: (message: EmailMessage) => Promise<void>;
    };
  }
}

interface Env extends Cloudflare.Env {}

declare class EmailMessage {
  constructor(from: string, to: string, raw: string);
}

declare module "cloudflare:email" {
  export { EmailMessage };
}
