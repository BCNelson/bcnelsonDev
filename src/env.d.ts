/// <reference types="astro/client" />

type Runtime = import("@astrojs/cloudflare").Runtime<Env>;

interface Env {
  TURNSTILE_SECRET_KEY: string;
  TURNSTILE_SITE_KEY: string;
  CONTACT_EMAIL: {
    send: (message: EmailMessage) => Promise<void>;
  };
}

declare namespace App {
  interface Locals extends Runtime {}
}

declare class EmailMessage {
  constructor(from: string, to: string, raw: string);
}

declare module "cloudflare:email" {
  export { EmailMessage };
}
