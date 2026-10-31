/// <reference types="astro/client" />

interface Env {
  TURNSTILE_SECRET_KEY: string;
  TURNSTILE_SITE_KEY: string;
  CONTACT_EMAIL: {
    send: (message: EmailMessage) => Promise<void>;
  };
}

declare class EmailMessage {
  constructor(from: string, to: string, raw: string);
}

declare module "cloudflare:email" {
  export { EmailMessage };
}
