/**
 * Outbound email. Production uses the Cloudflare Email Service `send_email`
 * binding (arbitrary recipients once the sending domain is onboarded); when the
 * binding is absent (tests, bare local runs) a dev mailer logs instead.
 */

import type { Env } from '../env';

export interface MailMessage {
  to: string;
  subject: string;
  text: string;
  html: string;
}

export interface Mailer {
  send(msg: MailMessage): Promise<void>;
}

export interface MailerOptions {
  /** Sender address; must be on an onboarded domain and in `allowed_sender_addresses`. */
  from?: string;
  /** Display name shown to recipients. */
  fromName?: string;
  /** Where the dev mailer writes; defaults to console.log. */
  log?: (line: string) => void;
}

export const DEFAULT_FROM = 'no-reply@bcnelson.dev';
export const DEFAULT_FROM_NAME = 'bcnelson.dev';

/** Thrown when Email Service rejects a send. `code` is Cloudflare's E_* code when present. */
export class MailError extends Error {
  readonly code: string | undefined;
  constructor(message: string, code?: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'MailError';
    this.code = code;
  }
}

/** Mailer backed by an Email Service binding. */
export function emailServiceMailer(binding: SendEmail, opts: MailerOptions = {}): Mailer {
  const from = { email: opts.from ?? DEFAULT_FROM, name: opts.fromName ?? DEFAULT_FROM_NAME };
  return {
    async send(msg) {
      try {
        await binding.send({ from, to: msg.to, subject: msg.subject, text: msg.text, html: msg.html });
      } catch (err) {
        const code = (err as { code?: unknown } | null)?.code;
        throw new MailError(
          `email send failed: ${(err as Error)?.message ?? String(err)}`,
          typeof code === 'string' ? code : undefined,
          { cause: err },
        );
      }
    },
  };
}

/** Mailer that only logs. Never use where real delivery is expected. */
export function devMailer(opts: MailerOptions = {}): Mailer {
  const log = opts.log ?? ((line: string) => console.log(line));
  const from = `${opts.fromName ?? DEFAULT_FROM_NAME} <${opts.from ?? DEFAULT_FROM}>`;
  return {
    async send(msg) {
      log(`[dev-mailer] From: ${from}\nTo: ${msg.to}\nSubject: ${msg.subject}\n\n${msg.text}`);
    },
  };
}

/** Email Service mailer when `env.EMAIL` is bound, otherwise the dev mailer. */
export function createMailer(env: Pick<Env, 'EMAIL'>, opts: MailerOptions = {}): Mailer {
  return env.EMAIL ? emailServiceMailer(env.EMAIL, opts) : devMailer(opts);
}
