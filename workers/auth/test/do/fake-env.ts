/**
 * A fake Env for DO and route tests: DO namespaces backed by real User /
 * UserIndex instances over fakeState(), an EMAIL binding that records mail,
 * and switchable rate limiters. Pass the DO classes in (they must be imported
 * after vi.mock('cloudflare:workers')).
 */

import type { Env } from '../../src/env';
import { fakeState } from './fake-storage';

type DOClass = new (state: DurableObjectState, env: Env) => object;

export interface FakeNamespace {
  instances: Map<string, { instance: any; fake: ReturnType<typeof fakeState> }>;
  idFromName(name: string): string;
  get(id: string): any;
}

function fakeNamespace(cls: DOClass, env: () => Env): FakeNamespace {
  const instances: FakeNamespace['instances'] = new Map();
  return {
    instances,
    idFromName: (name) => name,
    get(id) {
      let entry = instances.get(id);
      if (!entry) {
        const fake = fakeState();
        entry = { instance: new cls(fake.state as unknown as DurableObjectState, env()), fake };
        instances.set(id, entry);
      }
      return entry.instance;
    },
  };
}

export interface SentMail {
  to: string;
  subject: string;
  text: string;
}

export interface FakeEnv {
  env: Env;
  mail: SentMail[];
  users: FakeNamespace;
  index: FakeNamespace;
  /** Flip to false to make the binding refuse. */
  limits: { ip: boolean; identifier: boolean };
  /** Make EMAIL.send throw. */
  failMail: { value: boolean };
}

export function makeFakeEnv(
  classes: { User: DOClass; UserIndex: DOClass },
  overrides: Partial<Env> = {},
): FakeEnv {
  const mail: SentMail[] = [];
  const limits = { ip: true, identifier: true };
  const failMail = { value: false };
  let env: Env;
  const users = fakeNamespace(classes.User, () => env);
  const index = fakeNamespace(classes.UserIndex, () => env);
  env = {
    ISSUER: 'https://auth.bcnelson.dev',
    COOKIE_DOMAIN: 'bcnelson.dev',
    RP_ID: 'bcnelson.dev',
    ALLOWED_ORIGINS: 'https://auth.bcnelson.dev',
    ADMIN_EMAILS: '',
    TURNSTILE_SITE_KEY: 'test-site-key',
    TURNSTILE_SECRET: { get: async () => 'prod-secret' },
    AUTH_SIGNING_KEY: { get: async () => { throw new Error('not in store'); } },
    RL_IP: { limit: async () => ({ success: limits.ip }) },
    RL_IDENTIFIER: { limit: async () => ({ success: limits.identifier }) },
    USER: users,
    USER_INDEX: index,
    EMAIL: {
      send: async (msg: { to: string; subject: string; text: string }) => {
        if (failMail.value) throw new Error('E_TEST');
        mail.push({ to: msg.to, subject: msg.subject, text: msg.text });
        return { messageId: 'm' };
      },
    },
    ...overrides,
  } as unknown as Env;
  return { env, mail, users, index, limits, failMail };
}

/** The 6-digit code in the most recent mail. */
export function lastCode(mail: SentMail[]): string {
  const match = /\b(\d{6})\b/.exec(mail.at(-1)?.text ?? '');
  if (!match) throw new Error('no code in last mail');
  return match[1]!;
}

/** Stand-in for crypto/password: `v2$<pw>` is current, `v1$<pw>` verifies but needs a rehash. */
export function fakePasswordModule() {
  return {
    hashPassword: async (password: string) => `v2$${password}`,
    verifyPassword: async (password: string, stored: string) => {
      if (stored === `v2$${password}`) return { ok: true, needsRehash: false };
      if (stored === `v1$${password}`) return { ok: true, needsRehash: true };
      return { ok: false, needsRehash: false };
    },
    verifyDummy: async (_password: string) => {
      dummyCalls.count++;
    },
    validatePasswordPolicy: (password: string) => (password.length < 8 ? 'too_short' : null),
  };
}

export const dummyCalls = { count: 0 };
