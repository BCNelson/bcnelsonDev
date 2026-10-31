/**
 * A software WebAuthn authenticator for tests: a real ES256 key pair
 * (WebCrypto), 'none' attestation, and DER-encoded assertion signatures, so
 * @simplewebauthn/server verifies the payloads with real crypto.
 */

import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server';
import { isoBase64URL, isoCBOR } from '@simplewebauthn/server/helpers';

const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const FLAG_BE = 0x08;
const FLAG_BS = 0x10;
const FLAG_AT = 0x40;

/** A made-up AAGUID; iCloud Keychain's when `aaguid: 'icloud'`. */
const AAGUIDS = {
  zero: '00000000-0000-0000-0000-000000000000',
  icloud: 'fbfc3007-154e-4ecc-8c0b-6e020557d7bd',
};

export interface AuthenticatorOptions {
  origin?: string;
  rpId?: string;
  /** Synced (multi-device, backed up) passkey. */
  synced?: boolean;
  aaguid?: keyof typeof AAGUIDS;
}

function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let i = 0;
  for (const p of parts) {
    out.set(p, i);
    i += p.length;
  }
  return out;
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(data)));
}

function u32(n: number): Uint8Array {
  return new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
}

function aaguidBytes(uuid: string): Uint8Array {
  const hex = uuid.replace(/-/g, '');
  return new Uint8Array(hex.match(/../g)!.map((h) => parseInt(h, 16)));
}

/** IEEE P1363 r||s → ASN.1 DER SEQUENCE { INTEGER r, INTEGER s }. */
function derSignature(raw: Uint8Array): Uint8Array {
  const int = (bytes: Uint8Array) => {
    let b = bytes;
    while (b.length > 1 && b[0] === 0 && b[1]! < 0x80) b = b.slice(1);
    if (b[0]! >= 0x80) b = concat(new Uint8Array([0]), b);
    return concat(new Uint8Array([0x02, b.length]), b);
  };
  const body = concat(int(raw.slice(0, 32)), int(raw.slice(32)));
  return concat(new Uint8Array([0x30, body.length]), body);
}

function b64(bytes: Uint8Array): string {
  return isoBase64URL.fromBuffer(new Uint8Array(bytes));
}

export class SoftAuthenticator {
  readonly origin: string;
  readonly rpId: string;
  readonly credentialId = crypto.getRandomValues(new Uint8Array(16));
  counter = 0;
  /** Set by register(): the userHandle (user.id) the passkey was created for. */
  userHandle: string | null = null;
  private keys: CryptoKeyPair | null = null;

  constructor(private opts: AuthenticatorOptions = {}) {
    this.origin = opts.origin ?? 'https://auth.bcnelson.dev';
    this.rpId = opts.rpId ?? 'bcnelson.dev';
  }

  get id(): string {
    return b64(this.credentialId);
  }

  private flags(extra: number): number {
    return FLAG_UP | FLAG_UV | extra | (this.opts.synced ? FLAG_BE | FLAG_BS : 0);
  }

  /** navigator.credentials.create() for server options; returns RegistrationResponseJSON. */
  async register(options: { challenge: string; user: { id: string }; rp?: { id?: string } }): Promise<RegistrationResponseJSON> {
    this.keys = (await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'],
    )) as CryptoKeyPair;
    const jwk = (await crypto.subtle.exportKey('jwk', this.keys.publicKey)) as JsonWebKey;
    const cose = isoCBOR.encode(new Map<number, number | Uint8Array>([
      [1, 2], // kty: EC2
      [3, -7], // alg: ES256
      [-1, 1], // crv: P-256
      [-2, isoBase64URL.toBuffer(jwk.x!)],
      [-3, isoBase64URL.toBuffer(jwk.y!)],
    ]));
    const rpIdHash = await sha256(new TextEncoder().encode(options.rp?.id ?? this.rpId));
    const authData = concat(
      rpIdHash,
      new Uint8Array([this.flags(FLAG_AT)]),
      u32(this.counter),
      aaguidBytes(AAGUIDS[this.opts.aaguid ?? 'zero']),
      new Uint8Array([this.credentialId.length >> 8, this.credentialId.length & 255]),
      this.credentialId,
      cose,
    );
    const attestationObject = isoCBOR.encode(new Map<string, string | Uint8Array | Map<string, never>>([
      ['fmt', 'none'],
      ['attStmt', new Map<string, never>()],
      ['authData', authData],
    ]));
    const clientDataJSON = new TextEncoder().encode(JSON.stringify({
      type: 'webauthn.create', challenge: options.challenge, origin: this.origin, crossOrigin: false,
    }));
    this.userHandle = options.user.id;
    return {
      id: this.id,
      rawId: this.id,
      type: 'public-key',
      clientExtensionResults: {},
      response: {
        clientDataJSON: b64(clientDataJSON),
        attestationObject: b64(attestationObject),
        transports: ['internal', 'hybrid'],
      },
    };
  }

  /** navigator.credentials.get() for server options; bumps the counter unless `counter` is given. */
  async assert(
    options: { challenge: string },
    overrides: { counter?: number; userHandle?: string | null; origin?: string } = {},
  ): Promise<AuthenticationResponseJSON> {
    if (!this.keys) throw new Error('register first');
    this.counter = overrides.counter ?? this.counter + 1;
    const rpIdHash = await sha256(new TextEncoder().encode(this.rpId));
    const authData = concat(rpIdHash, new Uint8Array([this.flags(0)]), u32(this.counter));
    const clientDataJSON = new TextEncoder().encode(JSON.stringify({
      type: 'webauthn.get', challenge: options.challenge, origin: overrides.origin ?? this.origin, crossOrigin: false,
    }));
    const signed = concat(authData, await sha256(clientDataJSON));
    const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, this.keys.privateKey, signed));
    const userHandle = overrides.userHandle === undefined ? this.userHandle : overrides.userHandle;
    return {
      id: this.id,
      rawId: this.id,
      type: 'public-key',
      clientExtensionResults: {},
      response: {
        clientDataJSON: b64(clientDataJSON),
        authenticatorData: b64(authData),
        signature: b64(derSignature(raw)),
        ...(userHandle ? { userHandle } : {}),
      },
    };
  }
}

/** A challenge in the shape the server would issue. */
export function randomChallenge(): string {
  return isoBase64URL.fromBuffer(crypto.getRandomValues(new Uint8Array(32)));
}

/** userHandle for a userId (base64url of its UTF-8 bytes). */
export function userHandleFor(userId: string): string {
  return isoBase64URL.fromUTF8String(userId);
}
