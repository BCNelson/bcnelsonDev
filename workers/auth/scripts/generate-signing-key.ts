/**
 * Prints a fresh Ed25519 private JWK for AUTH_SIGNING_KEY. No dependencies.
 *
 *   node scripts/generate-signing-key.ts          (Node >= 23.6; older: --experimental-strip-types)
 *
 * The kid is `<YYYY-MM-DD>-<first 12 chars of the RFC 7638 thumbprint>`.
 * To rotate, store `{"keys":[<new>,<old>]}`: the first key signs, the rest are only published.
 */

const { subtle } = globalThis.crypto;

const pair = (await subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
const jwk = (await subtle.exportKey('jwk', pair.privateKey)) as JsonWebKey;
if (!jwk.x || !jwk.d) throw new Error('key export failed');

const thumbprintInput = JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x: jwk.x });
const digest = new Uint8Array(await subtle.digest('SHA-256', new TextEncoder().encode(thumbprintInput)));
const thumbprint = btoa(String.fromCharCode(...digest)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const kid = `${new Date().toISOString().slice(0, 10)}-${thumbprint.slice(0, 12)}`;

console.log(JSON.stringify({ kty: 'OKP', crv: 'Ed25519', x: jwk.x, d: jwk.d, kid, alg: 'EdDSA', use: 'sig' }));
