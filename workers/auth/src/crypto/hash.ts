/**
 * Hashing and comparison helpers for codes, tokens and refresh secrets.
 * Everything secret is stored as SHA-256 and compared in constant time.
 */

const encoder = new TextEncoder();

/** Base64url (no padding) encoding of raw bytes. */
export function toBase64url(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** SHA-256 of the UTF-8 input, base64url encoded. */
export async function sha256Base64url(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(input));
  return toBase64url(new Uint8Array(digest));
}

/**
 * Constant-time string comparison. Runs over equal-length buffers; when the
 * lengths differ it still does a full comparison (of `a` with itself) so the
 * time depends only on the length of `a`.
 */
export function timingSafeEqual(a: string, b: string): boolean {
  const ab = encoder.encode(a);
  const bb = encoder.encode(b);
  const sameLength = ab.byteLength === bb.byteLength;
  const other = sameLength ? bb : ab;
  // Workers exposes crypto.subtle.timingSafeEqual; Node (tests) does not.
  const native = (crypto.subtle as Partial<SubtleCrypto>).timingSafeEqual;
  let equal: boolean;
  if (typeof native === 'function') {
    equal = native.call(crypto.subtle, ab, other);
  } else {
    let diff = 0;
    for (let i = 0; i < ab.byteLength; i++) diff |= ab[i]! ^ other[i]!;
    equal = diff === 0;
  }
  return sameLength && equal;
}
