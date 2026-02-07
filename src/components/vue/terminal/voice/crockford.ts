/**
 * Crockford's Base32 encoding for generating short peer IDs.
 *
 * Crockford Base32 alphabet: 0123456789ABCDEFGHJKMNPQRSTVWXYZ
 * - Excludes I, L, O, U to avoid visual confusion
 * - Case insensitive for decoding
 *
 * @see https://www.crockford.com/base32.html
 */

const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

// Decoding map for case-insensitive lookup (handles common misreadings)
const DECODE_MAP: Record<string, number> = {};
for (let i = 0; i < ALPHABET.length; i++) {
  DECODE_MAP[ALPHABET[i]] = i;
  DECODE_MAP[ALPHABET[i].toLowerCase()] = i;
}
// Handle common visual substitutions
DECODE_MAP['O'] = 0;  // O -> 0
DECODE_MAP['o'] = 0;
DECODE_MAP['I'] = 1;  // I -> 1
DECODE_MAP['i'] = 1;
DECODE_MAP['L'] = 1;  // L -> 1
DECODE_MAP['l'] = 1;

/**
 * Generate a short ID using Crockford Base32 encoding.
 *
 * @param bits - Number of random bits (default 40 = 8 characters)
 * @returns A short ID string
 */
export function generateShortId(bits: number = 40): string {
  const bytes = Math.ceil(bits / 8);
  const array = new Uint8Array(bytes);
  crypto.getRandomValues(array);

  return encode(array).slice(0, Math.ceil(bits / 5));
}

/**
 * Encode a byte array as Crockford Base32.
 *
 * @param data - Uint8Array to encode
 * @returns Base32 encoded string
 */
export function encode(data: Uint8Array): string {
  if (data.length === 0) return '';

  // Convert bytes to a big number
  let num = 0n;
  for (let i = 0; i < data.length; i++) {
    num = (num << 8n) | BigInt(data[i]);
  }

  // Calculate number of output characters
  const totalBits = data.length * 8;
  const chars = Math.ceil(totalBits / 5);

  // Encode from least significant to most significant
  let result = '';
  for (let i = 0; i < chars; i++) {
    const index = Number(num & 31n);
    result = ALPHABET[index] + result;
    num = num >> 5n;
  }

  return result;
}

/**
 * Decode a Crockford Base32 string to bytes.
 *
 * @param str - Base32 encoded string
 * @returns Decoded byte array
 */
export function decode(str: string): Uint8Array {
  if (str.length === 0) return new Uint8Array(0);

  // Filter out hyphens (optional separators)
  const clean = str.replace(/-/g, '');

  // Decode to a big number
  let num = 0n;
  for (const char of clean) {
    const value = DECODE_MAP[char];
    if (value === undefined) {
      throw new Error(`Invalid character in Base32 string: ${char}`);
    }
    num = (num << 5n) | BigInt(value);
  }

  // Calculate number of output bytes
  const totalBits = clean.length * 5;
  const bytes = Math.floor(totalBits / 8);

  // Convert to bytes
  const result = new Uint8Array(bytes);
  for (let i = bytes - 1; i >= 0; i--) {
    result[i] = Number(num & 255n);
    num = num >> 8n;
  }

  return result;
}

/**
 * Normalize a peer ID by converting to uppercase and removing invalid characters.
 *
 * @param id - Input peer ID
 * @returns Normalized peer ID
 */
export function normalizePeerId(id: string): string {
  return id.toUpperCase().replace(/[^0-9A-HJ-NP-TV-Z]/g, '');
}
