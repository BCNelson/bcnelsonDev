/**
 * Argon2id (RFC 9106) via the openpgpjs `argon2id` package (design §11).
 *
 * Workers forbid compiling WebAssembly from bytes at runtime, so the package's
 * default entry (which expects a bundler-specific wasm loader) is not used.
 * Instead the two prebuilt .wasm files are imported as modules: wrangler
 * bundles them and the import yields a precompiled `WebAssembly.Module`, which
 * may be instantiated at runtime. Under vitest (Node) the same imports are
 * served by a small plugin in vitest.config.ts that compiles the bytes with
 * `new WebAssembly.Module(...)`, which Node allows.
 *
 * Memory: the wasm declares an initial linear memory of 1040 pages (65 MiB),
 * so one instance costs ~65 MiB of the isolate's 128 MB limit. It is created
 * lazily on first use and kept for the life of the isolate; m=19456 KiB fits
 * inside that initial memory, so it never grows for our parameters. The hash
 * function is synchronous, so concurrent requests cannot interleave on it.
 */

import setupWasm, { type Argon2idParams, type computeHash } from 'argon2id/lib/setup.js';
import simdModule from 'argon2id/dist/simd.wasm';
import noSimdModule from 'argon2id/dist/no-simd.wasm';

export type { Argon2idParams };

const instantiate = (module: WebAssembly.Module) => async (imports: WebAssembly.Imports) => ({
  module,
  instance: await WebAssembly.instantiate(module, imports),
});

let loading: Promise<computeHash> | null = null;

/** Instantiates the wasm once per isolate (SIMD build when supported). */
function load(): Promise<computeHash> {
  loading ??= setupWasm(instantiate(simdModule), instantiate(noSimdModule)).catch((err) => {
    loading = null; // allow a retry on the next call
    throw err;
  });
  return loading;
}

/**
 * Computes a raw Argon2id tag. Throws on invalid parameters; note the library
 * requires passwords and salts of at least 8 bytes.
 */
export async function argon2id(params: Argon2idParams): Promise<Uint8Array> {
  const hash = await load();
  return hash(params);
}
