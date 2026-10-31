import { readFileSync } from 'node:fs';
import { defineConfig, type Plugin } from 'vitest/config';

/**
 * Mirrors wrangler's handling of `import x from './file.wasm'` (x is a
 * compiled WebAssembly.Module). Node may compile wasm from bytes; Workers may not.
 */
function wasmModule(): Plugin {
  return {
    name: 'wasm-module',
    enforce: 'pre',
    load(id) {
      if (!id.endsWith('.wasm')) return null;
      const bytes = readFileSync(id).toString('base64');
      return `export default new WebAssembly.Module(Buffer.from(${JSON.stringify(bytes)}, 'base64'));`;
    },
  };
}

export default defineConfig({
  plugins: [wasmModule()],
  test: {
    // Run the package through Vite so its .wasm imports reach the plugin
    // instead of Node's native wasm ESM loader.
    server: { deps: { inline: ['argon2id'] } },
  },
});
