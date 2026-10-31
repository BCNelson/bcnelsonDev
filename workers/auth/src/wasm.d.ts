/** Wrangler bundles imported .wasm files and hands back a compiled module. */
declare module '*.wasm' {
  const module: WebAssembly.Module;
  export default module;
}
