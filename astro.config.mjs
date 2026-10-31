// @ts-check
import { defineConfig } from "astro/config";
import mdx from "@astrojs/mdx";
import sitemap from "@astrojs/sitemap";
import tailwindcss from "@tailwindcss/vite";
import vue from "@astrojs/vue";
import cloudflare from "@astrojs/cloudflare";

export default defineConfig({
  site: "https://bcnelson.dev",
  integrations: [
    mdx(),
    sitemap(),
    vue(),
  ],
  // The site has no sessions or astro:assets images, so skip the KV and
  // Images bindings the adapter would otherwise provision.
  session: false,
  adapter: cloudflare({
    imageService: "passthrough",
    // workerd cannot run on NixOS, and prerendered pages need no Workers APIs.
    prerenderEnvironment: "node",
  }),
  vite: {
    plugins: [tailwindcss()],
    ssr: {
      // xterm.js requires DOM and cannot be server-rendered
      external: ["@xterm/xterm", "@xterm/addon-fit", "@xterm/addon-web-links"],
    },
  },
});
