// @ts-check
import { defineConfig } from "astro/config";
import mdx from "@astrojs/mdx";
import sitemap from "@astrojs/sitemap";
import tailwind from "@astrojs/tailwind";
import vue from "@astrojs/vue";
import cloudflare from "@astrojs/cloudflare";

export default defineConfig({
  site: "https://bcnelson.dev",
  integrations: [
    mdx(),
    sitemap(),
    tailwind(),
    vue(),
  ],
  adapter: cloudflare({
    platformProxy: { enabled: true },
    workerEntryPoint: {
      path: "src/worker.ts",
      namedExports: ["PeerServer"],
    },
  }),
  vite: {
    ssr: {
      // xterm.js requires DOM and cannot be server-rendered
      external: ["@xterm/xterm", "@xterm/addon-fit", "@xterm/addon-web-links"],
    },
  },
});
