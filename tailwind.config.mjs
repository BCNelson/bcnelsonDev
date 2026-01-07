/** @type {import('tailwindcss').Config} */
export default {
  content: ["./src/**/*.{astro,html,js,jsx,md,mdx,svelte,ts,tsx,vue}"],
  theme: {
    extend: {
      colors: {
        // Backgrounds - very dark, almost black
        surface: {
          primary: "#0a0a0f",
          secondary: "#12131a",
          tertiary: "#1a1b23",
          terminal: "#0d0e14",
        },
        // Primary accent - Cyan/Teal
        accent: {
          cyan: "#22d3ee",
          "cyan-bright": "#67e8f9",
          "cyan-dim": "#0891b2",
          blue: "#3b82f6",
        },
        // Borders
        border: {
          DEFAULT: "#1e293b",
          accent: "rgba(34, 211, 238, 0.3)",
        },
      },
      fontFamily: {
        mono: [
          "JetBrains Mono",
          "Fira Code",
          "SF Mono",
          "Consolas",
          "monospace",
        ],
        sans: [
          "Inter",
          "-apple-system",
          "BlinkMacSystemFont",
          "Segoe UI",
          "sans-serif",
        ],
      },
      animation: {
        blink: "blink 1s step-end infinite",
        pulse: "pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "typing-cursor": "typing-cursor 1s step-end infinite",
        glow: "glow 2s ease-in-out infinite alternate",
      },
      keyframes: {
        blink: {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0" },
        },
        "typing-cursor": {
          "0%, 100%": { borderColor: "currentColor" },
          "50%": { borderColor: "transparent" },
        },
        glow: {
          from: { boxShadow: "0 0 5px rgba(34, 211, 238, 0.5)" },
          to: { boxShadow: "0 0 20px rgba(34, 211, 238, 0.8)" },
        },
      },
      boxShadow: {
        "glow-sm": "0 0 10px rgba(34, 211, 238, 0.3)",
        glow: "0 0 20px rgba(34, 211, 238, 0.4)",
        "glow-lg": "0 0 30px rgba(34, 211, 238, 0.5)",
      },
    },
  },
  plugins: [require("@tailwindcss/typography")],
};
