<template>
  <div ref="terminalWrapper" class="terminal-wrapper">
    <div ref="terminalContainer" class="terminal-container"></div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, nextTick } from "vue";
import { Terminal } from "@xterm/xterm";
import { TerminalManager } from "./terminalManager.js";
import { FitAddon } from "@xterm/addon-fit";
import { WebLinksAddon } from "@xterm/addon-web-links";

const terminalWrapper = ref<HTMLElement>();
const terminalContainer = ref<HTMLElement>();
let fitAddon: FitAddon;

// Custom theme matching site colors
const theme = {
  background: "#0d0e14",
  foreground: "#e2e8f0",
  cursor: "#22d3ee",
  cursorAccent: "#0d0e14",
  selectionBackground: "rgba(34, 211, 238, 0.3)",
  selectionForeground: "#ffffff",
  black: "#1e293b",
  red: "#f43f5e",
  green: "#22d3ee",
  yellow: "#f59e0b",
  blue: "#3b82f6",
  magenta: "#a855f7",
  cyan: "#22d3ee",
  white: "#e2e8f0",
  brightBlack: "#475569",
  brightRed: "#fb7185",
  brightGreen: "#67e8f9",
  brightYellow: "#fbbf24",
  brightBlue: "#60a5fa",
  brightMagenta: "#c084fc",
  brightCyan: "#67e8f9",
  brightWhite: "#f8fafc",
};

const doFit = () => {
  if (fitAddon && terminalWrapper.value) {
    try {
      fitAddon.fit();
    } catch (e) {
      console.error("Fit error:", e);
    }
  }
};

onMounted(async () => {
  fitAddon = new FitAddon();

  const terminal = new Terminal({
    cursorBlink: true,
    cursorStyle: "block",
    convertEol: true,
    scrollback: 1000,
    fontFamily: '"JetBrains Mono", "Fira Code", monospace',
    fontSize: 13,
    lineHeight: 0,
    theme: theme,
    allowProposedApi: true,
  });

  terminal.loadAddon(fitAddon);
  terminal.loadAddon(new WebLinksAddon());

  // Intercept Tab key to prevent browser focus navigation
  terminal.attachCustomKeyEventHandler((event) => {
    if (event.key === "Tab") {
      // Return true to let xterm handle the Tab key
      // This prevents the browser from using it for focus navigation
      return true;
    }
    return true;
  });

  if (terminalContainer.value) {
    terminal.open(terminalContainer.value);
  } else {
    throw new Error("terminalContainer is undefined");
  }

  // Multiple fit attempts to ensure correct sizing
  await nextTick();
  doFit();

  setTimeout(doFit, 100);
  setTimeout(doFit, 300);

  // Debounced resize handler
  let resizeTimer: number;
  const handleResize = () => {
    clearTimeout(resizeTimer);
    resizeTimer = window.setTimeout(doFit, 50);
  };

  window.addEventListener("resize", handleResize);

  // Observe container size changes
  if (terminalWrapper.value) {
    const ro = new ResizeObserver(handleResize);
    ro.observe(terminalWrapper.value);
  }

  new TerminalManager(terminal);
});
</script>

<style scoped>
.terminal-wrapper {
  position: relative;
  width: 100%;
  height: 500px;
  max-height: 70vh;
  overflow: hidden;
}

/* Override height when terminal is maximized */
:global(.maximized) .terminal-wrapper {
  height: 100% !important;
  max-height: none !important;
}

.terminal-container {
  position: absolute;
  top: 12px;
  left: 16px;
  right: 8px;
  bottom: 12px;
  overflow: hidden;
  box-sizing: border-box;
}

/* Force xterm to respect container bounds */
.terminal-container :deep(.xterm) {
  height: 100%;
  width: 100% !important;
  max-width: 100% !important;
  overflow: hidden !important;
  padding-left: 8px !important;
  padding-right: 4px !important;
}

.terminal-container :deep(.xterm-screen) {
  width: 100% !important;
  max-width: 100% !important;
  overflow: hidden !important;
}

.terminal-container :deep(.xterm-screen canvas) {
  max-width: 100% !important;
}

.terminal-container :deep(.xterm-viewport) {
  overflow-y: auto !important;
  overflow-x: hidden !important;
  width: 100% !important;
  max-width: 100% !important;
}

.terminal-container :deep(.xterm-viewport::-webkit-scrollbar) {
  width: 6px;
}

.terminal-container :deep(.xterm-viewport::-webkit-scrollbar-track) {
  background: transparent;
}

.terminal-container :deep(.xterm-viewport::-webkit-scrollbar-thumb) {
  background: #334155;
  border-radius: 3px;
}
</style>
