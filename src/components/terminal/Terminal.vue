<template>
  <div ref="terminalContainer" class="ring ring-offset-8 ring-offset-black ring-blue-600 md:m-5 rounded-lg"></div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { Terminal } from "xterm"
import { TerminalManager } from "./terminalManager.js"
import { FitAddon } from 'xterm-addon-fit';
import { WebLinksAddon } from 'xterm-addon-web-links';
const terminalContainer = ref<HTMLElement>();
onMounted(() => {
  const fitAddon = new FitAddon();
  const terminal = new Terminal({
    cursorBlink: true,
    convertEol: true,
    scrollback: 1000,
    fontFamily: 'Roboto Mono, Ubuntu Mono, courier-new, courier, monospace',
  })
  terminal.loadAddon(fitAddon);
  terminal.loadAddon(new WebLinksAddon());
  if (terminalContainer.value){
    terminal.open(terminalContainer.value);
  } else {
    console.error("terminalContainer is undefined");
    throw new Error("terminalContainer is undefined");
  }
  fitAddon.fit();
  addEventListener('resize', () => fitAddon.fit());
  new TerminalManager(terminal);
})
</script>