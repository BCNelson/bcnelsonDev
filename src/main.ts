import { Terminal } from "xterm"
import { TerminalManager } from "./terminalManager"
import { FitAddon } from 'xterm-addon-fit';
import { WebLinksAddon } from 'xterm-addon-web-links';

const terminalContainer = document.querySelector<HTMLDivElement>('#terminal')

if (terminalContainer) {
  const fitAddon = new FitAddon();
  const terminal = new Terminal({
    cursorBlink: true,
    convertEol: true,
    scrollback: 1000,
    fontFamily: 'Roboto Mono, Ubuntu Mono, courier-new, courier, monospace',
  })
  terminal.loadAddon(fitAddon);
  terminal.loadAddon(new WebLinksAddon());
  terminal.open(terminalContainer);
  fitAddon.fit();
  addEventListener('resize', () => fitAddon.fit());
  new TerminalManager(terminal);
} else {
  console.error('Terminal container not found')
}
