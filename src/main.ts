import { Terminal } from "xterm"
import { TerminalManager } from "./terminalManager"

const terminalContainer = document.querySelector<HTMLDivElement>('#terminal')

if (terminalContainer) {
  const terminal = new Terminal({
    cursorBlink: true,
    convertEol: true,
    scrollback: 1000,
    fontFamily: 'Roboto Mono, Ubuntu Mono, courier-new, courier, monospace',
  })
  terminal.open(terminalContainer)
  new TerminalManager(terminal);
} else {
  console.error('Terminal container not found')
}
