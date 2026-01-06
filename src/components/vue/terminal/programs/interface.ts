import type { Terminal } from 'xterm';
import Root from '../fileSystem';
import type { TerminalManager } from '../terminalManager';

export class ProgramInterface {
    private _terminal: Terminal;
    private _args: string[];
    private _env: Record<string, string>;
    private _terminalManager: TerminalManager;
    static root = Root;

    constructor(terminal: Terminal, args: string[], env: Record<string, string>, terminalManager: TerminalManager) {
        this._terminal = terminal;
        this._args = args;
        this._env = env;
        this._terminalManager = terminalManager;
    }

    get terminal(): Terminal {
        return this._terminal;
    }

    get args(): string[] {
        return this._args;
    }

    get env(): Record<string, string> {
        return this._env;
    }

    get terminalManager(): TerminalManager {
        return this._terminalManager;
    }

    async write(text: string): Promise<void> {
        return new Promise((resolve) => {
            this._terminal.write(text, resolve);
        });
    }

    async writeln(text: string): Promise<void> {
        return new Promise((resolve) => {
            this._terminal.writeln(text, resolve);
        });
    }
}

export interface Context {}
