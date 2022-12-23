import type{ Terminal } from 'xterm';

export class ProgramInterface {
    private _terminal: Terminal;
    private _args: string[];
    private _env: Record<string, string>;

    constructor(terminal: Terminal, args: string[], env?: Record<string, string>) {
        this._terminal = terminal;
        this._args = args;
        this._env = env || {};
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