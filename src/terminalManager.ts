import type { Terminal } from 'xterm';
import Programs, { ProgramInterface } from './programs';
import introduction from "../static/introduction.txt?raw";
import c from 'ansi-colors';
c.enabled = true;

export class TerminalManager {
    private _terminal: Terminal;
    private input = "";
    private position = 0;
    private env: Record<string, string> = {
        "HOME": "/home/visitor",
        "PWD": "/home/visitor"
    };

    private history: string[];
    private historyPosition: number | null = null;
    private tempHistory = "";

    constructor(terminal: Terminal) {
        this._terminal = terminal;
        this.setupInputHandler();
        this._terminal.writeln(introduction);
        this._terminal.write(this.prompt());
        const historyString = window.localStorage.getItem("history");
        if (historyString !== null) {
            this.history = JSON.parse(historyString);
            console.log("Loaded History", this.history);
        } else {
            this.history = [];
        }
    }

    private replaceInput(text: string): void {
        // CLear the current input
        let output = ''
        if (this.position > 0) {
            output += `\u001B[${this.position}D`;
        }
        output += '\u001B[0K';
        output += text;
        this._terminal.write(output);
        this.input = text;
        this.position = text.length;
    }

    private setupInputHandler(): void {
        this._terminal.onData((data) => {
            const dataCode = data.charCodeAt(0);
            if (dataCode === 13) { // enter
                this.exec();
            } else if (dataCode === 127) { // backspace
                if (this.position === 0) {
                    return;
                }
                this._terminal.write("\b \b");
                this.input = this.input.slice(0, -1);
                this.position -= 1;
            } else if (dataCode >= 32 && dataCode !== 127) { // printable characters
                this._terminal.write(data);
                this.input = this.input.slice(0, this.position) + data + this.input.slice(this.position);
                this.position += 1;
            } else if (dataCode === 27) { // escape
                switch (data.slice(1)) {
                    case "[A": // up
                        if (this.historyPosition === null) {
                            this.tempHistory = this.input;
                            this.historyPosition = this.history.length - 1;
                        } else if (this.history.length === 0) {
                            break;
                        } else {
                            this.historyPosition -= 1;
                            this.historyPosition = Math.max(this.historyPosition, 0);
                        }
                        this.replaceInput(this.history[this.historyPosition]);
                        break;
                    case "[B": // down
                        if (this.historyPosition === null) {
                            break; // do nothing
                        } else if (this.historyPosition === this.history.length - 1) { // if we are at the bottom of the history
                            this.historyPosition = null;
                            this.replaceInput(this.tempHistory);
                            break;
                        } else {
                            this.historyPosition += 1;
                            this.historyPosition = Math.min(this.historyPosition, this.history.length - 1);
                            this.replaceInput(this.history[this.historyPosition]);
                        }
                        break;// TODO: history
                    case "[C": // right
                        if (this.position < this.input.length){
                            this.position += 1;
                            this._terminal.write(data);
                        }
                        break;
                    case "[D": // left
                        if (this.position > 0){
                            this.position -= 1;
                            this._terminal.write(data);
                        }
                        break;
                    default:
                        console.log("Unknown Escape Code", data.slice(1));
                }
            } else if (dataCode === 9) { // tab
                //TODO: autocomplete
            } else if (dataCode === 12){
                this._terminal.clear();
                this._terminal.write(this.prompt());
                this._terminal.write(this.input);
            } else {
                console.log("Unknown Code", dataCode);
            }

        });
    }

    public async exec(): Promise<void> {
        this._terminal.write("\r\n");
        this.addHistory(this.input);
        this.historyPosition = 0;
        this.tempHistory = "";
        const args = this.input.split(" ");
        const programName = args[0];
        const program = Programs.get(programName);
        if (program) {
            const programInterface = new ProgramInterface(this._terminal, args, this.env, this);
            await program.run(programInterface)
        } else {
            this._terminal.writeln(programName + ": command not found");
        }
        this.input = "";
        this.position = 0;
        this._terminal.write(this.prompt())
    }

    private prompt(): string {
        let path = this.env.PWD;
        if (path.startsWith(this.env.HOME)) {
            path = "~" + path.slice(this.env.HOME.length);
        }
        return `visitor@bcnelson.dev ${c.green(path)}> `
    }

    private addHistory(input: string): void {
        this.history = this.history.filter((item) => item !== input);
        this.history.push(input);
        window.localStorage.setItem("history", JSON.stringify(this.history));
    }

    setHistory(history: string[]): void {
        console.log("set history", history);
        this.history = history;
        window.localStorage.setItem("history", JSON.stringify(this.history));
    }
}