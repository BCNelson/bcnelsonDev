import type { Terminal } from '@xterm/xterm';
import Programs, { ProgramInterface } from './programs';
import { message } from "../../../data/introduction.js";
import { tokenize, findTokenAtCursor } from './parser';
import { getDirectory, resolvePath } from './fileSystem/utils';
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
        this._terminal.writeln(message);
        const prompt = this.prompt();
        this._terminal.write(prompt);
        const historyString = window.localStorage.getItem("history");
        if (historyString !== null) {
            this.history = JSON.parse(historyString);
            console.log("Loaded History", this.history);
        } else {
            this.history = [];
        }
        this._terminal.focus();
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
                this.handleTab();
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
        this.historyPosition = this.history.length;
        this.tempHistory = "";
        const args = tokenize(this.input);
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
        return `${c.cyan('guest')}${c.gray('@')}${c.cyanBright('bcnelson.dev')}${c.gray(':')}${c.magenta(path)}${c.gray('$')} `
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

    private async handleTab(): Promise<void> {
        const tokenInfo = findTokenAtCursor(this.input, this.position);
        const tokens = tokenize(this.input);

        // Determine what we're completing
        let completions: string[] = [];
        let partial = "";
        let isCommand = false;

        if (!tokenInfo || tokenInfo.tokenIndex === 0) {
            // Completing command name
            isCommand = true;
            partial = tokens[0] ?? "";
            completions = this.getCommandCompletions(partial);
        } else {
            // Completing argument (path completion)
            partial = tokenInfo.token;
            completions = await this.getPathCompletions(partial);
        }

        if (completions.length === 0) {
            return;
        }

        if (completions.length === 1) {
            // Single completion - apply it
            this.applyCompletion(partial, completions[0], isCommand);
        } else {
            // Multiple completions - find common prefix
            const common = this.findCommonPrefix(completions);
            if (common.length > partial.length) {
                this.applyCompletion(partial, common, isCommand);
            } else {
                // Show all options
                this._terminal.write("\r\n");
                this._terminal.writeln(completions.join("  "));
                this._terminal.write(this.prompt());
                this._terminal.write(this.input);
            }
        }
    }

    private getCommandCompletions(partial: string): string[] {
        const programNames = Array.from(Programs.keys());
        if (partial === "") {
            return programNames;
        }
        return programNames.filter(name => name.startsWith(partial)).sort();
    }

    private async getPathCompletions(partial: string): Promise<string[]> {
        // Resolve the path to get the directory to list
        let dirPath: string;
        let prefix: string;

        if (partial.endsWith("/")) {
            // Completing within this directory
            dirPath = partial;
            prefix = "";
        } else {
            // Get parent directory and filename prefix
            const lastSlash = partial.lastIndexOf("/");
            if (lastSlash === -1) {
                // No slashes - completing in current directory
                dirPath = this.env.PWD;
                prefix = partial;
            } else {
                dirPath = partial.slice(0, lastSlash + 1);
                prefix = partial.slice(lastSlash + 1);
            }
        }

        // Resolve relative paths
        const resolvedDir = resolvePath(this.env.PWD, dirPath, this.env.HOME);

        try {
            const dir = await getDirectory(resolvedDir);

            // Get matching entries
            const entries: string[] = [];
            for (const d of dir.directories) {
                if (d.name.startsWith(prefix)) {
                    entries.push(d.name + "/");
                }
            }
            for (const f of dir.files) {
                if (f.name.startsWith(prefix)) {
                    entries.push(f.name);
                }
            }

            // Return full paths
            const basePath = partial.endsWith("/") ? partial : partial.slice(0, partial.lastIndexOf("/") + 1);
            return entries.map(e => basePath + e).sort();
        } catch {
            return [];
        }
    }

    private applyCompletion(partial: string, completion: string, isCommand: boolean): void {
        // Calculate what to insert
        const toInsert = completion.slice(partial.length);

        // Add space after command completion (unless it's a directory)
        const suffix = isCommand && !completion.endsWith("/") ? " " : "";

        // Insert at current position
        const before = this.input.slice(0, this.position);
        const after = this.input.slice(this.position);
        const newInput = before + toInsert + suffix + after;

        // Update display
        this._terminal.write(toInsert + suffix);
        this.input = newInput;
        this.position += toInsert.length + suffix.length;
    }

    private findCommonPrefix(strings: string[]): string {
        if (strings.length === 0) return "";
        if (strings.length === 1) return strings[0];

        let prefix = strings[0];
        for (let i = 1; i < strings.length; i++) {
            while (!strings[i].startsWith(prefix)) {
                prefix = prefix.slice(0, -1);
                if (prefix === "") return "";
            }
        }
        return prefix;
    }
}
