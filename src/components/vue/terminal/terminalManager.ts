import type { Terminal } from '@xterm/xterm';
import Programs, { ProgramInterface } from './programs';
import { message } from "../../../data/introduction.js";
import { tokenize, findTokenAtCursor } from './parser';
import { getDirectory, resolvePath } from './fileSystem/utils';
import { VoiceService } from './voice/VoiceService';
import type { VoiceEvent } from './voice/types';
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
    private voiceService: VoiceService;

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

        // Initialize voice service and subscribe to events
        this.voiceService = VoiceService.getInstance();
        this.voiceService.subscribe(this.handleVoiceEvent.bind(this));
        this.voiceService.initialize().catch(() => {
            // Silently fail - voice will initialize on first use
        });

        // Check for auto-call URL parameter
        this.handleAutoCall();
    }

    private async handleAutoCall(): Promise<void> {
        const url = new URL(window.location.href);
        const callPeerId = url.searchParams.get('call');

        if (!callPeerId) {
            return;
        }

        // Validate peer ID format (alphanumeric and hyphens only)
        if (!/^[a-zA-Z0-9-]+$/.test(callPeerId)) {
            this._terminal.writeln(c.red('\r\nError: Invalid peer ID in URL.\r\n'));
            return;
        }

        // Clear the URL parameter to prevent re-call on refresh
        url.searchParams.delete('call');
        window.history.replaceState({}, '', url.toString());

        // Show message and initiate call after a brief delay
        this._terminal.writeln(c.cyan('\r\nInitiating call from QR code link...\r\n'));

        // Wait for voice service to initialize
        try {
            await this.voiceService.initialize();
        } catch (e) {
            this._terminal.writeln(c.red(`Error connecting to voice service: ${e instanceof Error ? e.message : 'Unknown error'}\r\n`));
            return;
        }

        // Execute the call command
        this.input = `voice call ${callPeerId}`;
        this.position = this.input.length;
        this._terminal.write(this.input);

        // Give user a moment to see what's happening, then execute
        setTimeout(() => {
            this.exec();
        }, 500);
    }

    private handleVoiceEvent(event: VoiceEvent): void {
        switch (event.type) {
            case 'incoming-call':
                this.showNotification(
                    `\r\n${c.cyan('📞 Incoming call from:')} ${c.bold(event.data?.peerId ?? 'unknown')}\r\n` +
                    `${c.gray('Run')} ${c.green('voice answer')} ${c.gray('to accept or')} ${c.red('voice reject')} ${c.gray('to decline.')}\r\n`
                );
                break;
            case 'call-connected':
                this.showNotification(
                    `${c.green('✓')} ${c.green('Call connected with')} ${c.cyan(event.data?.peerId ?? 'peer')}\r\n`
                );
                break;
            case 'call-ended':
                this.showNotification(
                    `${c.yellow('Call ended.')}\r\n`
                );
                break;
            case 'error':
                if (event.data?.error) {
                    this.showNotification(
                        `${c.red('Voice error:')} ${event.data.error}\r\n`
                    );
                }
                break;
        }
    }

    private showNotification(message: string): void {
        // Save current line state
        const savedInput = this.input;
        const savedPosition = this.position;

        // Move to new line and show notification
        this._terminal.write('\r\n');
        this._terminal.write(message);

        // Restore prompt and input
        this._terminal.write(this.prompt());
        this._terminal.write(savedInput);

        // Restore cursor position if needed
        if (savedPosition < savedInput.length) {
            const moveBack = savedInput.length - savedPosition;
            this._terminal.write(`\x1b[${moveBack}D`);
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
