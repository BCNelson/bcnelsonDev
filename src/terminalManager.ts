import type { Terminal } from 'xterm';
import Programs, { ProgramInterface } from './programs';

export class TerminalManager {
    private _terminal: Terminal;
    private input = "";
    private position = 0;
    private env: Record<string, string> = {
        "HOME": "/home/visitor",
        "PWD": "/home/visitor"
    };

    constructor(terminal: Terminal) {
        this._terminal = terminal;
        this.setupInputHandler();
        this._terminal.write(this.prompt());
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
                    case "[B": // down
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
        const args = this.input.split(" ");
        const programName = args[0];
        const program = Programs.get(programName);
        if (program) {
            const programInterface = new ProgramInterface(this._terminal, args, this.env);
            await program.run(programInterface)
        } else {
            this._terminal.writeln(programName + ": command not found");
        }
        this.input = "";
        this.position = 0;
        this._terminal.write(this.prompt())
    }

    private prompt(): string {
        return "$ "
    }

}