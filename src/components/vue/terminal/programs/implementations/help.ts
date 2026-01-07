import type { ProgramInterface } from "../interface";
import type { Program } from "../base";
import programs from "../index.js";
import { parseArgs, formatHelp, type ArgSpec } from "../../argParser";

const helpSpec: ArgSpec[] = [
    { name: "help", short: "h", long: "help", description: "Show this help message" },
];

export default {
    run: async (programInterface: ProgramInterface): Promise<number> => {
        const parsed = parseArgs(programInterface.args.slice(1), helpSpec);
        if (parsed.flags.has("help")) {
            await programInterface.writeln(formatHelp("help", "List available commands or get help on a specific command.", helpSpec, "[command]"));
            return 0;
        }
        // If a specific command was requested, show its help
        if (parsed.positional.length > 0) {
            const cmdName = parsed.positional[0];
            const cmd = programs.get(cmdName);
            if (cmd) {
                await programInterface.writeln(`${cmdName}: ${cmd.description}`);
                await programInterface.writeln(`\nRun '${cmdName} --help' for more information.`);
            } else {
                await programInterface.writeln(`help: unknown command '${cmdName}'`);
            }
            return 0;
        }
        // List all commands
        for (const [name, program] of programs) {
            const programName = name + ":";
            await programInterface.writeln(`${programName.padEnd(10, " ")} ${program.description}`);
        }
        return 0;
    },
    suggest: async (): Promise<string> => {
        return "";
    },
    description: "Get help on a program."
} as Program;
