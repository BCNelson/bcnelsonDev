import type { ProgramInterface } from "../interface";
import type { Program } from "../base";
import { parseArgs, formatHelp, type ArgSpec } from "../../argParser";

const helpSpec: ArgSpec[] = [
    { name: "help", short: "h", long: "help", description: "Show this help message" },
];

export default {
    run: async (programInterface: ProgramInterface): Promise<number> => {
        const parsed = parseArgs(programInterface.args.slice(1), helpSpec);
        if (parsed.flags.has("help")) {
            await programInterface.writeln(formatHelp("history", "Manage command history.", helpSpec, "[clear]"));
            await programInterface.writeln("\nSubcommands:");
            await programInterface.writeln("  clear              Clear the command history");
            return 0;
        }
        const subcommand = parsed.positional[0];
        switch (subcommand) {
            case "clear":
                programInterface.terminalManager.setHistory([]);
                break;
        }
        return 0;
    },
    suggest: async (): Promise<string> => {
        return "";
    },
    description: "Manage the history of the terminal."
} as Program;
