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
            await programInterface.writeln(formatHelp("clear", "Clear the terminal screen.", helpSpec));
            return 0;
        }
        programInterface.terminal.clear();
        return 0;
    },
    suggest: async (): Promise<string> => {
        return "";
    },
    description: "Clear the terminal."
} as Program;
