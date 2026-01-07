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
            await programInterface.writeln(formatHelp("echo", "Print the arguments to the terminal.", helpSpec, "[text...]"));
            return 0;
        }
        await programInterface.writeln(parsed.positional.join(" "));
        return 0;
    },
    suggest: async (): Promise<string> => {
        return "";
    },
    description: "Print the arguments to the terminal."
} as Program;
