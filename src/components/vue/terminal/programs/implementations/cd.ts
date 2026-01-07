import type { ProgramInterface } from "../interface";
import type { Program } from "../base";
import { getDirectory, resolvePath } from "../../fileSystem/utils";
import { parseArgs, formatHelp, type ArgSpec } from "../../argParser";

const helpSpec: ArgSpec[] = [
    { name: "help", short: "h", long: "help", description: "Show this help message" },
];

export default {
    run: async (programInterface: ProgramInterface): Promise<number> => {
        const parsed = parseArgs(programInterface.args.slice(1), helpSpec);
        if (parsed.flags.has("help")) {
            await programInterface.writeln(formatHelp("cd", "Change the current working directory.", helpSpec, "[directory]"));
            return 0;
        }
        if (parsed.positional.length > 1) {
            await programInterface.writeln("cd: too many arguments");
            return 1;
        }
        if (parsed.positional.length === 0) {
            programInterface.env.PWD = programInterface.env.HOME;
            return 0;
        }
        const path = resolvePath(programInterface.env.PWD, parsed.positional[0], programInterface.env.HOME);
        try {
            await getDirectory(path);
            programInterface.env.PWD = path;
        } catch {
            programInterface.writeln("cd: no such directory");
            return 1;
        }
        return 0;
    },
    suggest: async (): Promise<string> => {
        return "";
    },
    description: "Change the current working directory."
} as Program;
