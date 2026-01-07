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
            await programInterface.writeln(formatHelp("ls", "List the contents of a directory.", helpSpec, "[directory...]"));
            return 0;
        }
        const dirs = parsed.positional;
        if (dirs.length === 0) {
            dirs.push(programInterface.env.PWD);
        }
        for (const arg of dirs) {
            const resolved = resolvePath(programInterface.env.PWD, arg, programInterface.env.HOME);
            const dir = await getDirectory(resolved);
            for (const d of dir.directories) {
                await programInterface.writeln(d.name);
            }
            for (const f of dir.files) {
                await programInterface.writeln(f.name);
            }
        }
        return 0;
    },
    suggest: async (): Promise<string> => {
        return "";
    },
    description: "List the contents of a directory."
} as Program;
