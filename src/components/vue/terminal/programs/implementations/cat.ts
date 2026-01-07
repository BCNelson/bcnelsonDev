import type { ProgramInterface } from "../interface";
import type { Program } from "../base";
import { getFile, getFileContents, resolvePath } from "../../fileSystem/utils";
import { parseArgs, formatHelp, type ArgSpec } from "../../argParser";

const helpSpec: ArgSpec[] = [
    { name: "help", short: "h", long: "help", description: "Show this help message" },
];

export default {
    run: async (programInterface: ProgramInterface): Promise<number> => {
        const parsed = parseArgs(programInterface.args.slice(1), helpSpec);
        if (parsed.flags.has("help")) {
            await programInterface.writeln(formatHelp("cat", "Print the contents of a file to the terminal.", helpSpec, "[file...]"));
            return 0;
        }
        const args = parsed.positional;
        for (const arg of args){
            let resolvedArg = resolvePath( programInterface.env.PWD, arg, programInterface.env.HOME);
            const file = await getFile(resolvedArg);
            const contents = await getFileContents(file);
            switch (file.type) {
                case "text":
                    await programInterface.writeln(contents.toString());
                    break;
                case "link":
                    const url = new URL(document.URL);
                    url.pathname = contents.toString();
                    await programInterface.writeln(url.toString());
                    break;
                default:
                    await programInterface.writeln("cat: " + arg + ": Not a text file");
            }
        }
        return 0;
    },
    suggest: async (): Promise<string> => {
        return "";
    },
    description: "Print the contents of a file to the terminal."
} as Program;
