import type { ProgramInterface } from "../interface";
import { Program } from "../base";
import { getFile, getFileContents, resolvePath } from "../../fileSystem/utils";

export default {
    run: async (programInterface: ProgramInterface): Promise<number> => {
        const args = programInterface.args.slice(1)
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

