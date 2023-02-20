import type { ProgramInterface } from "../interface";
import { Program } from "../base";
import { getContents, resolvePath } from "../../fileSystem/utils";

export default {
    run: async (programInterface: ProgramInterface): Promise<number> => {
        programInterface.args.slice(1).forEach(async (arg) => {
            arg = resolvePath( programInterface.env.PWD, arg, programInterface.env.HOME);
            const contents = await getContents(arg);
            await programInterface.writeln(contents.toString());
        });
        return 0;
    },
    suggest: async (): Promise<string> => {
        return ""; 
    },
    description: "Print the contents of a file to the terminal."
} as Program;

