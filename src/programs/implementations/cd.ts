import type { ProgramInterface } from "../interface";
import { Program } from "../base";
import { getDirectory, resolvePath } from "../../fileSystem/utils";

export default {
    run: async (programInterface: ProgramInterface): Promise<number> => {
        if (programInterface.args.length > 2) {
            programInterface.writeln("cd: too many arguments");
            return 1;
        }
        if (programInterface.args.length === 1) {
            programInterface.env.PWD = programInterface.env.HOME;
            return 0;
        }
        const path = resolvePath( programInterface.env.PWD, programInterface.args[1], programInterface.env.HOME);
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
    }
} as Program;

