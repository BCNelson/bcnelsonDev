import type { ProgramInterface } from "../interface";
import { Program } from "../base";
import { getDirectory, resolvePath } from "../../fileSystem/utils";

export default {
    run: async (programInterface: ProgramInterface): Promise<number> => {
        const dirs = programInterface.args.slice(1);
        if (dirs.length === 0) {
            dirs.push(programInterface.env.PWD);
        }
        dirs.forEach(async (arg) => {
            arg = resolvePath( programInterface.env.PWD, arg, programInterface.env.HOME);
            const dir = await getDirectory(arg);
            dir.directories.forEach((dir) => {
                programInterface.writeln(dir.name);
            });
            dir.files.forEach((file) => {
                programInterface.writeln(file.name);
            });
        });
        return 0;
    },
    suggest: async (): Promise<string> => {
        return ""; 
    },
    description: "List the contents of a directory."
} as Program;

