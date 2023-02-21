import type { ProgramInterface } from "../interface";
import { Program } from "../base";

export default {
    run: async (programInterface: ProgramInterface): Promise<number> => {
        programInterface.writeln(programInterface.env.PWD);
        return 0;
    },
    suggest: async (): Promise<string> => {
        return ""; 
    },
    description: "Print the current working directory."
} as Program;

