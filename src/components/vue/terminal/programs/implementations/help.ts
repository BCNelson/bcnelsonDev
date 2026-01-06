import type { ProgramInterface } from "../interface";
import type { Program } from "../base";
import programs from "../index.js";

export default {
    run: async (programInterface: ProgramInterface): Promise<number> => {
        programs.forEach((program, name) => {
            let programName = name + ":";
            programInterface.writeln(`${programName.padEnd(8, " ")} ${program.description}`);
        });
        return 0;
    },
    suggest: async (): Promise<string> => {
        return "";
    },
    description: "Get help on a program."
} as Program;
