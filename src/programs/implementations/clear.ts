import type { ProgramInterface } from "../interface";
import { Program } from "../base";

export default {
    run: async (programInterface: ProgramInterface): Promise<number> => {
        programInterface.terminal.clear();
        return 0;
    },
    suggest: async (): Promise<string> => {
        return "";
    },
    description: "Clear the terminal."
} as Program;

