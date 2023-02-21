import type { ProgramInterface } from "../interface";
import { Program } from "../base";

export default {
    run: async (programInterface: ProgramInterface): Promise<number> => {
        await programInterface.writeln(programInterface.args.slice(1).join(" "));
        return 0;
    },
    suggest: async (): Promise<string> => {
        return "";
    },
    description: "Print the arguments to the terminal."
} as Program;

