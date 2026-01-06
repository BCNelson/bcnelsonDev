import type { ProgramInterface } from "../interface";
import type { Program } from "../base";

export default {
    run: async (programInterface: ProgramInterface): Promise<number> => {
        const args = programInterface.args;
        switch (args[1]) {
            case "clear":
                programInterface.terminalManager.setHistory([]);
        }
        return 0;
    },
    suggest: async (): Promise<string> => {
        return "";
    },
    description: "Manage the history of the terminal."
} as Program;
