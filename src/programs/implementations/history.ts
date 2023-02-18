import type { ProgramInterface } from "../interface";
import { Program } from "../base";
import { getContents, resolvePath } from "../../fileSystem/utils";

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
    }
} as Program;

