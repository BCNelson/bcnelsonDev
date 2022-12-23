import type { ProgramInterface, Context } from './interface';


export interface Program {
    run(programInterface: ProgramInterface): Promise<number>;
    suggest(context: Context): Promise<string>;
}