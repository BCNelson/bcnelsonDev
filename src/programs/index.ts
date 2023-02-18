export * from './interface';
export * from './base';
import { Program } from './base';
import Echo from './implementations/echo';
import Clear from './implementations/clear';
import Ls from './implementations/ls';
import Cat from './implementations/cat';
import Cd from './implementations/cd';
import History from './implementations/history';

export default new Map<string, Program>(Object.entries({
    echo: Echo,
    clear: Clear,
    ls: Ls,
    cat: Cat,
    cd: Cd,
    history: History
}));