export * from './interface';
export * from './base';
import { Program } from './base';
import Echo from './echo';
import Clear from './clear';

export default new Map<string, Program>(Object.entries({
    echo: Echo,
    clear: Clear
}));