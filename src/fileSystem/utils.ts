import root from "./index";
import { Directory } from "./types";
import { File } from "./types";

export async function getFile(absolutePath: string, filesystem = root): Promise<File> {
    if(!absolutePath.startsWith('/')) throw new Error('Absolute path must start with /');
    if(absolutePath.endsWith('/')) throw new Error('Absolute path must be a file');
    const path = absolutePath.split('/').filter((p) => p !== '');
    let current = filesystem;
    const filename = path.pop();
    for(const p of path) {
        let next = current.directories.find((d) => d.name === p);
        if(!next) {
            throw new Error(`${absolutePath}: No such file or directory`);
        }
        current = next;
    }
    const file = current.files.find((f) => f.name === filename);
    if(!file) {
        throw new Error(`${absolutePath}: No such file or directory`);
    }
    return file;
}

export async function getFileContents(file: File): Promise<string | Uint8Array> {
    let content = file.content;
    if(typeof content === 'function') {
        content = await content();
    }
    return content;
}

export async function getContents(absolutePath: string, filesystem = root): Promise<string | Uint8Array> {
    const file = await getFile(absolutePath, filesystem);
    let content = file.content;
    if(typeof content === 'function') {
        content = await content();
    }
    return content;
}

export async function getDirectory(absolutePath: string, filesystem = root): Promise<Directory> {
    if(!absolutePath.startsWith('/')) throw new Error('Absolute path must start with /');
    const path = absolutePath.split('/').filter((p) => p !== '');
    let current = filesystem;
    for(const p of path) {
        let next = current.directories.find((d) => d.name === p);
        if(!next) {
            throw new Error(`${absolutePath}: No such file or directory`);
        }
        current = next;
    }
    return current;
}

export function resolvePath(currentWorkingDirectory: string, path: string, homePath: string): string {
    if(path.startsWith('/')) return path;
    if(path.startsWith('~')){
        currentWorkingDirectory = homePath;
    }
    const resolvedPath = currentWorkingDirectory.split('/').filter((p) => p !== '' && p !== '.');
    const pathParts = path.split('/').filter((p) => p !== '' && p !== '.');
    for(const part of pathParts) {
        if(part === '..') {
            resolvedPath.pop();
        } else {
            resolvedPath.push(part);
        }
    }

    return '/' + resolvedPath.join('/');
}