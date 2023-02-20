
export enum FileType {
    text = "text",
    image = "image",
    video = "video",
    audio = "audio",
    link = "link",
}

export interface File {
    name: string;
    type: FileType;
    content: string | Uint8Array | (()=>Promise<string |Uint8Array>);
}

export function isFile(file: File | Directory): file is File {
    return (file as File).type !== undefined;
}

export interface Directory {
    name: string;
    files: File[];
    directories: Directory[];
}

export function isDirectory(file: File | Directory): file is Directory {
    return (file as Directory).directories !== undefined;
}