
export enum FileType {
    text = "text",
    image = "image",
    video = "video",
    audio = "audio",
}

export interface File {
    name: string;
    type: FileType;
    content: string | Uint8Array;
}

export interface Directory {
    name: string;
    files: File[];
    directories: Directory[];
}