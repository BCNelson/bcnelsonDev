import { Directory } from "./types";

export default {
    name: '',
    files: [],
    directories: [{
        name: 'home',
        files: [],
        directories: [{
            name: 'bcnelson',
            files: [{
                name: 'resume.txt',
                type: 'text',
                content: 'TBD'
            }],
            directories: []
        },{
            name: 'visitor',
            files: [
                {
                    name: 'readme.md',
                    type: 'text',
                    content: 'Welcome to my website! Feel free to poke around and see what you can find.'
                },
            ],
            directories: []
        }]
    }]
} as Directory;
