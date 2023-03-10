import { Directory } from "./types";

export default {
    name: '',
    files: [{
        name: 'README.md',
        type: 'text',
        content: 'Welcome to my website! Feel free to poke around and see what you can find.'
    }],
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
                {
                    name: "resume.pdf",
                    type: "link",
                    content: "/resume.pdf"
                }
            ],
            directories: []
        }]
    }]
} as Directory;
