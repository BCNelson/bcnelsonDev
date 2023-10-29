import { createApp } from 'vue'
import './style.css'
import App from './App.vue'
import { router } from './routes'

createApp(App).use(router).mount('#app')

if (import.meta.env.PROD) {
    const umami = document.createElement('script');
    umami.setAttribute('async', '');
    umami.setAttribute('defer', '');
    umami.setAttribute('data-website-id', 'd5670f6f-8623-41ef-9987-b250b4e8ea77');
    umami.setAttribute('src', 'https://t.nel.to/script.js');
    document.body.appendChild(umami);
} else {
    console.log('dev mode');
    globalThis.umami = new Proxy({}, {
        get: function (target, prop, receiver) {
            if (prop !== "track") throw new Error("Property Not supported")
            return function () {
                console.log(`umami`, prop, ...arguments);
            }
        },
        set (target, prop, value) {
            console.log('umami', prop, value);
            return true;
        }
    }) as any;
}