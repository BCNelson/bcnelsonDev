<template>
    <div class="grid md:grid-cols-3">
        <div class="md:col-span-1 bg-gray-100 bg-opacity-80 rounded-md mx-4">
            <div class="flex flex-col items-center p-4">
                <img class="rounded-full w-32 h-32 drop-shadow-md hover:drop-shadow-2xl mb-4 transition ease-in-out duration-1000"
                    src="https://www.gravatar.com/avatar/29af645b8dabf75efa258579964a8137?s=500" alt="Bradley Nelson">
                <h1 class="text-2xl font-bold">Bradley Nelson</h1>
                <h2 class="text-xl font-medium">Software Engineer</h2>
                <button @click="handleContact()"
                    class="relative inline-flex items-center justify-center p-0.5 mb-1 mr-1 overflow-hidden text-sm font-medium text-gray-900 rounded-full group bg-gradient-to-br from-gray-600 to-blue-500 group-hover:from-purple-600 group-hover:to-blue-500 hover:text-white dark:text-white focus:ring-4 focus:outline-none focus:ring-blue-300 dark:focus:ring-blue-800">
                    <span
                        class="relative px-4 py-1.5 transition-all ease-in duration-75 bg-gray-100 dark:bg-gray-900 rounded-full group-hover:bg-opacity-0">
                        Contact
                    </span>
                </button>
                <p class="text-lg font-medium">My first love was C/C++ on the Arduino Uno. Recently I have diving deep into
                    node.js. Right now I'm exited to be learning Golang.</p>
            </div>
        </div>
        <div class="md:col-span-2 p-4 pt-8 mx-4 bg-gray-100 bg-opacity-80 rounded-md">
            <ul>
                <li>
                    <SkillMeter name="Node.JS" :rank='95' />
                </li>
                <li>
                    <SkillMeter name="Typescript" :rank='85' />
                </li>
                <li>
                    <SkillMeter name="C/C++" :rank='60' />
                </li>
                <li>
                    <SkillMeter name="Golang" :rank='50' />
                </li>
                <li>
                    <SkillMeter name="Python" :rank='40' />
                </li>
            </ul>
        </div>
    </div>
</template>
  
<script setup lang="ts">
import SkillMeter from './SkillMeter.vue'
import { useRouter } from 'vue-router'
const router = useRouter()

const handleContact = () => {
    router.push('/contact')
}
</script>