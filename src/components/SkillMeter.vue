<template>
    <div class="p-1 m-2 bg-black bg-opacity-5 rounded-xl">
        <div class="flex items-center justify-between">
            <span class="text-lg font-medium pr-3">{{ props.name }}</span>
            <span class="text-md font-medium text-gray-500 dark:text-gray-400">{{ label }}</span>
        </div>
        <div class="w-full bg-gray-200 rounded-full h-2.5 dark:bg-gray-700 mb-1">
            <div ref="progressBar" class="bg-blue-600 h-2.5 rounded-full" :style="{ width: rank + '%' }"></div>
        </div>
    </div>
</template>
  
<script setup lang="ts">
import { computed } from 'vue';


const props = defineProps({
    name: { type: String, required: true },
    rank: { type: Number, required: true },
    max: { type: Number, default: 100 }
});

const rank = computed(() => {
    return props.rank / props.max * 100
})

const label = computed(() => {
    if (props.max === 100)
        return `${Math.round(rank.value)}%`
    else
        return `${props.rank}/${props.max}`
})
</script>