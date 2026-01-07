<script setup lang="ts">
import { ref, onMounted } from "vue";

interface Props {
  text: string;
  speed?: number;
  delay?: number;
}

const props = withDefaults(defineProps<Props>(), {
  speed: 50,
  delay: 500,
});

const displayText = ref("");
const showCursor = ref(true);

onMounted(() => {
  setTimeout(() => {
    let i = 0;
    const interval = setInterval(() => {
      if (i < props.text.length) {
        displayText.value += props.text.charAt(i);
        i++;
      } else {
        clearInterval(interval);
      }
    }, props.speed);
  }, props.delay);
});
</script>

<template>
  <span class="font-mono">
    {{ displayText }}
    <span v-if="showCursor" class="animate-blink">_</span>
  </span>
</template>
