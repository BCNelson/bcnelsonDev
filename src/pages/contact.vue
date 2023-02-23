<script setup lang="ts">
import Contacts from '../components/contacts.vue'
</script>

<template>
  <div class="absolute bg-white rounded-full p-3 m-3">
    <router-link to="/">
      <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"
        class="w-8 h-8">
        <path stroke-linecap="round" stroke-linejoin="round" d="M9 15L3 9m0 0l6-6M3 9h12a6 6 0 010 12h-3" />
      </svg>
    </router-link>
  </div>
  <Contacts class="h-screen" />
</template>