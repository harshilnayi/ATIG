<template>
  <div class="bg-slate-800 rounded-lg p-6">
    <h3 class="text-lg font-semibold text-white mb-4">Threat Intelligence</h3>
    <div class="grid grid-cols-2 gap-4">
      <div class="bg-slate-700 rounded p-4 text-center">
        <div class="text-2xl font-bold text-red-400">{{ threatCount.ip }}</div>
        <div class="text-xs text-slate-400 mt-1">Malicious IPs</div>
      </div>
      <div class="bg-slate-700 rounded p-4 text-center">
        <div class="text-2xl font-bold text-orange-400">{{ threatCount.url }}</div>
        <div class="text-xs text-slate-400 mt-1">Malware URLs</div>
      </div>
    </div>
    <div class="mt-4 text-xs text-slate-500 text-center">
      Last updated: {{ lastUpdate }}
    </div>
  </div>
</template>

<script setup>
import { ref, watch } from 'vue'

defineProps(['threatStats'])

const threatCount = ref({ ip: 0, url: 0 })
const lastUpdate = ref('Never')

watch(() => props.threatStats, (newVal) => {
  if (!newVal) return

  // Parse threat stats (this will be expanded when API provides detailed counts)
  threatCount.value.ip = Math.floor(newVal / 2)
  threatCount.value.url = Math.floor(newVal / 2)
  lastUpdate.value = new Date().toLocaleTimeString()
}, { immediate: true })
</script>
