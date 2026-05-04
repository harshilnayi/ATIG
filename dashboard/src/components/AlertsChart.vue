<template>
  <div class="bg-slate-800 rounded-lg p-6">
    <h3 class="text-lg font-semibold text-white mb-4">Alerts by Type</h3>
    <div class="space-y-3">
      <div
        v-for="type in alertTypes"
        :key="type.label"
        class="flex items-center"
      >
        <div class="w-24 text-sm text-slate-400">{{ type.label }}</div>
        <div class="flex-1 bg-slate-700 rounded-full h-6 overflow-hidden">
          <div
            class="h-full rounded-full transition-all duration-500"
            :style="{ width: type.percent + '%', background: type.color }"
          ></div>
        </div>
        <div class="ml-3 text-sm font-medium text-white">{{ type.count }}</div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, watch } from 'vue'

defineProps(['stats'])

const alertTypes = ref([
  { label: 'Signature', count: 0, percent: 0, color: '#3b82f6' },
  { label: 'Anomaly', count: 0, percent: 0, color: '#a855f7' },
])

watch(() => props.stats, (newVal) => {
  if (!newVal) return

  const total = newVal.signature_detections + newVal.anomaly_detections || 1

  alertTypes.value[0].count = newVal.signature_detections || 0
  alertTypes.value[0].percent = (newVal.signature_detections / total) * 100

  alertTypes.value[1].count = newVal.anomaly_detections || 0
  alertTypes.value[1].percent = (newVal.anomaly_detections / total) * 100
}, { immediate: true })
</script>
