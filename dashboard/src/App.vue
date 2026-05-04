<template>
  <div class="min-h-screen p-6">
    <header class="mb-8">
      <h1 class="text-3xl font-bold text-white">ATIG Dashboard</h1>
      <p class="text-slate-400 mt-1">Network Intrusion Detection System</p>
    </header>

    <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
      <div class="bg-slate-800 rounded-lg p-4">
        <div class="text-slate-400 text-sm">Total Alerts</div>
        <div class="text-3xl font-bold text-white">{{ stats.total_alerts || 0 }}</div>
      </div>
      <div class="bg-slate-800 rounded-lg p-4 border-l-4 border-red-500">
        <div class="text-slate-400 text-sm">High Severity</div>
        <div class="text-3xl font-bold text-red-400">{{ stats.high_severity || 0 }}</div>
      </div>
      <div class="bg-slate-800 rounded-lg p-4 border-l-4 border-yellow-500">
        <div class="text-slate-400 text-sm">Signature Detections</div>
        <div class="text-3xl font-bold text-yellow-400">{{ stats.signature_detections || 0 }}</div>
      </div>
      <div class="bg-slate-800 rounded-lg p-4 border-l-4 border-purple-500">
        <div class="text-slate-400 text-sm">Anomaly Detections</div>
        <div class="text-3xl font-bold text-purple-400">{{ stats.anomaly_detections || 0 }}</div>
      </div>
    </div>

    <div class="bg-slate-800 rounded-lg p-6">
      <div class="flex justify-between items-center mb-4">
        <h2 class="text-xl font-semibold text-white">Live Alerts</h2>
        <span class="text-sm text-slate-400">
          <span class="inline-block w-2 h-2 bg-green-500 rounded-full mr-2 animate-pulse"></span>
          {{ connectionStatus }}
        </span>
      </div>

      <div class="space-y-2 max-h-96 overflow-y-auto" v-if="alerts.length > 0">
        <div
          v-for="alert in alerts"
          :key="alert.timestamp + Math.random()"
          class="p-4 rounded alert-{{ alert.severity }}"
        >
          <div class="flex justify-between items-start">
            <div>
              <div class="font-medium text-white">{{ alert.message || alert.type }}</div>
              <div class="text-sm text-slate-400 mt-1">
                {{ alert.src_ip }} → {{ alert.dst_ip }}
              </div>
              <div class="text-xs text-slate-500 mt-1">
                {{ formatTime(alert.timestamp) }}
              </div>
            </div>
            <span
              class="px-2 py-1 rounded text-xs font-medium"
              :class="severityClass(alert.severity)"
            >
              {{ alert.severity?.toUpperCase() || alert.type }}
            </span>
          </div>
        </div>
      </div>

      <div v-else class="text-center py-12 text-slate-500">
        No alerts yet. Traffic is being monitored...
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import axios from 'axios'

const alerts = ref([])
const stats = ref({})
const connectionStatus = ref('Connecting...')
let ws = null

const severityClass = (severity) => {
  const classes = {
    'critical': 'bg-red-900 text-red-200',
    'high': 'bg-orange-900 text-orange-200',
    'medium': 'bg-yellow-900 text-yellow-200',
    'low': 'bg-blue-900 text-blue-200'
  }
  return classes[severity] || 'bg-slate-700 text-slate-200'
}

const formatTime = (timestamp) => {
  return new Date(timestamp).toLocaleTimeString()
}

const connectWebSocket = () => {
  ws = new WebSocket('ws://localhost:8000/ws/alerts')

  ws.onopen = () => {
    connectionStatus.value = 'Connected'
  }

  ws.onmessage = (event) => {
    const alert = JSON.parse(event.data)
    alerts.value.unshift(alert)
    if (alerts.value.length > 50) {
      alerts.value = alerts.value.slice(0, 50)
    }
  }

  ws.onerror = () => {
    connectionStatus.value = 'Disconnected'
  }

  ws.onclose = () => {
    connectionStatus.value = 'Reconnecting...'
    setTimeout(connectWebSocket, 3000)
  }
}

const fetchStats = async () => {
  try {
    const response = await axios.get('http://localhost:8000/stats')
    stats.value = response.data
  } catch (error) {
    console.error('Failed to fetch stats:', error)
  }
}

const fetchAlerts = async () => {
  try {
    const response = await axios.get('http://localhost:8000/alerts?limit=20')
    alerts.value = response.data
  } catch (error) {
    console.error('Failed to fetch alerts:', error)
  }
}

onMounted(() => {
  connectWebSocket()
  fetchStats()
  fetchAlerts()
  setInterval(fetchStats, 10000)
})

onUnmounted(() => {
  if (ws) {
    ws.close()
  }
})
</script>
