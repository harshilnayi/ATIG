<template>
  <div class="min-h-screen bg-slate-900">
    <!-- Header -->
    <header class="bg-slate-800 border-b border-slate-700 px-6 py-4">
      <div class="flex justify-between items-center">
        <div>
          <h1 class="text-2xl font-bold text-white">ATIG Dashboard</h1>
          <p class="text-slate-400 text-sm mt-1">Network Intrusion Detection System</p>
        </div>
        <div class="flex items-center gap-4">
          <div class="flex items-center gap-2">
            <span class="w-2 h-2 rounded-full" :class="connectionStatusColor"></span>
            <span class="text-sm text-slate-400">{{ connectionStatus }}</span>
          </div>
          <button @click="refreshAll" class="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded-lg text-sm transition">
            Refresh
          </button>
        </div>
      </div>
    </header>

    <!-- Main Content -->
    <main class="px-6 py-6">
      <!-- Stats Cards -->
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <div class="bg-slate-800 rounded-lg p-4 border-l-4 border-blue-500">
          <div class="text-slate-400 text-sm">Total Alerts</div>
          <div class="text-3xl font-bold text-white mt-1">{{ stats.total_alerts || 0 }}</div>
          <div class="text-xs text-slate-500 mt-1">{{ stats.total_alerts || 0 }} total</div>
        </div>
        <div class="bg-slate-800 rounded-lg p-4 border-l-4 border-red-500">
          <div class="text-slate-400 text-sm">Critical</div>
          <div class="text-3xl font-bold text-red-400 mt-1">{{ stats.critical || 0 }}</div>
          <div class="text-xs text-slate-500 mt-1">Critical severity</div>
        </div>
        <div class="bg-slate-800 rounded-lg p-4 border-l-4 border-orange-500">
          <div class="text-slate-400 text-sm">High Severity</div>
          <div class="text-3xl font-bold text-orange-400 mt-1">{{ stats.high_severity || 0 }}</div>
          <div class="text-xs text-slate-500 mt-1">High severity</div>
        </div>
        <div class="bg-slate-800 rounded-lg p-4 border-l-4 border-yellow-500">
          <div class="text-slate-400 text-sm">Medium Severity</div>
          <div class="text-3xl font-bold text-yellow-400 mt-1">{{ stats.medium_severity || 0 }}</div>
          <div class="text-xs text-slate-500 mt-1">Medium severity</div>
        </div>
      </div>

      <!-- Charts Row -->
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <!-- Alert Timeline Chart -->
        <div class="bg-slate-800 rounded-lg p-6">
          <h3 class="text-lg font-semibold text-white mb-4">Alert Timeline (24h)</h3>
          <div class="h-64">
            <canvas ref="timelineChart"></canvas>
          </div>
        </div>

        <!-- Severity Distribution Chart -->
        <div class="bg-slate-800 rounded-lg p-6">
          <h3 class="text-lg font-semibold text-white mb-4">Severity Distribution</h3>
          <div class="h-64">
            <canvas ref="severityChart"></canvas>
          </div>
        </div>
      </div>

      <!-- Detection Types Chart -->
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
        <div class="bg-slate-800 rounded-lg p-6">
          <h3 class="text-lg font-semibold text-white mb-4">Detection Types</h3>
          <div class="h-48">
            <canvas ref="typeChart"></canvas>
          </div>
        </div>

        <!-- Top Source IPs -->
        <div class="bg-slate-800 rounded-lg p-6">
          <h3 class="text-lg font-semibold text-white mb-4">Top Source IPs</h3>
          <div class="space-y-2">
            <div v-for="(ip, idx) in topSourceIps.slice(0, 5)" :key="idx" class="flex justify-between items-center">
              <span class="text-sm text-slate-400">{{ ip.ip }}</span>
              <span class="text-sm font-medium text-white">{{ ip.count }}</span>
            </div>
          </div>
        </div>

        <!-- Top Targeted Ports -->
        <div class="bg-slate-800 rounded-lg p-6">
          <h3 class="text-lg font-semibold text-white mb-4">Top Targeted Ports</h3>
          <div class="space-y-2">
            <div v-for="(port, idx) in topPorts.slice(0, 5)" :key="idx" class="flex justify-between items-center">
              <span class="text-sm text-slate-400">Port {{ port.port }}</span>
              <span class="text-sm font-medium text-white">{{ port.count }}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Attack Patterns -->
      <div class="bg-slate-800 rounded-lg p-6 mb-6">
        <h3 class="text-lg font-semibold text-white mb-4">Attack Patterns</h3>
        <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
          <div
            v-for="(pattern, idx) in attackPatterns"
            :key="idx"
            class="bg-slate-700 rounded-lg p-4 text-center"
          >
            <div class="text-2xl font-bold" :class="getPatternColor(pattern.count)">{{ pattern.count }}</div>
            <div class="text-sm text-slate-400 mt-1">{{ formatPatternName(pattern.pattern) }}</div>
          </div>
        </div>
      </div>

      <!-- Alert Filters and Search -->
      <div class="bg-slate-800 rounded-lg p-6 mb-6">
        <div class="flex flex-wrap gap-4 mb-4">
          <input
            v-model="searchQuery"
            @input="filterAlerts"
            placeholder="Search alerts..."
            class="px-4 py-2 bg-slate-700 text-white rounded-lg text-sm w-64 focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
          <select
            v-model="selectedSeverity"
            @change="filterAlerts"
            class="px-4 py-2 bg-slate-700 text-white rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <select
            v-model="selectedType"
            @change="filterAlerts"
            class="px-4 py-2 bg-slate-700 text-white rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="">All Types</option>
            <option value="SIGNATURE">Signature</option>
            <option value="ANOMALY">Anomaly</option>
            <option value="THREAT_INTEL">Threat Intel</option>
          </select>
          <select
            v-model="timeRange"
            @change="filterAlerts"
            class="px-4 py-2 bg-slate-700 text-white rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="1h">Last Hour</option>
            <option value="24h">Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
            <option value="30d">Last 30 Days</option>
          </select>
          <button
            @click="exportAlerts"
            class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm transition"
          >
            Export
          </button>
        </div>
        <div class="text-sm text-slate-400">
          Showing {{ filteredAlerts.length }} alerts
        </div>
      </div>

      <!-- Live Alerts Feed -->
      <div class="bg-slate-800 rounded-lg p-6 mb-6">
        <div class="flex justify-between items-center mb-4">
          <h3 class="text-lg font-semibold text-white">Live Alerts</h3>
          <span class="text-sm text-slate-400">
            <span class="inline-block w-2 h-2 bg-green-500 rounded-full mr-2 animate-pulse"></span>
            {{ connectionStatus }}
          </span>
        </div>

        <div class="space-y-2 max-h-96 overflow-y-auto" v-if="filteredAlerts.length > 0">
          <div
            v-for="(alert, idx) in filteredAlerts"
            :key="alert.id"
            class="p-4 rounded border-l-4"
            :class="getSeverityBorder(alert.severity)"
          >
            <div class="flex justify-between items-start">
              <div class="flex-1">
                <div class="font-medium text-white">{{ alert.message || alert.signature_msg }}</div>
                <div class="text-sm text-slate-400 mt-1">
                  {{ alert.src_ip || 'N/A' }} → {{ alert.dst_ip || 'N/A' }}
                  <span class="mx-2">•</span>
                  Port {{ alert.dest_port || 'N/A' }}
                </div>
                <div class="text-xs text-slate-500 mt-1">
                  {{ formatTime(alert.timestamp) }} • {{ alert.type || alert.detection_type }}
                </div>
              </div>
              <span
                class="px-2 py-1 rounded text-xs font-medium"
                :class="getSeverityBadge(alert.severity)"
              >
                {{ alert.severity?.toUpperCase() || alert.type?.toUpperCase() || 'UNKNOWN' }}
              </span>
            </div>
          </div>
        </div>

        <div v-else class="text-center py-12 text-slate-500">
          <svg class="w-12 h-12 mx-auto mb-3 text-slate-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
          </svg>
          No alerts found. Traffic is being monitored...
        </div>
      </div>

      <!-- Threat Intelligence -->
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <div class="bg-slate-800 rounded-lg p-6">
          <h3 class="text-lg font-semibold text-white mb-4">Threat Intelligence</h3>
          <div class="space-y-3">
            <div class="flex justify-between items-center">
              <span class="text-sm text-slate-400">Active Indicators</span>
              <span class="text-lg font-bold text-red-400">{{ stats.threat_intel_indicators || 0 }}</span>
            </div>
            <div class="flex justify-between items-center">
              <span class="text-sm text-slate-400">Feeds Connected</span>
              <span class="text-lg font-bold text-green-400">3</span>
            </div>
            <div class="flex justify-between items-center">
              <span class="text-sm text-slate-400">Last Updated</span>
              <span class="text-sm text-slate-400">{{ threatIntelLastUpdated }}</span>
            </div>
          </div>
        </div>

        <!-- Top Threats -->
        <div class="bg-slate-800 rounded-lg p-6">
          <h3 class="text-lg font-semibold text-white mb-4">Top Threats</h3>
          <div class="space-y-2">
    <!-- Empty state when no threats -->
    <div v-if="topThreats.length === 0" class="text-center py-6">
      <div class="text-4xl mb-2">🛡️</div>
      <div class="text-slate-400 text-sm">No malicious IPs detected yet</div>
    </div>
    <!-- Threat list -->
    <div v-else
              v-for="(threat, idx) in topThreats.slice(0, 5)"
              :key="idx"
              class="flex justify-between items-center p-3 bg-slate-700 rounded"
            >
              <div>
                <div class="text-sm font-medium text-white">{{ threat.ip }}</div>
                <div class="text-xs text-slate-400 mt-1">{{ threat.alert_count }} alerts</div>
              </div>
              <span
                class="px-2 py-1 rounded text-xs font-medium"
                :class="getThreatLevelClass(threat.risk_level)"
              >
                {{ threat.risk_level?.toUpperCase() || 'UNKNOWN' }}
              </span>
            </div>
          </div>
        </div>
      </div>

      <!-- Correlated Attacks -->
      <div class="bg-slate-800 rounded-lg p-6 mb-6" v-if="correlations.length > 0">
        <h3 class="text-lg font-semibold text-white mb-4">Correlated Attack Patterns</h3>
        <div class="space-y-2">
          <div
            v-for="(corr, idx) in correlations"
            :key="idx"
            class="p-4 bg-slate-700 rounded border-l-4"
            :class="getCorrelationSeverityClass(corr.severity)"
          >
            <div class="flex justify-between items-start">
              <div>
                <div class="font-medium text-white">{{ corr.correlation_name }}</div>
                <div class="text-sm text-slate-400 mt-1">
                  {{ corr.matched_alerts }} alerts detected
                </div>
                <div class="text-xs text-slate-500 mt-1">
                  {{ formatTime(corr.first_seen) }} - {{ formatTime(corr.last_seen) }}
                </div>
              </div>
              <span
                class="px-2 py-1 rounded text-xs font-medium"
                :class="getSeverityBadge(corr.severity)"
              >
                {{ corr.severity?.toUpperCase() }}
              </span>
            </div>
          </div>
        </div>
      </div>

      <!-- System Status -->
      <div class="bg-slate-800 rounded-lg p-6">
        <h3 class="text-lg font-semibold text-white mb-4">System Status</h3>
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div class="bg-slate-700 rounded p-4 text-center">
            <div class="text-2xl font-bold text-green-400">{{ systemStatus.rules_loaded }}</div>
            <div class="text-xs text-slate-400 mt-1">Rules Loaded</div>
          </div>
          <div class="bg-slate-700 rounded p-4 text-center">
            <div class="text-2xl font-bold text-blue-400">{{ systemStatus.webhooks_configured }}</div>
            <div class="text-xs text-slate-400 mt-1">Webhooks</div>
          </div>
          <div class="bg-slate-700 rounded p-4 text-center">
            <div class="text-2xl font-bold text-purple-400">{{ systemStatus.blocked_ips }}</div>
            <div class="text-xs text-slate-400 mt-1">Blocked IPs</div>
          </div>
          <div class="bg-slate-700 rounded p-4 text-center">
            <div class="text-2xl font-bold text-orange-400">{{ systemStatus.threat_intel ? systemStatus.threat_intel.split(' ')[0] : 0 }}</div>
            <div class="text-xs text-slate-400 mt-1">Threat Intel</div>
          </div>
        </div>
      </div>
    </main>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted, computed } from 'vue'
import axios from 'axios'
import { Chart as ChartJS, CategoryScale, LinearScale, PointElement, LineElement, BarElement, ArcElement, Title, Tooltip, Legend, LineController, BarController, DoughnutController } from 'chart.js'
import { format } from 'date-fns'

// Register Chart.js components
ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, BarElement, ArcElement, Title, Tooltip, Legend, LineController, BarController, DoughnutController)

const alerts = ref([])
const stats = ref({})
const connectionStatus = ref('Connecting...')
const ws = ref(null)

// Search and filters
const searchQuery = ref('')
const selectedSeverity = ref('')
const selectedType = ref('')
const timeRange = ref('24h')

// Analytics data
const topSourceIps = ref([])
const topPorts = ref([])
const attackPatterns = ref([])
const correlations = ref([])
const topThreats = ref([])
const threatIntelLastUpdated = ref('Never')
const timelineData = ref([])

// System status
const systemStatus = ref({
  rules_loaded: 0,
  webhooks_configured: 0,
  blocked_ips: 0,
  threat_intel_indicators: 0
})

// Chart refs
const timelineChart = ref(null)
const severityChart = ref(null)
const typeChart = ref(null)

// Chart instances
let timelineChartInstance = null
let severityChartInstance = null
let typeChartInstance = null

const connectionStatusColor = computed(() => {
  switch (connectionStatus.value) {
    case 'Connected': return 'bg-green-500'
    case 'Connecting...': return 'bg-yellow-500'
    case 'Disconnected': return 'bg-red-500'
    default: return 'bg-slate-500'
  }
})

const filteredAlerts = computed(() => {
  let result = alerts.value

  if (searchQuery.value) {
    const query = searchQuery.value.toLowerCase()
    result = result.filter(alert =>
      (alert.message || alert.signature_msg || '').toLowerCase().includes(query) ||
      (alert.src_ip || '').includes(query)
    )
  }

  if (selectedSeverity.value) {
    result = result.filter(alert => alert.severity === selectedSeverity.value)
  }

  if (selectedType.value) {
    result = result.filter(alert => alert.type === selectedType.value || alert.detection_type === selectedType.value)
  }

  return result
})

const formatTime = (timestamp) => {
  if (!timestamp) return 'N/A'
  return format(new Date(timestamp), 'MMM d, yyyy HH:mm:ss')
}

const formatPatternName = (pattern) => {
  const names = {
    'sql_injection': 'SQL Injection',
    'xss': 'XSS',
    'brute_force': 'Brute Force',
    'scan': 'Scanning',
    'exploit': 'Exploits',
    'data_exfil': 'Data Exfiltration'
  }
  return names[pattern] || pattern
}

const getSeverityBorder = (severity) => {
  const colors = {
    'critical': 'border-red-500',
    'high': 'border-orange-500',
    'medium': 'border-yellow-500',
    'low': 'border-blue-500'
  }
  return colors[severity] || 'border-slate-500'
}

const getSeverityBadge = (severity) => {
  const classes = {
    'critical': 'bg-red-900 text-red-200',
    'high': 'bg-orange-900 text-orange-200',
    'medium': 'bg-yellow-900 text-yellow-200',
    'low': 'bg-blue-900 text-blue-200'
  }
  return classes[severity] || 'bg-slate-700 text-slate-200'
}

const getPatternColor = (count) => {
  if (count >= 10) return 'text-red-400'
  if (count >= 5) return 'text-orange-400'
  if (count >= 3) return 'text-yellow-400'
  return 'text-slate-400'
}

const getThreatLevelClass = (level) => {
  const classes = {
    'critical': 'bg-red-900 text-red-200',
    'high': 'bg-orange-900 text-orange-200',
    'medium': 'bg-yellow-900 text-yellow-200',
    'low': 'bg-blue-900 text-blue-200'
  }
  return classes[level] || 'bg-slate-700 text-slate-200'
}

const getCorrelationSeverityClass = (severity) => {
  const colors = {
    'critical': 'border-red-500',
    'high': 'border-orange-500',
    'medium': 'border-yellow-500',
    'low': 'border-blue-500'
  }
  return colors[severity] || 'border-slate-500'
}

const connectWebSocket = () => {
  ws.value = new WebSocket('ws://localhost:8001/ws/alerts')

  ws.value.onopen = () => {
    connectionStatus.value = 'Connected'
  }

  ws.value.onmessage = (event) => {
    const alert = JSON.parse(event.data)
    alerts.value.unshift(alert)
    if (alerts.value.length > 100) {
      alerts.value = alerts.value.slice(0, 100)
    }
  }

  ws.value.onerror = () => {
    connectionStatus.value = 'Disconnected'
  }

  ws.value.onclose = () => {
    connectionStatus.value = 'Reconnecting...'
    setTimeout(connectWebSocket, 8001)
  }
}

const fetchStats = async () => {
  try {
    const response = await axios.get('/stats')
    stats.value = response.data
  } catch (error) {
    console.error('Failed to fetch stats:', error)
  }
}

const fetchAlerts = async () => {
  try {
    const response = await axios.get('/alerts?limit=100')
    alerts.value = response.data
  } catch (error) {
    console.error('Failed to fetch alerts:', error)
  }
}

const fetchAnalytics = async () => {
  try {
    const [topPortsRes, topSourceRes, patternsRes, threatsRes, correlationsData, systemStatusData, timeline] = await Promise.all([
      axios.get('/analytics/top-ports'),
      axios.get('/analytics/top-source-ips'),
      axios.get('/analytics/attack-patterns'),
      axios.get('/threats/top'),
      axios.get('/threats/correlations'),
      axios.get('/system/status'),
      axios.get('/alerts/timeline?hours=24')
    ])

    console.log('Raw API responses:', {
      topPortsRes: topPortsRes.data,
      topSourceRes: topSourceRes.data,
      patternsRes: patternsRes.data,
      threatsRes: threatsRes.data
    })

    topPorts.value = topPortsRes.data.top_ports || []
    topSourceIps.value = topSourceRes.data.top_source_ips || []
    attackPatterns.value = patternsRes.data.attack_patterns || []
    topThreats.value = threatsRes.data.top_threats || []
    correlations.value = correlationsData.data.correlations || []
    systemStatus.value = systemStatusData.data.components || {}
    timelineData.value = timeline.data.timeline || []

    console.log('Analytics after assignment:', {
      topPorts: topPorts.value,
      topSourceIps: topSourceIps.value,
      attackPatterns: attackPatterns.value,
      topThreats: topThreats.value,
      timelineData: timelineData.value
    })
  } catch (error) {
    console.error('Failed to fetch analytics:', error)
  }
}

const initCharts = () => {
  // Timeline Chart - Initialize with 24 hours of data
  if (timelineChart.value) {
    const now = new Date()
    const initialLabels = []
    const initialData = []

    // Create 24-hour labels from 24 hours ago to now
    for (let i = 23; i >= 0; i--) {
      const hour = new Date(now.getTime() - i * 60 * 60 * 1000)
      initialLabels.push(hour.getHours().toString().padStart(2, '0') + ':00')
      initialData.push(0)
    }

    timelineChartInstance = new ChartJS(timelineChart.value, {
      type: 'line',
      data: {
        labels: initialLabels,
        datasets: [{
          label: 'Alerts',
          data: initialData,
          borderColor: '#60a5fa',
          backgroundColor: 'rgba(96, 165, 250, 0.15)',
          borderWidth: 3,
          tension: 0.6,
          fill: true,
          pointRadius: 0,
          pointHoverRadius: 8,
          pointBackgroundColor: '#60a5fa',
          pointBorderColor: '#1e293b',
          pointBorderWidth: 2,
          borderJoinStyle: 'round',
          spanGaps: true
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            display: false
          },
          tooltip: {
            backgroundColor: 'rgba(15, 23, 42, 0.9)',
            titleColor: '#94a3b8',
            bodyColor: '#fff',
            borderColor: '#3b82f6',
            borderWidth: 1
          }
        },
        scales: {
          y: {
            beginAtZero: true,
            ticks: {
              color: '#94a3b8'
            },
            grid: {
              color: '#334155'
            }
          },
          x: {
            ticks: {
              color: '#94a3b8'
            },
            grid: {
              color: '#334155'
            }
          }
        },
        animation: {
          duration: 1000,
          easing: 'easeInOutQuart'
        }
      }
    })
  }

  // Severity Chart
  if (severityChart.value) {
    severityChartInstance = new ChartJS(severityChart.value, {
      type: 'doughnut',
      data: {
        labels: ['Critical', 'High', 'Medium', 'Low'],
        datasets: [{
          data: [0, 0, 0, 0],
          backgroundColor: [
            'rgba(239, 68, 68, 0.8)',
            'rgba(249, 115, 22, 0.8)',
            'rgba(234, 179, 8, 0.8)',
            'rgba(59, 130, 246, 0.8)'
          ],
          borderColor: '#1e293b'
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'bottom',
            labels: {
              color: '#94a3b8'
            }
          }
        }
      }
    })
  }

  // Type Chart
  if (typeChart.value) {
    typeChartInstance = new ChartJS(typeChart.value, {
      type: 'bar',
      data: {
        labels: ['Signature', 'Anomaly', 'Threat Intel'],
        datasets: [{
          label: 'Alerts',
          data: [0, 0, 0],
          backgroundColor: [
            'rgba(59, 130, 246, 0.8)',
            'rgba(168, 85, 247, 0.8)',
            'rgba(239, 68, 68, 0.8)'
          ],
          borderColor: '#1e293b'
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            labels: {
              color: '#94a3b8'
            }
          }
        },
        scales: {
          y: {
            beginAtZero: true,
            ticks: {
              color: '#94a3b8'
            },
            grid: {
              color: '#334155'
            }
          },
          x: {
            ticks: {
              color: '#94a3b8'
            },
            grid: {
              color: '#334155'
            }
          }
        }
      }
    })
  }
}

const updateCharts = () => {
  // Update severity chart
  if (severityChartInstance) {
    severityChartInstance.data.datasets[0].data = [
      stats.value.critical || 0,
      stats.value.high_severity || 0,
      stats.value.medium_severity || 0,
      stats.value.low_severity || 0
    ]
    severityChartInstance.update()
  }

  // Update type chart
  if (typeChartInstance) {
    typeChartInstance.data.datasets[0].data = [
      stats.value.signature_detections || 0,
      stats.value.anomaly_detections || 0,
      stats.value.threat_intel_detections || 0
    ]
    typeChartInstance.update()
  }

  // Update timeline chart - update existing chart data
  if (timelineChartInstance) {
    const labels = []
    const data = []

    // Always use all 24 hours
    if (timelineData.value && timelineData.value.length > 0) {
      timelineData.value.forEach(item => {
        const time = item.timestamp || ''
        const hour = time.split(' ')[1]?.split(':')[0] || time.slice(-5)
        labels.push(hour + ':00')
        data.push(item.total || 0)
      })
    }

    // Update the existing chart's dataset values
    timelineChartInstance.data.datasets[0].data = data.length > 0 ? data : timelineChartInstance.data.datasets[0].data
    timelineChartInstance.update()
  }
}

const filterAlerts = () => {
  // Filter logic is handled by computed property
}

const refreshAll = async () => {
  await fetchStats()
  await fetchAlerts()
  await fetchAnalytics()
  updateCharts()
}

const exportAlerts = async () => {
  try {
    const response = await axios.get('/alerts/export?format=json')
    const blob = new Blob([JSON.stringify(response.data, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `atig_alerts_${new Date().toISOString()}.json`
    a.click()
    URL.revokeObjectURL(url)
  } catch (error) {
    console.error('Export failed:', error)
  }
}

onMounted(async () => {
  connectWebSocket()
  await fetchStats()
  await fetchAlerts()
  await fetchAnalytics()
  initCharts()
  updateCharts() // Update charts with real data after fetching

  // Set up periodic refresh
  setInterval(() => {
    fetchStats()
    fetchAlerts()
  }, 10000)

  setInterval(() => {
    fetchAnalytics()
    updateCharts()
  }, 30000)
})

onUnmounted(() => {
  if (ws.value) {
    ws.value.close()
  }
  if (timelineChartInstance) {
    timelineChartInstance.destroy()
  }
  if (severityChartInstance) {
    severityChartInstance.destroy()
  }
  if (typeChartInstance) {
    typeChartInstance.destroy()
  }
})
</script>
