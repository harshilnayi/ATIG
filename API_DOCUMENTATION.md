# 📡 ATIG API Documentation

**Complete API reference for all endpoints**

---

## Base URL

```
http://localhost:8001
```

---

## 🔍 Core Endpoints

### Health & Status

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | API information |
| `GET` | `/health` | Health check |
| `GET` | `/system/status` | System status with components |
| `GET` | `/rules` | List all detection rules |
| `GET` | `/rules/reload` | Reload detection rules |

**Example:**
```powershell
Invoke-RestMethod -Uri "http://localhost:8001/health"
```

**Response:**
```json
{
  "health": "ok",
  "timestamp": "2026-05-06T15:30:00.000000"
}
```

---

### Packet Analysis

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/packet/analyze` | Analyze packet for threats |

**Query Parameters:**
- `src_ip` - Source IP address
- `dst_ip` - Destination IP address
- `src_port` - Source port
- `dst_port` - Destination port
- `protocol` - Protocol (tcp, udp, icmp)
- `payload` - Packet payload content

**Example:**
```powershell
$payload = "UNION SELECT * FROM users"
$uri = "http://localhost:8001/packet/analyze?src_ip=192.168.1.100&dst_ip=10.0.0.1&src_port=54321&dst_port=80&protocol=tcp&payload=" + [System.Web.HttpUtility]::UrlEncode($payload)
Invoke-RestMethod -Uri $uri -Method POST
```

**Response:**
```json
{
  "analysis": [
    {
      "type": "SIGNATURE",
      "rule_id": "2000001",
      "message": "ET WEB_SERVER SQL Injection UNION SELECT",
      "severity": "medium"
    }
  ],
  "packets_analyzed": 1
}
```

---

### Alerts

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/alerts` | Get recent alerts |
| `GET` | `/alerts?limit=100` | Get limited alerts |
| `GET` | `/alerts/recent` | Recent alerts with correlations |
| `GET` | `/alerts/search?q=query` | Search alerts |
| `GET` | `/alerts/by-severity/{severity}` | Filter by severity |
| `GET` | `/alerts/by-type/{type}` | Filter by detection type |
| `GET` | `/alerts/summary` | Alert summary statistics |
| `GET` | `/alerts/timeline?hours=24` | Timeline for last N hours |
| `GET` | `/alerts/export?format=json` | Export as JSON/CSV |
| `GET` | `/alerts/acknowledge/{alert_id}` | Mark as acknowledged |
| `GET` | `/alerts/resolve/{alert_id}` | Mark as resolved |

**Example - Get Alerts:**
```powershell
Invoke-RestMethod -Uri "http://localhost:8001/alerts?limit=10" | ConvertTo-Json
```

**Response:**
```json
[
  {
    "id": "abc-123-def",
    "timestamp": "2026-05-06T15:30:00.000000",
    "severity": "medium",
    "type": "SIGNATURE",
    "src_ip": "192.168.1.100",
    "dst_ip": "10.0.0.1",
    "message": "ET WEB_SERVER SQL Injection UNION SELECT"
  }
]
```

**Example - Search Alerts:**
```powershell
Invoke-RestMethod -Uri "http://localhost:8001/alerts/search?q=SQL&limit=10" | ConvertTo-Json
```

**Example - Export:**
```powershell
Invoke-RestMethod -Uri "http://localhost:8001/alerts/export?format=json" | ConvertTo-Json
```

---

### Statistics

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/stats` | Dashboard statistics |
| `GET` | `/dashboard/comprehensive` | All dashboard data |
| `GET` | `/dashboard/extended-stats` | Extended stats with threats |

**Example:**
```powershell
Invoke-RestMethod -Uri "http://localhost:8001/stats" | ConvertTo-Json
```

**Response:**
```json
{
  "total_alerts": 150,
  "high_severity": 25,
  "signature_detections": 120,
  "anomaly_detections": 20,
  "threat_intel_indicators": 8
}
```

---

### Analytics

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/analytics/attack-patterns` | Attack pattern breakdown |
| `GET` | `/analytics/top-ports` | Most targeted ports |
| `GET` | `/analytics/top-source-ips` | Top source IPs |
| `GET` | `/analytics/alerts-by-hour?hours=24` | Hourly alert counts |
| `GET` | `/analytics/severity-trends?days=7` | Severity trends |

**Example - Attack Patterns:**
```powershell
Invoke-RestMethod -Uri "http://localhost:8001/analytics/attack-patterns" | ConvertTo-Json
```

**Response:**
```json
{
  "attack_patterns": [
    {"pattern": "sql_injection", "count": 45},
    {"pattern": "xss", "count": 30},
    {"pattern": "brute_force", "count": 25},
    {"pattern": "scan", "count": 20},
    {"pattern": "exploit", "count": 15},
    {"pattern": "data_exfil", "count": 10}
  ]
}
```

---

### Threat Intelligence

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/threats/top?limit=10` | Top dangerous IPs |
| `GET` | `/threats/ip/{ip}` | IP reputation info |
| `GET` | `/threats/correlations` | Correlated attacks |

**Example - Top Threats:**
```powershell
Invoke-RestMethod -Uri "http://localhost:8001/threats/top" | ConvertTo-Json
```

**Response:**
```json
{
  "top_threats": [
    {
      "ip": "192.168.1.100",
      "alert_count": 15,
      "risk_level": "high"
    }
  ]
}
```

**Example - IP Reputation:**
```powershell
Invoke-RestMethod -Uri "http://localhost:8001/threats/ip/192.168.1.100" | ConvertTo-Json
```

---

### Response Automation

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/block/ip/{ip}?duration=3600&reason=test` | Block an IP |
| `DELETE` | `/block/ip/{ip}` | Unblock an IP |
| `GET` | `/blocked` | List blocked IPs |
| `GET` | `/rate-limit/check/{ip}?port=80` | Check rate limit |

**Example - Block IP:**
```powershell
Invoke-RestMethod -Uri "http://localhost:8001/block/ip/192.168.1.100?duration=3600&reason=test" -Method POST | ConvertTo-Json
```

**Response:**
```json
{
  "ip": "192.168.1.100",
  "blocked": true,
  "block_duration_seconds": 3600,
  "expires_at": "2026-05-06T17:30:00.000000",
  "reason": "test"
}
```

**Example - Unblock IP:**
```powershell
Invoke-RestMethod -Uri "http://localhost:8001/block/ip/192.168.1.100" -Method Delete | ConvertTo-Json
```

---

### Notifications

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/notifications/webhooks` | List webhooks |
| `POST` | `/notifications/webhooks?url=URL&events=events` | Add webhook |

**Example - Add Webhook:**
```powershell
$body = @{
  url = "https://hooks.slack.com/your-webhook"
  events = "alert,critical"
  severities = "critical,high"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:8001/notifications/webhooks" -Method Post -Body $body -ContentType "application/json"
```

---

### Real-time

| Method | Endpoint | Description |
|--------|----------|-------------|
| `WS` | `/ws/alerts` | WebSocket for live alerts |

**WebSocket Connection:**
```javascript
const ws = new WebSocket('ws://localhost:8001/ws/alerts');

ws.onopen = () => {
  console.log('Connected to alerts');
};

ws.onmessage = (event) => {
  const alert = JSON.parse(event.data);
  console.log('New alert:', alert);
};
```

**Message Format:**
```json
{
  "timestamp": "2026-05-06T15:30:00.000000",
  "type": "SIGNATURE",
  "severity": "medium",
  "message": "ET WEB_SERVER SQL Injection UNION SELECT",
  "src_ip": "192.168.1.100",
  "dst_ip": "10.0.0.1"
}
```

---

## 🔒 Detection Rules

### Severities
- `critical` - Critical threats (C2, malware)
- `high` - High severity (exploits, data exfil)
- `medium` - Medium severity (injections, scanning)
- `low` - Low severity (info gathering)

### Detection Types
- `SIGNATURE` - Rule-based detection
- `ANOMALY` - ML-based anomaly detection
- `THREAT_INTEL` - Threat feed matches

---

## 📊 Response Codes

| Code | Meaning |
|------|---------|
| `200` | Success |
| `201` | Created |
| `400` | Bad Request |
| `404` | Not Found |
| `500` | Internal Server Error |

---

## 🧪 Testing Tools

### PowerShell Quick Tests

```powershell
# Health
Invoke-RestMethod -Uri "http://localhost:8001/health"

# Stats
Invoke-RestMethod -Uri "http://localhost:8001/stats"

# All Alerts
Invoke-RestMethod -Uri "http://localhost:8001/alerts" | ConvertTo-Json

# System Status
Invoke-RestMethod -Uri "http://localhost:8001/system/status" | ConvertTo-Json

# Comprehensive Dashboard Data
Invoke-RestMethod -Uri "http://localhost:8001/dashboard/comprehensive" | ConvertTo-Json -Depth 5
```

---

## 📝 Complete Example Script

```powershell
# Complete API Test Script

$baseUrl = "http://localhost:8001"

Write-Host "=== ATIG API Test Suite ===" -ForegroundColor Cyan

# 1. Health Check
Write-Host "`n[1] Health Check..." -ForegroundColor Yellow
$health = Invoke-RestMethod -Uri "$baseUrl/health"
Write-Host "✓ Status: $($health.health)" -ForegroundColor Green

# 2. Get Stats
Write-Host "`n[2] Statistics..." -ForegroundColor Yellow
$stats = Invoke-RestMethod -Uri "$baseUrl/stats"
Write-Host "✓ Total Alerts: $($stats.total_alerts)" -ForegroundColor Green

# 3. Trigger Detection
Write-Host "`n[3] Trigger Detection..." -ForegroundColor Yellow
$payload = "UNION SELECT * FROM users"
$uri = "$baseUrl/packet/analyze?src_ip=192.168.1.100&dst_ip=10.0.0.1&src_port=54321&dst_port=80&protocol=tcp&payload=" + [System.Web.HttpUtility]::UrlEncode($payload)
$result = Invoke-RestMethod -Uri $uri -Method POST
Write-Host "✓ Rule Matched: $($result.analysis[0].message)" -ForegroundColor Green

# 4. Get Analytics
Write-Host "`n[4] Attack Patterns..." -ForegroundColor Yellow
$patterns = Invoke-RestMethod -Uri "$baseUrl/analytics/attack-patterns"
Write-Host "✓ Patterns: $($patterns.attack_patterns.Count)" -ForegroundColor Green

# 5. Block IP
Write-Host "`n[5] Block IP..." -ForegroundColor Yellow
$block = Invoke-RestMethod -Uri "$baseUrl/block/ip/192.168.1.100?duration=3600&reason=test" -Method POST
Write-Host "✓ IP Blocked: $($block.blocked)" -ForegroundColor Green

# 6. Get Blocked IPs
Write-Host "`n[6] Blocked IPs..." -ForegroundColor Yellow
$blocked = Invoke-RestMethod -Uri "$baseUrl/blocked"
Write-Host "✓ Blocked Count: $($blocked.blocked_ips.Count)" -ForegroundColor Green

Write-Host "`n=== All Tests Passed ===" -ForegroundColor Green
```

---

## 📚 Additional Resources

- **[README.md](README.md)** - Project overview
- **[TESTING_GUIDE.md](TESTING_GUIDE.md)** - Testing procedures
- **[QUICK_START.md](QUICK_START.md)** - Setup guide
- **[GITHUB_PUSH_GUIDE.md](GITHUB_PUSH_GUIDE.md)** - Deployment guide

---

**End of API Documentation**
