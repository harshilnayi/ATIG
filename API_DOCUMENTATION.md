# ATIG API Documentation

## Base URL
```
http://localhost:8001
```

## Core Endpoints

### Health & Status
- `GET /health` - Health check
- `GET /` - API info
- `GET /system/status` - System status with component details

### Packet Analysis
- `POST /packet/analyze` - Analyze a packet for threats
  - Query params: `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `payload`

### Alerts
- `GET /alerts` - Get recent alerts
- `GET /alerts/recent` - Get recent alerts with correlations
- `GET /alerts/search` - Search alerts with filters
- `GET /alerts/by-severity/{severity}` - Filter by severity
- `GET /alerts/by-type/{type}` - Filter by detection type
- `GET /alerts/summary` - Alert summary statistics
- `GET /alerts/timeline` - Alert timeline (last N hours)
- `GET /alerts/export` - Export alerts (json/csv)
- `GET /alerts/acknowledge/{alert_id}` - Acknowledge alert
- `GET /alerts/resolve/{alert_id}` - Resolve alert

### Statistics
- `GET /stats` - Basic statistics
- `GET /dashboard/comprehensive` - All dashboard data in one call
- `GET /dashboard/extended-stats` - Extended stats with threat scores

### Threat Intelligence
- `GET /threats/top` - Top N most dangerous IPs
- `GET /threats/ip/{ip}` - Get IP reputation info
- `GET /threats/correlations` - Get correlated attack patterns

### Response Automation
- `POST /block/ip/{ip}` - Block an IP
- `DELETE /block/ip/{ip}` - Unblock an IP
- `GET /blocked` - List blocked IPs
- `GET /rate-limit/check/{ip}` - Check rate limit status

### Rules & Configuration
- `GET /rules` - List all detection rules
- `GET /rules/reload` - Reload rules from file

### Notifications
- `GET /notifications/webhooks` - List configured webhooks
- `POST /notifications/webhooks` - Add webhook

## WebSocket
- `WS /ws/alerts` - Real-time alert stream

## Response Examples

### Comprehensive Dashboard
```json
{
  "stats": {
    "total_alerts": 3,
    "high_severity": 0,
    "signature_detections": 3,
    "anomaly_detections": 0,
    "threat_intel_indicators": 11
  },
  "recent_alerts": [...],
  "breakdown": {
    "by_severity": {"critical": 0, "high": 0, "medium": 3, "low": 0},
    "by_type": {"SIGNATURE": 3, "ANOMALY": 0, "THREAT_INTEL": 0}
  },
  "top_threats": [...],
  "correlations": [...],
  "blocked_ips": 0,
  "system_status": {
    "rules_loaded": 50,
    "webhooks_configured": 0
  }
}
```

### Block IP
```json
{
  "ip": "192.168.1.100",
  "blocked": true,
  "block_duration_seconds": 3600,
  "expires_at": "2026-05-05T22:16:20.614027",
  "reason": "manual"
}
```
