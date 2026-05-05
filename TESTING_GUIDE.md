# ATIG Testing Guide

## 🧪 How to Test Everything Yourself

### 1. **Test API Health**
```powershell
# Check if API is running
Invoke-RestMethod -Uri "http://localhost:8001/health"

# Expected output:
# {"health":"ok","timestamp":"2026-05-05T..."}
```

### 2. **Test Detection Rules**
```powershell
# View all loaded rules
Invoke-RestMethod -Uri "http://localhost:8001/rules" | ConvertTo-Json

# Expected: 50+ rules listed
```

### 3. **Test Vulnerability Detection**

#### SQL Injection
```powershell
Invoke-RestMethod -Uri "http://localhost:8001/packet/analyze?src_ip=192.168.1.100&dst_ip=10.0.0.1&src_port=54321&dst_port=80&protocol=tcp&payload=UNION%20SELECT" -Method POST

# Expected: Detection result showing SQL Injection
```

#### XSS
```powershell
Invoke-RestMethod -Uri "http://localhost:8001/packet/analyze?src_ip=192.168.1.100&dst_ip=10.0.0.1&src_port=54321&dst_port=80&protocol=tcp&payload=%3Cscript%3E" -Method POST

# Expected: XSS detection
```

#### Path Traversal
```powershell
Invoke-RestMethod -Uri "http://localhost:8001/packet/analyze?src_ip=192.168.1.100&dst_ip=10.0.0.1&src_port=54321&dst_port=80&protocol=tcp&payload=../etc/passwd" -Method POST

# Expected: Path traversal detection
```

#### Command Injection
```powershell
Invoke-RestMethod -Uri "http://localhost:8001/packet/analyze?src_ip=192.168.1.100&dst_ip=10.0.0.1&src_port=54321&dst_port=80&protocol=tcp&payload=|cat%20/etc/passwd" -Method POST

# Expected: Command injection detection
```

### 4. **Test Dashboard**

#### Open Dashboard
```
http://localhost:3000
```

#### Check Dashboard Features:
- [ ] Dashboard loads without errors
- [ ] Shows "Connected" status
- [ ] Stats cards display numbers
- [ ] Alert feed shows recent alerts
- [ ] WebSocket is receiving alerts (test by running detection commands above)

### 5. **Test Analytics Endpoints**

#### Attack Patterns
```powershell
Invoke-RestMethod -Uri "http://localhost:8001/analytics/attack-patterns" | ConvertTo-Json

# Expected: Shows attack pattern breakdown
```

#### Top Ports
```powershell
Invoke-RestMethod -Uri "http://localhost:8001/analytics/top-ports" | ConvertTo-Json

# Expected: Shows most targeted ports
```

#### Top Source IPs
```powershell
Invoke-RestMethod -Uri "http://localhost:8001/analytics/top-source-ips" | ConvertTo-Json

# Expected: Shows most frequent source IPs
```

### 6. **Test Response Automation**

#### Block an IP
```powershell
Invoke-RestMethod -Uri "http://localhost:8001/block/ip/192.168.1.100?duration=3600&reason=test" -Method POST | ConvertTo-Json

# Expected: {"ip":"192.168.1.100","blocked":true,...}
```

#### View Blocked IPs
```powershell

Invoke-RestMethod -Uri "http://localhost:8001/blocked" | ConvertTo-Json

# Expected: Shows blocked IPs list
```

#### Unblock IP
```powershell
Invoke-RestMethod -Uri "http://localhost:8001/block/ip/192.168.1.100" -Method Delete | ConvertTo-Json

# Expected: {"ip":"192.168.1.100","unblocked":true}
```

### 7. **Test Threat Intelligence**

#### Top Threats
```powershell
Invoke-RestMethod -Uri "http://localhost:8001/threats/top" | ConvertTo-Json

# Expected: Shows top dangerous IPs
```

#### IP Reputation
```powershell
Invoke-RestMethod -Uri "http://localhost:8001/threats/ip/192.168.1.100" | ConvertTo-Json

# Expected: Shows IP reputation info
```

### 8. **Test Comprehensive Dashboard Data**
```powershell
Invoke-RestMethod -Uri "http://localhost:8001/dashboard/comprehensive" | ConvertTo-Json

# Expected: All dashboard data in one call
```

### 9. **Test Alert Management**

#### Get Recent Alerts
```powershell
Invoke-RestMethod -Uri "http://localhost:8001/alerts/recent" | ConvertTo-Json

# Expected: Recent alerts with correlations
```

#### Search Alerts
```powershell
Invoke-RestMethod -Uri "http://localhost:8001/alerts/search?q=SQL" | ConvertTo-Json

# Expected: Alerts matching "SQL"
```

#### Filter by Severity
```powershell
Invoke-RestMethod -Uri "http://localhost:8001/alerts/by-severity/medium" | ConvertTo-Json

# Expected: Medium severity alerts
```

### 10. **Test Export**

#### Export as JSON
```powershell
Invoke-RestMethod -Uri "http://localhost:8001/alerts/export?format=json" | ConvertTo-Json

# Expected: JSON export of alerts
```

#### Export as CSV
```powershell
Invoke-RestMethod -Uri "http://localhost:8001/alerts/export?format=csv" | ConvertTo-Json

# Expected: CSV export of alerts
```

### 11. **Test System Status**
```powershell
Invoke-RestMethod -Uri "http://localhost:8001/system/status" | ConvertTo-Json

# Expected: System status with component details
```

### 12. **Test WebSocket Connection**

#### Check Dashboard WebSocket
- Open browser console (F12)
- Look for WebSocket connection messages
- Should see "Connected" status
- Run a detection command and watch for real-time updates

## ✅ Testing Checklist

### Core Functionality
- [ ] API health check passes
- [ ] 50+ detection rules loaded
- [ ] SQL injection detected
- [ ] XSS detected
- [ ] Path traversal detected
- [ ] Command injection detected

### Dashboard
- [ ] Dashboard loads without errors
- [ ] WebSocket connects successfully
- [ ] Stats cards show correct numbers
- [ ] Alert feed displays alerts
- [ ] Real-time updates work

### Analytics
- [ ] Attack patterns endpoint works
- [ ] Top ports endpoint works
- [ ] Top source IPs endpoint works
- [ ] Timeline endpoint works

### Response Automation
- [ ] IP blocking works
- [ ] IP unblocking works
- [ ] Blocked IPs list works
- [ ] Rate limit check works

### Threat Intelligence
- [ ] Top threats endpoint works
- [ ] IP reputation endpoint works
- [ ] Correlations endpoint works

### Alert Management
- [ ] Recent alerts endpoint works
- [ ] Search alerts works
- [ ] Filter by severity works
- [ ] Filter by type works
- [ ] Export JSON works
- [ ] Export CSV works

### System
- [ ] System status endpoint works
- [ ] Rules reload works
- [ ] Webhooks list works
- [ ] Comprehensive dashboard works

## 🐛 Troubleshooting

### API Not Responding
```powershell
# Check if API is running
Get-NetTCPConnection -LocalPort 8001

# If not running, restart:
cd E:\ATIG\python
python main.py
```

### Dashboard Not Connecting
- Check API is running on port 8001
- Refresh browser
- Check browser console for errors
- Verify Vite proxy configuration

### Database Issues
```powershell
# Restart database
cd E:\ATIG
docker-compose down
docker-compose up -d postgres
```

### Port Conflicts
```powershell
# Kill process on port 8001
Get-NetTCPConnection -LocalPort 8001 | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }

# Kill process on port 3000
Get-NetTCPConnection -LocalPort 3000 | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }
```

## 📝 Test Results Template

```
Date: ___________
Tester: ___________

Core Functionality:
[ ] API health check
[ ] Detection rules loaded
[ ] SQL injection detection
[ ] XSS detection
[ ] Path traversal detection
[ ] Command injection detection

Dashboard:
[ ] Dashboard loads
[ ] WebSocket connects
[ ] Stats display correctly
[ ] Alert feed works
[ ] Real-time updates work

Analytics:
[ ] Attack patterns
[ ] Top ports
[ ] Top source IPs
[ ] Timeline

Response Automation:
[ ] IP blocking
[ ] IP unblocking
[ ] Blocked IPs list
[ ] Rate limiting

Threat Intelligence:
[ ] Top threats
[ ] IP reputation
[ ] Correlations

Alert Management:
[ ] Recent alerts
[ ] Search alerts
[ ] Filter by severity
[ ] Filter by type
[ ] Export JSON
[ ] Export CSV

System:
[ ] System status
[ ] Rules reload
[ ] Webhooks list
[ ] Comprehensive dashboard

Overall Status: PASS / FAIL
Notes: ___________
```

## 🎯 Next Steps After Testing

1. Run through all tests above
2. Mark each test as PASS or FAIL
3. Note any issues or errors
4. Report back with results
5. Once confirmed OK, we'll push to GitHub
