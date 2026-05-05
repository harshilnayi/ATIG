# ATIG Quick Start Guide

## 🚀 Start the System

### 1. Start Database
```powershell
cd E:\ATIG
docker-compose up -d postgres
```

### 2. Start API
```powershell
cd E:\ATIG\python
python main.py
```
*Wait for "Uvicorn running on http://0.0.0.0:8001"*

### 3. Start Dashboard
```powershell
cd E:\ATIG\dashboard
npm run dev
```

### 4. Open Browser
Go to `http://localhost:3000`

## 🧪 Test Vulnerability Detection

### SQL Injection
```powershell
Invoke-RestMethod -Uri "http://localhost:8001/packet/analyze?src_ip=192.168.1.100&dst_ip=10.0.0.1&src_port=54321&dst_port=80&protocol=tcp&payload=UNION%20SELECT" -Method POST
```

### XSS
```powershell
Invoke-RestMethod -Uri "http://localhost:8001/packet/analyze?src_ip=192.168.1.100&dst_ip=10.0.0.1&src_port=54321&dst_port=80&protocol=tcp&payload=%3Cscript%3E" -Method POST
```

### Path Traversal
```powershell
Invoke-RestMethod -Uri "http://localhost:8001/packet/analyze?src_ip=192.168.1.100&dst_ip=10.0.0.1&src_port=54321&dst_port=80&protocol=tcp&payload=../etc/passwd" -Method POST
```

## 🛡️ Block an IP

```powershell
Invoke-RestMethod -Uri "http://localhost:8001/block/ip/192.168.1.100?duration=3600&reason=malicious" -Method POST
```

## 📊 Get Dashboard Data

```powershell
Invoke-RestMethod -Uri "http://localhost:8001/dashboard/comprehensive"
```

## 🔍 View Attack Patterns

```powershell
Invoke-RestMethod -Uri "http://localhost:8001/analytics/attack-patterns"
```

## 📋 View All Rules

```powershell
Invoke-RestMethod -Uri "http://localhost:8001/rules"
```

## 🚨 View Blocked IPs

```powershell
Invoke-RestMethod -Uri "http://localhost:8001/blocked"
```

## 📈 View Top Threats

```powershell
Invoke-RestMethod -Uri "http://localhost:8001/threats/top"
```

## 🔄 Stop the System

### Stop API
Press `Ctrl+C` in the Python window

### Stop Database
```powershell
cd E:\ATIG
docker-compose down
```

### Stop Dashboard
Press `Ctrl+C` in the dashboard window

## 📚 API Documentation

See `API_DOCUMENTATION.md` for complete API reference.

## 🎯 Key Endpoints

| Endpoint | Description |
|----------|-------------|
| `/health` | Health check |
| `/packet/analyze` | Analyze packet for threats |
| `/alerts` | Get recent alerts |
| `/dashboard/comprehensive` | All dashboard data |
| `/threats/top` | Top dangerous IPs |
| `/block/ip/{ip}` | Block an IP |
| `/rules` | List detection rules |
| `/analytics/attack-patterns` | Attack patterns |

## 🔧 Troubleshooting

### Port 8001 in use
```powershell
Get-NetTCPConnection -LocalPort 8001 | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }
```

### Database connection issues
```powershell
docker-compose down
docker-compose up -d postgres
```

### Dashboard not connecting
- Check API is running on port 8001
- Refresh the browser
- Check browser console for errors

## 🎉 You're Ready!

The system is now production-ready with:
- ✅ 50+ detection rules
- ✅ Real-time threat scoring
- ✅ IP blocking and rate limiting
- ✅ Comprehensive analytics
- ✅ WebSocket real-time alerts
- ✅ 30+ API endpoints
- ✅ Full documentation

Start detecting threats now! 🚀
