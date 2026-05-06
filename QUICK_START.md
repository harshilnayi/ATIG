# 🚀 ATIG Quick Start Guide

**Get up and running in 5 minutes**

---

## Step-by-Step Setup

### 1️⃣ Start the Database
```powershell
cd E:\ATIG
docker-compose up -d postgres
```
*Wait 10 seconds for PostgreSQL to start*

---

### 2️⃣ Start the Detection API
```powershell
cd E:\ATIG\python
python main.py
```
**Wait until you see:**
```
INFO: Uvicorn running on http://0.0.0.0:8001
INFO: Application startup complete.
```

---

### 3️⃣ Start the Dashboard
**Open a NEW terminal/window:**
```powershell
cd E:\ATIG\dashboard
npm run dev
```
**Wait until you see:**
```
➜  Local:   http://localhost:3000/
```

---

### 4️⃣ Open the Dashboard
Open your browser and go to:
```
http://localhost:3000
```

**You should see:**
- ✅ Green "Connected" status
- 📊 Stats cards showing alerts
- 📈 Charts with data
- 🚨 Alert feed

---

## 🧪 Quick Test

**Test SQL Injection Detection:**
```powershell
$payload = "UNION SELECT * FROM users"
$uri = "http://localhost:8001/packet/analyze?src_ip=192.168.1.100&dst_ip=10.0.0.1&src_port=54321&dst_port=80&protocol=tcp&payload=" + [System.Web.HttpUtility]::UrlEncode($payload)
Invoke-RestMethod -Uri $uri -Method POST
```

**Expected:** Detection result with SQL Injection rule matched

---

## 🔧 Troubleshooting

### API won't start?
```powershell
# Check if port 8001 is in use
Get-NetTCPConnection -LocalPort 8001

# Kill process if needed
Get-NetTCPConnection -LocalPort 8001 | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }

# Try again
cd E:\ATIG\python
python main.py
```

### Dashboard won't start?
```powershell
# Check if port 3000 is in use
Get-NetTCPConnection -LocalPort 3000

# Kill process if needed
Get-NetTCPConnection -LocalPort 3000 | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }

# Try again
cd E:\ATIG\dashboard
npm run dev
```

### Database won't start?
```powershell
# Check Docker is running
docker ps

# Restart container
docker-compose restart postgres

# Or recreate
docker-compose down
docker-compose up -d postgres
```

---

## 📊 What You'll See

### Stats Cards
- Total Alerts
- Critical Severity
- High Severity  
- Medium Severity

### Charts
- Alert Timeline (24h)
- Severity Distribution
- Detection Types

### Analytics
- Top Source IPs
- Top Targeted Ports
- Attack Patterns

### Live Features
- Real-time alert feed (WebSocket)
- Auto-updating stats
- Live charts

---

## 🎯 Next Steps

1. **Read the full documentation:** See [README.md](README.md)
2. **Run comprehensive tests:** See [TESTING_GUIDE.md](TESTING_GUIDE.md)
3. **Learn the API:** See [API_DOCUMENTATION.md](API_DOCUMENTATION.md)

---

## ✅ Verification Checklist

- [ ] Database running (`docker ps` shows postgres)
- [ ] API responding (`http://localhost:8001/health`)
- [ ] Dashboard accessible (`http://localhost:3000`)
- [ ] WebSocket connected (green "Connected" on dashboard)
- [ ] Stats showing data
- [ ] Test detection works (SQL injection test)

**All checked? You're ready to go! 🚀**
