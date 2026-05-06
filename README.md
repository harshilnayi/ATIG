# 🔒 ATIG - Automated Threat Intelligence Aggregator

**Real-time Network Intrusion Detection System (NIDS)** with signature-based detection, ML-powered anomaly detection, threat intelligence integration, and a beautiful live dashboard.

---

## 🎯 What is ATIG?

ATIG is a comprehensive network security monitoring system that:
- **Captures and analyzes** network packets in real-time
- **Detects threats** using 50+ signature rules (SQL injection, XSS, brute force, malware patterns)
- **Learns baseline** traffic patterns to identify anomalies
- **Integrates threat feeds** from OTX, Abuse.ch, and PhishTank
- **Visualizes everything** on a real-time dashboard with charts and alerts
- **Automates responses** by blocking malicious IPs automatically

---

## 🏗️ Architecture

```
┌─────────────────────┐      ┌──────────────────────┐      ┌───────────────────┐
│   Packet Capture    │ ──→  │  Detection Engine    │ ──→  │   PostgreSQL      │
│   (Go / libpcap)    │      │  (Python + FastAPI)  │      │   + Vue Dashboard │
└─────────────────────┘      └──────────────────────┘      └───────────────────┘
         ↓                          ↓                             ↓
   Network Traffic          50+ Detection Rules          Real-time Analytics
                            Threat Intelligence          Live Alert Dashboard
                            Auto IP Blocking
```

---

## 🛠️ Tech Stack

| Component | Technology |
|-----------|-----------|
| **Packet Capture** | Go (libpcap/AF_PACKET) |
| **Detection Engine** | Python 3.11+ (FastAPI, scikit-learn) |
| **API Server** | Uvicorn (ASGI) |
| **Database** | PostgreSQL 15+ |
| **Dashboard** | Vue 3 + Vite + Tailwind CSS |
| **Charts** | Chart.js |
| **Threat Feeds** | OTX, Abuse.ch, PhishTank (all free) |

---

## 🚀 Quick Start

### Prerequisites

- **Go** 1.21+ (for packet capture engine)
- **Python** 3.11+ (for detection engine)
- **PostgreSQL** 15+ (or use Docker)
- **Node.js** 18+ (for dashboard - optional)
- **Docker** (optional, for easy database setup)

---

### Step 1: Database Setup (Docker - Recommended)

```bash
# Start PostgreSQL with one command
docker-compose up -d postgres

# Wait 5 seconds for DB to be ready
sleep 5

# Verify database is running
docker-compose ps
```

**Or traditional setup:**
```bash
# Install PostgreSQL 15+
# Create database and user:
createdb atig_db
psql -d atig_db -c "CREATE USER atig_user WITH PASSWORD 'atig_pass';"
psql -d atig_db -c "GRANT ALL PRIVILEGES ON DATABASE atig_db TO atig_user;"
```

---

### Step 2: Python Detection Engine

```bash
cd E:\ATIG\python

# Install dependencies
pip install -r requirements.txt

# Start the API server (runs on port 8001)
python main.py

# You should see:
# INFO: Uvicorn running on http://0.0.0.0:8001
# INFO: Application startup complete.
```

---

### Step 3: Vue Dashboard (Optional but Recommended)

```bash
cd E:\ATIG\dashboard

# Install dependencies (first time only)
npm install

# Start development server (runs on port 3000)
npm run dev

# You should see:
# ➜  Local:   http://localhost:3000/
```

---

### Step 4: Open the Dashboard

Open your browser and navigate to:
```
http://localhost:3000
```

You should see:
- ✅ **"Connected"** status (green)
- 📊 Real-time stats cards
- 📈 Charts showing severity distribution
- 🚨 Live alert feed
- 🌐 Attack pattern analytics

---

## 📡 API Endpoints

### Health & Status
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/system/status` | System component status |
| GET | `/rules` | List all detection rules |

### Alerts & Stats
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/alerts` | Get recent alerts |
| GET | `/stats` | Dashboard statistics |
| GET | `/alerts/search?q=query` | Search alerts |
| GET | `/alerts/export?format=json` | Export alerts |

### Analytics
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/analytics/attack-patterns` | Attack pattern breakdown |
| GET | `/analytics/top-ports` | Most targeted ports |
| GET | `/analytics/top-source-ips` | Top source IPs |
| GET | `/alerts/timeline?hours=24` | Alert timeline |

### Threat Intelligence
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/threats/top` | Top dangerous IPs |
| GET | `/threats/ip/{ip}` | IP reputation info |
| GET | `/threats/correlations` | Correlated attacks |

### Response Automation
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/block/ip/{ip}?duration=3600` | Block an IP |
| DELETE | `/block/ip/{ip}` | Unblock an IP |
| GET | `/blocked` | List blocked IPs |

### Real-time
| Method | Endpoint | Description |
|--------|----------|-------------|
| WS | `/ws/alerts` | WebSocket for live alerts |

---

## 🧪 Testing & Verification

### Test 1: Health Check
```powershell
Invoke-RestMethod -Uri "http://localhost:8001/health"
# Expected: {"health":"ok","timestamp":"..."}
```

### Test 2: SQL Injection Detection
```powershell
$payload = "UNION SELECT * FROM users"
$uri = "http://localhost:8001/packet/analyze?src_ip=192.168.1.100&dst_ip=10.0.0.1&src_port=54321&dst_port=80&protocol=tcp&payload=" + [System.Web.HttpUtility]::UrlEncode($payload)
Invoke-RestMethod -Uri $uri -Method POST
# Expected: Detection with rule_id 2000001 (SQL Injection)
```

### Test 3: XSS Detection
```powershell
$payload = "<script>alert('XSS')</script>"
$uri = "http://localhost:8001/packet/analyze?src_ip=192.168.1.100&dst_ip=10.0.0.1&src_port=54321&dst_port=80&protocol=tcp&payload=" + [System.Web.HttpUtility]::UrlEncode($payload)
Invoke-RestMethod -Uri $uri -Method POST
# Expected: Detection with rule_id 2000020 (XSS Script Tag)
```

### Test 4: Path Traversal Detection
```powershell
$payload = "../../../etc/passwd"
$uri = "http://localhost:8001/packet/analyze?src_ip=192.168.1.100&dst_ip=10.0.0.1&src_port=54321&dst_port=80&protocol=tcp&payload=" + [System.Web.HttpUtility]::UrlEncode($payload)
Invoke-RestMethod -Uri $uri -Method POST
# Expected: Detection with rule_id 2000030/2000032 (Path Traversal)
```

### Test 5: Command Injection Detection
```powershell
$payload = "|cat /etc/passwd"
$uri = "http://localhost:8001/packet/analyze?src_ip=192.168.1.100&dst_ip=10.0.0.1&src_port=54321&dst_port=80&protocol=tcp&payload=" + [System.Web.HttpUtility]::UrlEncode($payload)
Invoke-RestMethod -Uri $uri -Method POST
# Expected: Detection with rule_id 2000040 (Command Injection)
```

### Test 6: IP Blocking
```powershell
# Block an IP
Invoke-RestMethod -Uri "http://localhost:8001/block/ip/192.168.1.100?duration=3600&reason=test" -Method POST

# View blocked IPs
Invoke-RestMethod -Uri "http://localhost:8001/blocked"

# Unblock
Invoke-RestMethod -Uri "http://localhost:8001/block/ip/192.168.1.100" -Method Delete
```

---

## 🔍 What to Observe on the Dashboard

### Stats Cards
- **Total Alerts**: Should increase as attacks are detected
- **Critical/High/Medium**: Severity breakdown
- **Threat Intel Indicators**: Active threat feed indicators (should show 8+)

### Charts
- **Severity Distribution**: Doughnut chart showing alert severity ratio
- **Detection Types**: Bar chart of Signature vs Anomaly vs Threat Intel
- **Attack Patterns**: Grid showing SQLi, XSS, Brute Force counts

### Live Alert Feed
- Alerts should appear in real-time via WebSocket
- Shows source IP → destination IP, port, message
- Color-coded by severity (red = critical, orange = high, yellow = medium)

### Analytics
- **Top Source IPs**: Most frequent attackers
- **Top Targeted Ports**: Most attacked ports
- **Threat Intelligence**: Known malicious IPs

---

## 📁 Project Structure

```
ATIG/
├── go/                       # Packet capture engine (Go)
│   ├── main.go              # Main packet capture logic
│   └── pkg/                 # Packet decoding protocols
│
├── python/                   # Detection engine (Python)
│   ├── main.py              # FastAPI server
│   ├── engine/              # Detection logic
│   │   ├── signatures.py    # Signature-based detection
│   │   ├── ml_model.py      # ML anomaly detection
│   │   └── threat_scoring.py # Threat scoring system
│   ├── services/            # External services
│   │   ├── database.py      # PostgreSQL connection
│   │   └── threat_intel.py  # Threat feed integration
│   └── models/              # Database models
│
├── dashboard/                # Vue 3 frontend
│   ├── src/
│   │   ├── App.vue          # Main dashboard component
│   │   └── main.js          # Vue entry point
│   ├── package.json
│   └── vite.config.js       # Dev server config
│
├── docker-compose.yml        # PostgreSQL container
└── README.md                 # This file
```

---

## 🔧 Troubleshooting

### API Not Starting
```powershell
# Check if port 8001 is in use
Get-NetTCPConnection -LocalPort 8001

# Kill process using port 8001
Get-NetTCPConnection -LocalPort 8001 | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }

# Restart API
cd E:\ATIG\python
python main.py
```

### Dashboard Not Loading
```powershell
# Check if port 3000 is in use
Get-NetTCPConnection -LocalPort 3000

# Kill process using port 3000
Get-NetTCPConnection -LocalPort 3000 | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }

# Restart dashboard
cd E:\ATIG\dashboard
npm run dev
```

### Database Connection Issues
```powershell
# Restart PostgreSQL container
docker-compose restart postgres

# Or recreate from scratch
docker-compose down
docker-compose up -d postgres
```

### Blank Screen on Dashboard
1. Open browser console (F12)
2. Check for JavaScript errors
3. Verify API is running on port 8001
4. Hard refresh: Ctrl + Shift + R

---

## 📊 Detection Rules (50+ Covered)

| Category | Example Rules | Severity |
|----------|---------------|----------|
| **SQL Injection** | UNION SELECT, OR 1=1, DROP TABLE | Medium |
| **XSS** | Script tags, Event handlers, JS protocol | Medium |
| **Path Traversal** | ../../../etc/passwd, Directory access | Medium |
| **Command Injection** | Pipe commands, Backticks, wget | Medium |
| **Brute Force** | SSH, RDP, FTP, MySQL, PostgreSQL | Medium |
| **Exploits** | EternalBlue, Buffer overflow, NOP slides | High |
| **C2 Communication** | Known C2 servers, Botnets, Cobalt Strike | Critical |
| **Data Exfiltration** | Large transfers, FTP/SFTP abuse | High |
| **Reconnaissance** | Scanning, DGA domains, Large DNS | Medium |
| **Lateral Movement** | WinRM, PowerShell remoting | High |

---

## 🚀 Next Steps

1. **Test all detection rules** - See TESTING_GUIDE.md for comprehensive tests
2. **Configure webhooks** - Set up alert notifications to Slack/Discord
3. **Enable threat feeds** - Customize which feeds to track
4. **Set IP blocking** - Configure automatic blocking thresholds
5. **Deploy to production** - Follow deployment guide

---

## 📝 Additional Documentation

- **[TESTING_GUIDE.md](TESTING_GUIDE.md)** - Comprehensive testing procedures
- **[API_DOCUMENTATION.md](API_DOCUMENTATION.md)** - Full API reference
- **[SETUP.md](SETUP.md)** - Detailed setup instructions
- **[GITHUB_PUSH_GUIDE.md](GITHUB_PUSH_GUIDE.md)** - How to push to GitHub

---

## 📜 License

MIT License - Feel free to use for personal or commercial projects.

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

---

## ⚠️ Disclaimer

This tool is for **educational and defensive purposes only**. Ensure you have proper authorization before testing on any network. Unauthorized access to computer systems is illegal.

**Use responsibly. Stay safe. Keep your networks secure! 🔒**
