# 🧪 ATIG Testing Guide

**Complete testing procedures for all ATIG components**

---

## 📋 Pre-Flight Checklist

Before testing, ensure all services are running:

```powershell
# Check API is running
Invoke-RestMethod -Uri "http://localhost:8001/health"

# Check Dashboard is running
Invoke-WebRequest -Uri "http://localhost:3000"

# Expected results:
# API: {"health":"ok","timestamp":"..."}
# Dashboard: StatusCode 200
```

---

## ✅ Test Suite 1: API Health & Status

### Test 1.1: Health Check
```powershell
Invoke-RestMethod -Uri "http://localhost:8001/health" | ConvertTo-Json
```
**Expected Output:** `{"health":"ok","timestamp":"..."}`
**Status:** ⬜ PASS ⬜ FAIL

### Test 1.2: System Status
```powershell
Invoke-RestMethod -Uri "http://localhost:8001/system/status" | ConvertTo-Json
```
**Expected:** `{"status":"operational","components":{...}}`
**Status:** ⬜ PASS ⬜ FAIL

### Test 1.3: Detection Rules Count
```powershell
Invoke-RestMethod -Uri "http://localhost:8001/rules" | Select-Object -ExpandProperty total_rules
```
**Expected:** `50` or more
**Status:** ⬜ PASS ⬜ FAIL

---

## ✅ Test Suite 2: Threat Detection

### Test 2.1: SQL Injection - UNION SELECT
```powershell
$payload = "UNION SELECT * FROM users"
$uri = "http://localhost:8001/packet/analyze?src_ip=192.168.1.100&dst_ip=10.0.0.1&src_port=54321&dst_port=80&protocol=tcp&payload=" + [System.Web.HttpUtility]::UrlEncode($payload)
Invoke-RestMethod -Uri $uri -Method POST | ConvertTo-Json
```
**Expected:** Detection with rule_id `2000001` (SQL Injection UNION SELECT)
**Status:** ⬜ PASS ⬜ FAIL

### Test 2.2: SQL Injection - OR 1=1
```powershell
$payload = "OR 1=1"
$uri = "http://localhost:8001/packet/analyze?src_ip=192.168.1.100&dst_ip=10.0.0.1&src_port=54321&dst_port=80&protocol=tcp&payload=" + [System.Web.HttpUtility]::UrlEncode($payload)
Invoke-RestMethod -Uri $uri -Method POST | ConvertTo-Json
```
**Expected:** Detection with rule_id `2000011` (SQL Injection OR 1=1)
**Status:** ⬜ PASS ⬜ FAIL

### Test 2.3: XSS - Script Tag
```powershell
$payload = "<script>alert('XSS')</script>"
$uri = "http://localhost:8001/packet/analyze?src_ip=192.168.1.100&dst_ip=10.0.0.1&src_port=54321&dst_port=80&protocol=tcp&payload=" + [System.Web.HttpUtility]::UrlEncode($payload)
Invoke-RestMethod -Uri $uri -Method POST | ConvertTo-Json
```
**Expected:** Detection with rule_id `2000020` (XSS Script Tag)
**Status:** ⬜ PASS ⬜ FAIL

### Test 2.4: XSS - Event Handler
```powershell
$payload = "<img src=x onerror=alert(1)>"
$uri = "http://localhost:8001/packet/analyze?src_ip=192.168.1.100&dst_ip=10.0.0.1&src_port=54321&dst_port=80&protocol=tcp&payload=" + [System.Web.HttpUtility]::UrlEncode($payload)
Invoke-RestMethod -Uri $uri -Method POST | ConvertTo-Json
```
**Expected:** Detection with rule_id `2000021` (XSS Event Handler)
**Status:** ⬜ PASS ⬜ FAIL

### Test 2.5: Path Traversal - Basic
```powershell
$payload = "../../../etc/passwd"
$uri = "http://localhost:8001/packet/analyze?src_ip=192.168.1.100&dst_ip=10.0.0.1&src_port=54321&dst_port=80&protocol=tcp&payload=" + [System.Web.HttpUtility]::UrlEncode($payload)
Invoke-RestMethod -Uri $uri -Method POST | ConvertTo-Json
```
**Expected:** Detection with rule_id `2000030` (Path Traversal Attempt)
**Status:** ⬜ PASS ⬜ FAIL

### Test 2.6: Path Traversal - /etc/passwd
```powershell
$payload = "/etc/passwd"
$uri = "http://localhost:8001/packet/analyze?src_ip=192.168.1.100&dst_ip=10.0.0.1&src_port=54321&dst_port=80&protocol=tcp&payload=" + [System.Web.HttpUtility]::UrlEncode($payload)
Invoke-RestMethod -Uri $uri -Method POST | ConvertTo-Json
```
**Expected:** Detection with rule_id `2000032` (Path Traversal /etc/passwd)
**Status:** ⬜ PASS ⬜ FAIL

### Test 2.7: Command Injection - Pipe
```powershell
$payload = "|cat /etc/passwd"
$uri = "http://localhost:8001/packet/analyze?src_ip=192.168.1.100&dst_ip=10.0.0.1&src_port=54321&dst_port=80&protocol=tcp&payload=" + [System.Web.HttpUtility]::UrlEncode($payload)
Invoke-RestMethod -Uri $uri -Method POST | ConvertTo-Json
```
**Expected:** Detection with rule_id `2000040` (Command Injection Pipe)
**Status:** ⬜ PASS ⬜ FAIL

### Test 2.8: Brute Force - SSH
```powershell
$payload = "ssh br