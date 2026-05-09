# ATIG Full System Startup Script
# Run this to start the complete ATIG system

$ErrorActionPreference = "Stop"
$host.ui.RawUI.WindowTitle = "ATIG - Automated Threat Intelligence Aggregator"

Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "  ATIG - Automated Threat Intelligence Aggregator" -ForegroundColor Cyan
Write-Host "  Full System Startup" -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host ""

# Function to check port
function Test-Port {
    param($port)
    try {
        $null = Get-NetTCPConnection -LocalPort $port -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

# Function to kill process on port
function Kill-Port {
    param($port)
    try {
        $conn = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue
        if ($conn) {
            Stop-Process -Id $conn.OwningProcess -Force -ErrorAction SilentlyContinue
            Write-Host "  Killed process on port $port" -ForegroundColor Yellow
        }
    } catch {}
}

# Step 1: Check/Kill existing processes
Write-Host "[1/7] Checking for existing processes..." -ForegroundColor White
if (Test-Port 8001) { Kill-Port 8001 }
if (Test-Port 3000) { Kill-Port 3000 }
Start-Sleep -Seconds 2

# Step 2: Start Database
Write-Host "[2/7] Starting PostgreSQL database..." -ForegroundColor White
Set-Location E:\ATIG
try {
    docker-compose up -d postgres 2>&1 | Out-Null
    Write-Host "  Database starting..." -ForegroundColor Green
    Start-Sleep -Seconds 8
} catch {
    Write-Host "  Docker not available, skipping database" -ForegroundColor Yellow
}

# Step 3: Verify database
Write-Host "[3/7] Verifying database..." -ForegroundColor White
if (Test-Port 5432) {
    Write-Host "  Database ON port 5432 OK" -ForegroundColor Green
} else {
    Write-Host "  Database NOT running (continuing without DB)" -ForegroundColor Yellow
}

# Step 4: Start API
Write-Host "[4/7] Starting Detection API (port 8001)..." -ForegroundColor White
Set-Location E:\ATIG\python
$apiProcess = Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd E:\ATIG\python; python main.py" -PassThru
Start-Sleep -Seconds 5

if (Test-Port 8001) {
    Write-Host "  API ON port 8001 OK" -ForegroundColor Green
} else {
    Write-Host "  API FAILED to start!" -ForegroundColor Red
    exit 1
}

# Step 5: Start Dashboard
Write-Host "[5/7] Starting Dashboard (port 3000)..." -ForegroundColor White
$dashboardProcess = Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd E:\ATIG\dashboard; npm run dev" -PassThru
Start-Sleep -Seconds 5

if (Test-Port 3000) {
    Write-Host "  Dashboard ON port 3000 OK" -ForegroundColor Green
} else {
    Write-Host "  Dashboard FAILED to start!" -ForegroundColor Red
    exit 1
}

# Step 6: Test API
Write-Host "[6/7] Testing API health..." -ForegroundColor White
try {
    $health = Invoke-RestMethod -Uri "http://localhost:8001/health" -TimeoutSec 5
    Write-Host "  API Health: $($health.health) OK" -ForegroundColor Green
} catch {
    Write-Host "  API health check FAILED!" -ForegroundColor Red
}

# Step 7: Open browser
Write-Host "[7/7] Opening dashboard in browser..." -ForegroundColor White
Start-Process "http://localhost:3000"

# Summary
Write-Host ""
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "  SYSTEM STARTED SUCCESSFULLY" -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "  Dashboard: http://localhost:3000" -ForegroundColor White
Write-Host "  API:       http://localhost:8001" -ForegroundColor White
Write-Host "  Database:  localhost:5432" -ForegroundColor White
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Running processes:" -ForegroundColor Yellow
Write-Host "  - API:      PID $($apiProcess.Id)" -ForegroundColor White
Write-Host "  - Dashboard: PID $($dashboardProcess.Id)" -ForegroundColor White
Write-Host ""
Write-Host "To stop: Close the terminal windows that opened" -ForegroundColor Gray
Write-Host ""

# Keep terminal open
Set-Location E:\ATIG
Write-Host "Press any key to exit this window (child windows remain running)..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")