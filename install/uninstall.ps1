# ============================================================
# FlowGuard — Uninstaller (MS8.6)
# AI Security Monitor for Claude Code | by EHZ-AI
#
# Usage:          .\uninstall.ps1
# Silent:         .\uninstall.ps1 -Silent
# Keep data:      .\uninstall.ps1 -KeepData
# ============================================================

param(
  [switch]$Silent,
  [switch]$KeepData
)

$ErrorActionPreference = 'Continue'
$Version = "1.0.0"

# ── Paths ─────────────────────────────────────────────────────
$ProjectDir   = Split-Path -Parent $PSScriptRoot
$CollectorDir = Join-Path $ProjectDir "collector"
$ClaudeConfig = "$env:USERPROFILE\.claude\settings.json"
$TaskName     = "FlowGuard-Collector"

# ── Banner ────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ███████╗██╗      ██████╗ ██╗    ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ " -ForegroundColor Red
Write-Host "  ██╔════╝██║     ██╔═══██╗██║    ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗" -ForegroundColor Red
Write-Host "  █████╗  ██║     ██║   ██║██║ █╗ ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║" -ForegroundColor Red
Write-Host "  ██╔══╝  ██║     ██║   ██║██║███╗██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║" -ForegroundColor Red
Write-Host "  ██║     ███████╗╚██████╔╝╚███╔███╔╝╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝" -ForegroundColor Red
Write-Host "  ╚═╝     ╚══════╝ ╚═════╝  ╚══╝╚══╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ " -ForegroundColor Red
Write-Host ""
Write-Host "  FlowGuard v$Version — Uninstaller" -ForegroundColor White
Write-Host "  by EHZ-AI | 054-4825276" -ForegroundColor DarkGray
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Red
Write-Host ""

# ── Confirm (interactive mode) ────────────────────────────────
if (-not $Silent) {
  $confirm = Read-Host "  Are you sure you want to uninstall FlowGuard? (y/N)"
  if ($confirm -notmatch '^[Yy]$') {
    Write-Host ""
    Write-Host "  Uninstall cancelled." -ForegroundColor Yellow
    Write-Host ""
    exit 0
  }
  Write-Host ""
}

# ── Step 1: Stop Collector ────────────────────────────────────
Write-Host "[1/5] Stopping FlowGuard Collector..." -ForegroundColor Yellow

# נסה לבדוק אם רץ
$collectorRunning = $false
try {
  $res = Invoke-RestMethod -Uri "http://localhost:3010/health" -TimeoutSec 2
  if ($res.ok) { $collectorRunning = $true }
} catch { }

if ($collectorRunning) {
  # מצא את תהליך ה-node שמריץ את server.js
  $nodeProcs = Get-Process -Name "node" -ErrorAction SilentlyContinue | Where-Object {
    try {
      $cmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($_.Id)").CommandLine
      $cmdLine -like "*server.js*" -or $cmdLine -like "*flowguard*" -or $cmdLine -like "*ehz-sec-ai*"
    } catch { $false }
  }

  if ($nodeProcs) {
    $nodeProcs | ForEach-Object {
      Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
      Write-Host "  [OK] Stopped node process (PID $($_.Id))" -ForegroundColor Green
    }
  } else {
    # fallback — עצור את כולם שמאזינים על 3010
    Write-Host "  [INFO] Stopping all node.exe processes on port 3010..." -ForegroundColor DarkGray
    $pids = netstat -ano | Select-String ":3010" | ForEach-Object {
      ($_ -split '\s+')[-1]
    } | Select-Object -Unique
    $pids | ForEach-Object {
      if ($_ -match '^\d+$') {
        Stop-Process -Id ([int]$_) -Force -ErrorAction SilentlyContinue
      }
    }
    Write-Host "  [OK] Port 3010 processes stopped" -ForegroundColor Green
  }
  Start-Sleep -Seconds 1
} else {
  Write-Host "  [INFO] Collector was not running" -ForegroundColor DarkGray
}

# ── Step 2: Remove Task Scheduler ────────────────────────────
Write-Host "[2/5] Removing Task Scheduler entry..." -ForegroundColor Yellow
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($task) {
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
  Write-Host "  [OK] Task '$TaskName' removed" -ForegroundColor Green
} else {
  Write-Host "  [INFO] No scheduled task found" -ForegroundColor DarkGray
}

# ── Step 3: Remove Claude Code Hooks ─────────────────────────
Write-Host "[3/5] Removing hooks from Claude Code settings.json..." -ForegroundColor Yellow
if (Test-Path $ClaudeConfig) {
  try {
    $raw      = Get-Content $ClaudeConfig -Raw -Encoding UTF8
    $settings = $raw | ConvertFrom-Json -AsHashtable
    if ($settings.ContainsKey('hooks')) {
      $settings.Remove('hooks')
      $settings | ConvertTo-Json -Depth 10 | Set-Content $ClaudeConfig -Encoding UTF8
      Write-Host "  [OK] Hooks removed from $ClaudeConfig" -ForegroundColor Green
    } else {
      Write-Host "  [INFO] No FlowGuard hooks found in settings.json" -ForegroundColor DarkGray
    }
  } catch {
    Write-Host "  [WARN] Could not parse settings.json: $_" -ForegroundColor Yellow
  }
} else {
  Write-Host "  [INFO] Claude settings.json not found" -ForegroundColor DarkGray
}

# ── Step 4: Delete Data (optional) ───────────────────────────
Write-Host "[4/5] Data cleanup..." -ForegroundColor Yellow

$deleteData = $false
if ($KeepData) {
  Write-Host "  [INFO] Keeping data (-KeepData flag)" -ForegroundColor DarkGray
} elseif ($Silent) {
  $deleteData = $true
} else {
  Write-Host ""
  Write-Host "  FlowGuard collected the following data:" -ForegroundColor White
  $dbFile  = Join-Path $CollectorDir "ccsm.db"
  $logDir  = Join-Path $ProjectDir "logs"
  if (Test-Path $dbFile)  { Write-Host "    • Events database: $dbFile" -ForegroundColor DarkGray }
  if (Test-Path $logDir)  { Write-Host "    • Logs: $logDir" -ForegroundColor DarkGray }
  Write-Host ""
  $delAnswer = Read-Host "  Delete all data? (y/N)"
  $deleteData = $delAnswer -match '^[Yy]$'
}

if ($deleteData) {
  # מחק DB
  $dbFile = Join-Path $CollectorDir "ccsm.db"
  if (Test-Path $dbFile) {
    Remove-Item $dbFile -Force -ErrorAction SilentlyContinue
    Write-Host "  [OK] Database deleted" -ForegroundColor Green
  }
  # מחק לוגים
  $logDir = Join-Path $ProjectDir "logs"
  if (Test-Path $logDir) {
    Remove-Item "$logDir\*.log" -Force -ErrorAction SilentlyContinue
    Write-Host "  [OK] Logs deleted" -ForegroundColor Green
  }
  # מחק .env
  $envFile = Join-Path $ProjectDir ".env"
  if (Test-Path $envFile) {
    Remove-Item $envFile -Force -ErrorAction SilentlyContinue
    Write-Host "  [OK] .env (credentials) deleted" -ForegroundColor Green
  }
} else {
  Write-Host "  [INFO] Data kept" -ForegroundColor DarkGray
}

# ── Step 5: Verify ────────────────────────────────────────────
Write-Host "[5/5] Verifying..." -ForegroundColor Yellow

$stillRunning = $false
try {
  Invoke-RestMethod -Uri "http://localhost:3010/health" -TimeoutSec 2 | Out-Null
  $stillRunning = $true
} catch { }

if ($stillRunning) {
  Write-Host "  [WARN] Collector still responding on port 3010 — restart may be needed" -ForegroundColor Yellow
} else {
  Write-Host "  [OK] Collector not running" -ForegroundColor Green
}

# הוקים
if (Test-Path $ClaudeConfig) {
  $check = Get-Content $ClaudeConfig -Raw -Encoding UTF8
  if ($check -match 'hook\.js') {
    Write-Host "  [WARN] hook.js still referenced in settings.json" -ForegroundColor Yellow
  } else {
    Write-Host "  [OK] No FlowGuard hooks in settings.json" -ForegroundColor Green
  }
}

# ── Done ──────────────────────────────────────────────────────
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Red
Write-Host "  FlowGuard uninstalled successfully." -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Red
Write-Host ""
Write-Host "  Thank you for using FlowGuard!" -ForegroundColor DarkGray
Write-Host "  by EHZ-AI | 054-4825276" -ForegroundColor DarkGray
Write-Host ""
