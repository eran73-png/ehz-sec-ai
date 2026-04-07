# EHZ-SEC-AI — Installer
# מוסיף Hooks ל-Claude Code settings.json ומפעיל את ה-Collector
# הרץ כ: powershell -ExecutionPolicy Bypass -File setup.ps1

param(
  [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'

# ─── Paths ────────────────────────────────────────────────────────────────────

$ProjectDir    = Split-Path -Parent $PSScriptRoot
$HookScript    = Join-Path $ProjectDir "agent\hook.js"
$CollectorDir  = Join-Path $ProjectDir "collector"
$ClaudeConfig  = "$env:USERPROFILE\.claude\settings.json"
$NodeExe       = (Get-Command node -ErrorAction SilentlyContinue)?.Source

# ─── Banner ───────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "  ███████╗██╗  ██╗███████╗      ███████╗███████╗ ██████╗" -ForegroundColor Cyan
Write-Host "  ██╔════╝██║  ██║╚══███╔╝      ██╔════╝██╔════╝██╔════╝" -ForegroundColor Cyan
Write-Host "  █████╗  ███████║  ███╔╝ █████╗███████╗█████╗  ██║     " -ForegroundColor Cyan
Write-Host "  ██╔══╝  ██╔══██║ ███╔╝  ╚════╝╚════██║██╔══╝  ██║     " -ForegroundColor Cyan
Write-Host "  ███████╗██║  ██║███████╗      ███████║███████╗╚██████╗" -ForegroundColor Cyan
Write-Host "  ╚══════╝╚═╝  ╚═╝╚══════╝      ╚══════╝╚══════╝ ╚═════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Claude Code Security Monitor — v1.0 (Milestone 1)" -ForegroundColor White
Write-Host "  EHZ-AI | ערן | 054-4825276" -ForegroundColor DarkGray
Write-Host ""

# ─── Checks ───────────────────────────────────────────────────────────────────

if (-not $NodeExe) {
  Write-Host "[ERROR] Node.js לא נמצא. התקן מ-https://nodejs.org/" -ForegroundColor Red
  exit 1
}
Write-Host "[OK] Node.js: $NodeExe" -ForegroundColor Green

if (-not (Test-Path $HookScript)) {
  Write-Host "[ERROR] hook.js לא נמצא: $HookScript" -ForegroundColor Red
  exit 1
}
Write-Host "[OK] hook.js: $HookScript" -ForegroundColor Green

# ─── npm install ──────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "[*] מתקין dependencies..." -ForegroundColor Yellow
Push-Location $ProjectDir
  npm install --silent 2>&1 | Out-Null
  if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] npm install נכשל" -ForegroundColor Red
    exit 1
  }
Pop-Location
Write-Host "[OK] npm install הושלם" -ForegroundColor Green

# ─── Read / Create Claude settings.json ──────────────────────────────────────

Write-Host ""
if ($Uninstall) {
  Write-Host "[*] מסיר Hooks מ-Claude settings.json..." -ForegroundColor Yellow
} else {
  Write-Host "[*] מוסיף Hooks ל-Claude settings.json..." -ForegroundColor Yellow
}

# Ensure .claude directory exists
$ClaudeDir = "$env:USERPROFILE\.claude"
if (-not (Test-Path $ClaudeDir)) { New-Item -ItemType Directory -Path $ClaudeDir | Out-Null }

# Read existing settings or start fresh
$settings = @{}
if (Test-Path $ClaudeConfig) {
  try {
    $settings = Get-Content $ClaudeConfig -Raw | ConvertFrom-Json -AsHashtable
  } catch {
    Write-Host "[WARN] settings.json לא תקין — יוצר חדש" -ForegroundColor Yellow
    $settings = @{}
  }
}

$hookCmd = "node `"$($HookScript -replace '\\','/')`""

if ($Uninstall) {
  # Remove hooks
  if ($settings.ContainsKey('hooks')) { $settings.Remove('hooks') }
  Write-Host "[OK] Hooks הוסרו" -ForegroundColor Green
} else {
  # Add / overwrite hooks section
  $settings['hooks'] = @{
    PreToolUse  = @(@{ matcher = '.*'; hooks = @(@{ type = 'command'; command = $hookCmd }) })
    PostToolUse = @(@{ matcher = '.*'; hooks = @(@{ type = 'command'; command = $hookCmd }) })
    # ConfigChange hook (Milestone 12.2) — uncomment when ready:
    # ConfigChange = @(@{ hooks = @(@{ type = 'command'; command = $hookCmd }) })
  }
  Write-Host "[OK] Hooks נוספו ל-settings.json" -ForegroundColor Green
}

# Write back
$settings | ConvertTo-Json -Depth 10 | Set-Content $ClaudeConfig -Encoding UTF8
Write-Host "[OK] settings.json עודכן: $ClaudeConfig" -ForegroundColor Green

if ($Uninstall) {
  Write-Host ""
  Write-Host "  ✅ EHZ-SEC-AI הוסר בהצלחה" -ForegroundColor Yellow
  exit 0
}

# ─── Start Collector ──────────────────────────────────────────────────────────

Write-Host ""
Write-Host "[*] מפעיל Collector..." -ForegroundColor Yellow

# Check if already running
$existing = Get-Process -Name "node" -ErrorAction SilentlyContinue |
  Where-Object { $_.MainWindowTitle -like '*ccsm*' -or $_.CommandLine -like '*server.js*' }

if ($existing) {
  Write-Host "[INFO] Collector כבר רץ (PID $($existing.Id))" -ForegroundColor Cyan
} else {
  $collectorScript = Join-Path $CollectorDir "server.js"
  Start-Process -FilePath $NodeExe `
                -ArgumentList "`"$collectorScript`"" `
                -WorkingDirectory $ProjectDir `
                -WindowStyle Hidden `
                -RedirectStandardOutput (Join-Path $ProjectDir "logs\collector.log") `
                -RedirectStandardError  (Join-Path $ProjectDir "logs\collector-error.log")

  Start-Sleep -Seconds 2

  # Health check
  try {
    $res = Invoke-RestMethod -Uri "http://localhost:3010/health" -TimeoutSec 3
    if ($res.ok) {
      Write-Host "[OK] Collector רץ על http://localhost:3010" -ForegroundColor Green
    }
  } catch {
    Write-Host "[WARN] Collector לא הגיב — בדוק logs\collector-error.log" -ForegroundColor Yellow
  }
}

# ─── Done ─────────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "  ✅ EHZ-SEC-AI הותקן בהצלחה!" -ForegroundColor Green
Write-Host ""
Write-Host "  Collector:  http://localhost:3010/health" -ForegroundColor White
Write-Host "  Events:     http://localhost:3010/events" -ForegroundColor White
Write-Host "  Dashboard:  פתח dashboard-demo.html בדפדפן" -ForegroundColor White
Write-Host ""
Write-Host "  להשבית:     יצור קובץ .ccsm-disable בתיקיית הפרויקט" -ForegroundColor DarkGray
Write-Host "  להסיר:      setup.ps1 -Uninstall" -ForegroundColor DarkGray
Write-Host ""
