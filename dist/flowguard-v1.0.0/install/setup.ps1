# EHZ-SEC-AI -- Installer (PowerShell 5+ compatible)
# Adds Hooks to Claude Code settings.json and starts the Collector
# Run as: powershell -ExecutionPolicy Bypass -File setup.ps1

param(
  [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'

# --- Paths -------------------------------------------------------------------

$ProjectDir    = Split-Path -Parent $PSScriptRoot
$HookScript    = Join-Path $ProjectDir "agent\hook.js"
$CollectorDir  = Join-Path $ProjectDir "collector"
$ClaudeConfig  = "$env:USERPROFILE\.claude\settings.json"

$nodeCmd = Get-Command node -ErrorAction SilentlyContinue
$NodeExe = if ($nodeCmd) { $nodeCmd.Source } else { $null }

# --- Banner ------------------------------------------------------------------

Write-Host ""
Write-Host "  EHZ-SEC-AI -- Claude Code Security Monitor v1.0" -ForegroundColor Cyan
Write-Host "  Milestone 1 | EHZ-AI | 054-4825276" -ForegroundColor DarkGray
Write-Host ""

# --- Checks ------------------------------------------------------------------

if (-not $NodeExe) {
  Write-Host "[ERROR] Node.js not found. Install from https://nodejs.org/" -ForegroundColor Red
  exit 1
}
Write-Host "[OK] Node.js: $NodeExe" -ForegroundColor Green

if (-not (Test-Path $HookScript)) {
  Write-Host "[ERROR] hook.js not found: $HookScript" -ForegroundColor Red
  exit 1
}
Write-Host "[OK] hook.js: $HookScript" -ForegroundColor Green

# --- npm install -------------------------------------------------------------

Write-Host ""
Write-Host "[*] Installing dependencies..." -ForegroundColor Yellow
Push-Location $ProjectDir
  $npmOut = npm install 2>&1
  if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] npm install failed" -ForegroundColor Red
    Write-Host $npmOut
    Pop-Location
    exit 1
  }
Pop-Location
Write-Host "[OK] npm install done" -ForegroundColor Green

# --- Read / Create Claude settings.json -------------------------------------

Write-Host ""
if ($Uninstall) {
  Write-Host "[*] Removing hooks from Claude settings.json..." -ForegroundColor Yellow
} else {
  Write-Host "[*] Adding hooks to Claude settings.json..." -ForegroundColor Yellow
}

$ClaudeDir = "$env:USERPROFILE\.claude"
if (-not (Test-Path $ClaudeDir)) { New-Item -ItemType Directory -Path $ClaudeDir | Out-Null }

$settings = @{}
if (Test-Path $ClaudeConfig) {
  try {
    $raw = Get-Content $ClaudeConfig -Raw -Encoding UTF8
    $settings = $raw | ConvertFrom-Json -AsHashtable
  } catch {
    Write-Host "[WARN] settings.json invalid -- creating new" -ForegroundColor Yellow
    $settings = @{}
  }
}

$hookCmd = "node `"$($HookScript -replace '\\','/')`""

if ($Uninstall) {
  if ($settings.ContainsKey('hooks')) { $settings.Remove('hooks') }
  Write-Host "[OK] Hooks removed" -ForegroundColor Green
} else {
  $settings['hooks'] = @{
    PreToolUse  = @(@{ matcher = '.*'; hooks = @(@{ type = 'command'; command = $hookCmd }) })
    PostToolUse = @(@{ matcher = '.*'; hooks = @(@{ type = 'command'; command = $hookCmd }) })
  }
  Write-Host "[OK] Hooks added to settings.json" -ForegroundColor Green
}

$settings | ConvertTo-Json -Depth 10 | Set-Content $ClaudeConfig -Encoding UTF8
Write-Host "[OK] settings.json updated: $ClaudeConfig" -ForegroundColor Green

if ($Uninstall) {
  Write-Host ""
  Write-Host "  EHZ-SEC-AI removed successfully." -ForegroundColor Yellow
  exit 0
}

# --- Start Collector ---------------------------------------------------------

Write-Host ""
Write-Host "[*] Starting Collector..." -ForegroundColor Yellow

$collectorScript = Join-Path $CollectorDir "server.js"

# Check if already running
$healthOk = $false
try {
  $res = Invoke-RestMethod -Uri "http://localhost:3010/health" -TimeoutSec 2
  if ($res.ok) { $healthOk = $true }
} catch { }

if ($healthOk) {
  Write-Host "[INFO] Collector already running on http://localhost:3010" -ForegroundColor Cyan
} else {
  $logDir = Join-Path $ProjectDir "logs"
  if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir | Out-Null }

  Start-Process -FilePath $NodeExe `
                -ArgumentList "`"$collectorScript`"" `
                -WorkingDirectory $ProjectDir `
                -WindowStyle Hidden `
                -RedirectStandardOutput (Join-Path $logDir "collector.log") `
                -RedirectStandardError  (Join-Path $logDir "collector-error.log")

  Start-Sleep -Seconds 2

  try {
    $res2 = Invoke-RestMethod -Uri "http://localhost:3010/health" -TimeoutSec 3
    if ($res2.ok) {
      Write-Host "[OK] Collector running on http://localhost:3010" -ForegroundColor Green
    }
  } catch {
    Write-Host "[WARN] Collector did not respond -- check logs\collector-error.log" -ForegroundColor Yellow
  }
}

# --- Done --------------------------------------------------------------------

Write-Host ""
Write-Host "  EHZ-SEC-AI installed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "  Collector:  http://localhost:3010/health" -ForegroundColor White
Write-Host "  Events:     http://localhost:3010/events" -ForegroundColor White
Write-Host "  Stats:      http://localhost:3010/stats" -ForegroundColor White
Write-Host ""
Write-Host "  Disable:    create .ccsm-disable in project folder" -ForegroundColor DarkGray
Write-Host "  Remove:     setup.ps1 -Uninstall" -ForegroundColor DarkGray
Write-Host ""
