# ============================================================
# FlowGuard - Windows Service Installer (v2.4.3)
# Registers FlowGuard-Collector as a real Windows Service
# using NSSM (Non-Sucking Service Manager)
#
# Usage:
#   Install:    .\install-service.ps1
#   Uninstall:  .\install-service.ps1 -Remove
# ============================================================

param([switch]$Remove)

$ErrorActionPreference = 'Stop'

# -- Check Administrator (Inno Setup already runs as admin) --
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "[WARN] Not running as Administrator — service install may fail" -ForegroundColor Yellow
}

# -- Paths ---------------------------------------------------
$ProjectDir  = Split-Path -Parent $PSScriptRoot
$NssmExe     = Join-Path $PSScriptRoot "..\tools\nssm.exe"
$NodeCmd     = Get-Command node -ErrorAction SilentlyContinue
$NodeExe     = if ($NodeCmd) { $NodeCmd.Source } else { $null }
$Collector   = Join-Path $ProjectDir "collector\server.js"
$ServiceName = "FlowGuardCollector"
$LogDir      = Join-Path $ProjectDir "logs"

Write-Host ""
Write-Host "  FlowGuard - Service Manager" -ForegroundColor Cyan
Write-Host "  by EHZ-AI" -ForegroundColor DarkGray
Write-Host ""

# -- Remove mode ---------------------------------------------
if ($Remove) {
  Write-Host "[*] Removing FlowGuard Windows Service..." -ForegroundColor Yellow
  $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
  if ($svc) {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    & $NssmExe remove $ServiceName confirm
    Write-Host "  [OK] Service removed." -ForegroundColor Green
  } else {
    Write-Host "  [INFO] Service not found." -ForegroundColor DarkGray
  }
  exit 0
}

# -- Checks --------------------------------------------------
if (-not (Test-Path $NssmExe)) {
  Write-Host "[ERROR] nssm.exe not found: $NssmExe" -ForegroundColor Red; exit 1
}
if (-not $NodeExe) {
  Write-Host "[ERROR] Node.js not found." -ForegroundColor Red; exit 1
}
if (-not (Test-Path $Collector)) {
  Write-Host "[ERROR] collector\server.js not found." -ForegroundColor Red; exit 1
}

if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir | Out-Null }

Write-Host "[OK] Node.js: $NodeExe" -ForegroundColor Green
Write-Host "[OK] NSSM:    $NssmExe" -ForegroundColor Green
Write-Host ""

# -- Remove existing service if any --------------------------
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
  Write-Host "[*] Removing existing service..." -ForegroundColor Yellow
  Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
  & $NssmExe remove $ServiceName confirm
}

# -- Install Service -----------------------------------------
Write-Host "[*] Installing FlowGuard as Windows Service..." -ForegroundColor Yellow

& $NssmExe install $ServiceName $NodeExe $Collector
& $NssmExe set $ServiceName AppDirectory $ProjectDir
& $NssmExe set $ServiceName DisplayName "FlowGuard Collector"
& $NssmExe set $ServiceName Description "FlowGuard AI Security Monitor — Event Collector (port 3010)"
& $NssmExe set $ServiceName Start SERVICE_AUTO_START

# Restart on failure — 3 times, 5 second delay
& $NssmExe set $ServiceName AppRestartDelay 5000
& $NssmExe set $ServiceName AppThrottle 5000
& $NssmExe set $ServiceName AppExit Default Restart

# Logging
& $NssmExe set $ServiceName AppStdout (Join-Path $LogDir "collector-stdout.log")
& $NssmExe set $ServiceName AppStderr (Join-Path $LogDir "collector-stderr.log")
& $NssmExe set $ServiceName AppRotateFiles 1
& $NssmExe set $ServiceName AppRotateSeconds 86400

Write-Host "  [OK] Service installed." -ForegroundColor Green

# -- Start Service -------------------------------------------
Write-Host "[*] Starting service..." -ForegroundColor Yellow
Start-Service -Name $ServiceName
Start-Sleep -Seconds 3

$svc = Get-Service -Name $ServiceName
if ($svc.Status -eq 'Running') {
  Write-Host "  [OK] FlowGuardCollector is RUNNING" -ForegroundColor Green
} else {
  Write-Host "  [WARN] Service status: $($svc.Status)" -ForegroundColor Yellow
}

# -- Remove old Task Scheduler task if exists ----------------
if (Get-ScheduledTask -TaskName "FlowGuard-Collector" -ErrorAction SilentlyContinue) {
  Write-Host "[*] Removing old Task Scheduler task..." -ForegroundColor Yellow
  Unregister-ScheduledTask -TaskName "FlowGuard-Collector" -Confirm:$false
  Write-Host "  [OK] Old task removed." -ForegroundColor Green
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  FlowGuard Service installed!" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Service: FlowGuardCollector" -ForegroundColor White
Write-Host "  Status:  Auto-start + Restart on failure" -ForegroundColor White
Write-Host "  Logs:    $LogDir" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  To remove:  .\install-service.ps1 -Remove" -ForegroundColor DarkGray
Write-Host ""
