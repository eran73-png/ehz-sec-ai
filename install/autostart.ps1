# ============================================================
# FlowGuard - Windows Auto-Start (MS8.9)
# Registers FlowGuard Collector + Tray in Task Scheduler
#
# Usage:
#   Install:    .\autostart.ps1
#   Uninstall:  .\autostart.ps1 -Remove
# ============================================================

param(
  [switch]$Remove
)

$ErrorActionPreference = 'Stop'

# -- Auto-elevate if not Administrator ---------------------------
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  $args = @('-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
  if ($Remove) { $args += '-Remove' }
  Start-Process powershell -ArgumentList $args -Verb RunAs
  exit
}

# -- Paths -------------------------------------------------------
$ProjectDir      = Split-Path -Parent $PSScriptRoot
$nodeCmd         = Get-Command node -ErrorAction SilentlyContinue
$NodeExe         = if ($nodeCmd) { $nodeCmd.Source } else { $null }
$CollectorScript = Join-Path $ProjectDir "collector\server.js"
$TrayScript      = Join-Path $ProjectDir "agent\tray.js"

$TaskCollector   = "FlowGuard-Collector"
$TaskTray        = "FlowGuard-Tray"

# -- Banner ------------------------------------------------------
Write-Host ""
Write-Host "  FlowGuard - Auto-Start Manager" -ForegroundColor Cyan
Write-Host "  by EHZ-AI" -ForegroundColor DarkGray
Write-Host ""

# -- Remove mode -------------------------------------------------
if ($Remove) {
  Write-Host "[*] Removing Auto-Start tasks..." -ForegroundColor Yellow

  foreach ($name in @($TaskCollector, $TaskTray)) {
    if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) {
      Unregister-ScheduledTask -TaskName $name -Confirm:$false
      Write-Host "  [OK] Removed: $name" -ForegroundColor Green
    } else {
      Write-Host "  [INFO] Not found: $name" -ForegroundColor DarkGray
    }
  }

  Write-Host ""
  Write-Host "  Auto-Start removed. FlowGuard will not start with Windows." -ForegroundColor Yellow
  Write-Host ""
  exit 0
}

# -- Checks ------------------------------------------------------
if (-not $NodeExe) {
  Write-Host "[ERROR] Node.js not found." -ForegroundColor Red
  exit 1
}
if (-not (Test-Path $CollectorScript)) {
  Write-Host "[ERROR] collector\server.js not found: $CollectorScript" -ForegroundColor Red
  exit 1
}

Write-Host "[OK] Node.js: $NodeExe" -ForegroundColor Green
Write-Host "[OK] Collector: $CollectorScript" -ForegroundColor Green
Write-Host ""

# -- Collector runs as Windows Service (FlowGuardCollector) -- skip Task Scheduler for it
$logDir = Join-Path $ProjectDir "logs"
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir | Out-Null }

# Remove old collector task if exists from previous installs
if (Get-ScheduledTask -TaskName $TaskCollector -ErrorAction SilentlyContinue) {
  Unregister-ScheduledTask -TaskName $TaskCollector -Confirm:$false
  Write-Host "  [OK] Removed old Collector task (now runs as Windows Service)" -ForegroundColor DarkGray
}

# -- Task: FlowGuard-Tray --------------------------------------
Write-Host "[2/2] Registering FlowGuard-Tray..." -ForegroundColor Yellow

if (Test-Path $TrayScript) {
  $actionTray = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-WindowStyle Hidden -NonInteractive -ExecutionPolicy Bypass -Command `"& '$NodeExe' '$TrayScript'`"" `
    -WorkingDirectory $ProjectDir

  $triggerTray = New-ScheduledTaskTrigger -AtLogOn
  $triggerTray.Delay = 'PT5S'

  $settingsTray = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Hours 0) `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -StartWhenAvailable `
    -MultipleInstances IgnoreNew

  $principalTray = New-ScheduledTaskPrincipal `
    -UserId $env:USERNAME `
    -LogonType Interactive `
    -RunLevel Limited

  if (Get-ScheduledTask -TaskName $TaskTray -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $TaskTray -Confirm:$false
  }

  Register-ScheduledTask `
    -TaskName    $TaskTray `
    -Action      $actionTray `
    -Trigger     $triggerTray `
    -Settings    $settingsTray `
    -Principal   $principalTray `
    -Description "FlowGuard AI Security Monitor - System Tray icon" | Out-Null

  Write-Host "  [OK] $TaskTray registered - starts 5s after login" -ForegroundColor Green
} else {
  Write-Host "  [SKIP] tray.js not found - skipping tray task" -ForegroundColor DarkGray
}

# -- Verify ------------------------------------------------------
Write-Host ""
Write-Host "[*] Verifying..." -ForegroundColor Yellow

$svc = Get-Service -Name "FlowGuardCollector" -ErrorAction SilentlyContinue
$t2  = Get-ScheduledTask -TaskName $TaskTray -ErrorAction SilentlyContinue

if ($svc) { Write-Host "  [OK] FlowGuardCollector Service - $($svc.Status)" -ForegroundColor Green }
if ($t2)  { Write-Host "  [OK] $TaskTray - $($t2.State)" -ForegroundColor Green }

# -- Done --------------------------------------------------------
Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  Auto-Start configured successfully!" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  FlowGuard will now start automatically with Windows." -ForegroundColor White
Write-Host ""
Write-Host "  To remove:  .\autostart.ps1 -Remove" -ForegroundColor DarkGray
Write-Host ""
