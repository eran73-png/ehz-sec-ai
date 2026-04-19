# ============================================================
# FlowGuard — Installer (MS8.3 + MS8.4)
# AI Security Monitor for Claude Code | by EHZ-AI
#
# Usage (interactive):  .\setup.ps1
# Usage (silent/GPO):   .\setup.ps1 -Silent -TelegramToken "TOKEN" -TelegramChatId "CHATID"
# Uninstall:            .\uninstall.ps1
# ============================================================

param(
  [switch]$Uninstall,
  [switch]$Silent,
  [string]$TelegramToken  = "",
  [string]$TelegramChatId = "",
  [string]$HardeningLevel = "1"
)

$ErrorActionPreference = 'Stop'
$Version = "2.4.2"

# ── Paths ────────────────────────────────────────────────────
$ProjectDir   = Split-Path -Parent $PSScriptRoot
$HookScript   = Join-Path $ProjectDir "agent\hook.js"
$CollectorDir = Join-Path $ProjectDir "collector"
$EnvFile      = Join-Path $ProjectDir ".env"
$ClaudeConfig = "$env:USERPROFILE\.claude\settings.json"
$nodeCmd      = Get-Command node -ErrorAction SilentlyContinue
$NodeExe      = if ($nodeCmd) { $nodeCmd.Source } else { $null }

# ── Banner ───────────────────────────────────────────────────
Write-Host ""
Write-Host "  ███████╗██╗      ██████╗ ██╗    ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ " -ForegroundColor Cyan
Write-Host "  ██╔════╝██║     ██╔═══██╗██║    ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗" -ForegroundColor Cyan
Write-Host "  █████╗  ██║     ██║   ██║██║ █╗ ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║" -ForegroundColor Cyan
Write-Host "  ██╔══╝  ██║     ██║   ██║██║███╗██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║" -ForegroundColor Cyan
Write-Host "  ██║     ███████╗╚██████╔╝╚███╔███╔╝╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝" -ForegroundColor Cyan
Write-Host "  ╚═╝     ╚══════╝ ╚═════╝  ╚══╝╚══╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ " -ForegroundColor Cyan
Write-Host ""
Write-Host "  FlowGuard v$Version — AI Security Monitor for Claude Code" -ForegroundColor White
Write-Host "  by EHZ-AI | 054-4825276" -ForegroundColor DarkGray
Write-Host ""

# ── Checks ───────────────────────────────────────────────────
if (-not $NodeExe) {
  Write-Host "[ERROR] Node.js not found. Install from https://nodejs.org/ (v18+)" -ForegroundColor Red
  exit 1
}
$nodeVersion = node --version
Write-Host "[OK] Node.js $nodeVersion" -ForegroundColor Green

if (-not (Test-Path $HookScript)) {
  Write-Host "[ERROR] hook.js not found: $HookScript" -ForegroundColor Red
  exit 1
}
Write-Host "[OK] hook.js found" -ForegroundColor Green

# ── npm install ──────────────────────────────────────────────
Write-Host ""
Write-Host "[*] Installing dependencies..." -ForegroundColor Yellow
Push-Location $ProjectDir
  $npmOut = npm install --omit=dev 2>&1
  if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] npm install failed" -ForegroundColor Red
    Write-Host $npmOut
    Pop-Location
    exit 1
  }
Pop-Location
Write-Host "[OK] Dependencies installed" -ForegroundColor Green

# ── Config Wizard (MS8.4) ────────────────────────────────────
if (-not $Uninstall) {
  Write-Host ""
  Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan
  Write-Host "  Configuration" -ForegroundColor Cyan
  Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan

  # Telegram Token
  if ($Silent -and $TelegramToken -ne "") {
    $finalToken  = $TelegramToken
    $finalChatId = $TelegramChatId
    Write-Host "[Silent] Telegram configured from parameters" -ForegroundColor DarkGray
  } else {
    # קרא מ-.env קיים אם יש
    $existingToken  = ""
    $existingChatId = ""
    if (Test-Path $EnvFile) {
      $envContent = Get-Content $EnvFile -Raw
      if ($envContent -match 'TELEGRAM_TOKEN=(.+)') { $existingToken  = $matches[1].Trim() }
      if ($envContent -match 'TELEGRAM_CHAT_ID=(.+)') { $existingChatId = $matches[1].Trim() }
    }

    Write-Host ""
    Write-Host "  Telegram Alerts (optional — press Enter to skip)" -ForegroundColor Yellow
    Write-Host ""

    $prompt1 = if ($existingToken) { "  Telegram Bot Token [$existingToken]: " } else { "  Telegram Bot Token: " }
    $inputToken = Read-Host $prompt1
    $finalToken = if ($inputToken -ne "") { $inputToken } else { $existingToken }

    if ($finalToken -ne "") {
      $prompt2 = if ($existingChatId) { "  Telegram Chat ID [$existingChatId]: " } else { "  Telegram Chat ID: " }
      $inputChatId = Read-Host $prompt2
      $finalChatId = if ($inputChatId -ne "") { $inputChatId } else { $existingChatId }
    } else {
      $finalChatId = ""
      Write-Host "  [INFO] Telegram skipped — alerts will be dashboard-only" -ForegroundColor DarkGray
    }

    # Hardening Level
    Write-Host ""
    Write-Host "  Hardening Level:" -ForegroundColor Yellow
    Write-Host "    0 = OFF   (no alerts)"
    Write-Host "    1 = SOFT  (Telegram HIGH+CRITICAL only)  [default]"
    Write-Host "    2 = STRICT (all alerts + extra rules)"
    Write-Host "    3 = LOCKDOWN (maximum)"
    $inputLevel = Read-Host "  Choose level [1]"
    $HardeningLevel = if ($inputLevel -match '^[0-3]$') { $inputLevel } else { "1" }
  }

  # כתוב .env
  $envLines = @(
    "TELEGRAM_TOKEN=$finalToken",
    "TELEGRAM_CHAT_ID=$finalChatId",
    "HARDENING_LEVEL=$HardeningLevel"
  )
  $envLines | Set-Content $EnvFile -Encoding UTF8
  Write-Host ""
  Write-Host "[OK] Config saved to .env (Hardening Level: $HardeningLevel)" -ForegroundColor Green
}

# ── Claude settings.json ─────────────────────────────────────
Write-Host ""
$ClaudeDir = "$env:USERPROFILE\.claude"
if (-not (Test-Path $ClaudeDir)) { New-Item -ItemType Directory -Path $ClaudeDir | Out-Null }

$settings = @{}
if (Test-Path $ClaudeConfig) {
  try {
    $raw = Get-Content $ClaudeConfig -Raw -Encoding UTF8
    $settings = $raw | ConvertFrom-Json -AsHashtable
  } catch {
    Write-Host "[WARN] settings.json invalid — creating new" -ForegroundColor Yellow
    $settings = @{}
  }
}

$hookCmd = "node `"$($HookScript -replace '\\','/')`""

if ($Uninstall) {
  Write-Host "[*] Removing hooks from Claude settings.json..." -ForegroundColor Yellow
  if ($settings.ContainsKey('hooks')) { $settings.Remove('hooks') }
  Write-Host "[OK] Hooks removed" -ForegroundColor Green
} else {
  Write-Host "[*] Adding hooks to Claude settings.json..." -ForegroundColor Yellow
  $settings['hooks'] = @{
    PreToolUse  = @(@{ matcher = '.*'; hooks = @(@{ type = 'command'; command = $hookCmd }) })
    PostToolUse = @(@{ matcher = '.*'; hooks = @(@{ type = 'command'; command = $hookCmd }) })
  }
  Write-Host "[OK] Hooks added" -ForegroundColor Green
}

$settings | ConvertTo-Json -Depth 10 | Set-Content $ClaudeConfig -Encoding UTF8
Write-Host "[OK] settings.json updated: $ClaudeConfig" -ForegroundColor Green

if ($Uninstall) {
  Write-Host ""
  Write-Host "  FlowGuard removed successfully." -ForegroundColor Yellow
  Write-Host ""
  exit 0
}

# ── Start Collector ──────────────────────────────────────────
Write-Host ""
Write-Host "[*] Starting Collector..." -ForegroundColor Yellow

$collectorScript = Join-Path $CollectorDir "server.js"
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
    Write-Host "[WARN] Collector did not respond — check logs\collector-error.log" -ForegroundColor Yellow
  }
}

# ── Done ─────────────────────────────────────────────────────
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "  FlowGuard installed successfully!" -ForegroundColor Green
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Dashboard:  http://localhost:3010/dashboard/index-v2.html" -ForegroundColor White
Write-Host "  Collector:  http://localhost:3010/health" -ForegroundColor White
Write-Host "  Level:      Hardening $HardeningLevel active" -ForegroundColor White
Write-Host ""
Write-Host "  Uninstall:  .\setup.ps1 -Uninstall" -ForegroundColor DarkGray
Write-Host "  Silent:     .\setup.ps1 -Silent -TelegramToken TOKEN -TelegramChatId ID" -ForegroundColor DarkGray
Write-Host ""
