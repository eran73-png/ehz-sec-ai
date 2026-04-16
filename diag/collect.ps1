# ============================================================
# FlowGuard Diagnostics Collector — v1.0
# ============================================================
# Collects logs, config, and system info into a single ZIP file.
# All sensitive data (tokens, passwords, usernames) is sanitized.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File collect.ps1
#   powershell -ExecutionPolicy Bypass -File collect.ps1 -InstallDir "C:\FlowGuard"
# ============================================================

param(
    [string]$OutputDir    = "$env:USERPROFILE\Desktop",
    [string]$InstallDir   = "",
    [string]$SupportEmail = "eranhz26@gmail.com",
    [switch]$NoOpen,
    [switch]$NoMail
)

$ErrorActionPreference = 'SilentlyContinue'

# ─── Auto-detect install directory ──────────────────────────
if (-not $InstallDir) {
    $candidates = @(
        "C:\FlowGuard",
        "C:\Program Files\FlowGuard",
        "C:\Program Files (x86)\FlowGuard"
    )
    foreach ($c in $candidates) {
        if (Test-Path "$c\agent\tray.js") { $InstallDir = $c; break }
    }
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$hostname  = $env:COMPUTERNAME
$workDir   = "$env:TEMP\flowguard-diag-$timestamp"
$zipPath   = "$OutputDir\FlowGuard-Diag-$hostname-$timestamp.zip"

New-Item -ItemType Directory -Path $workDir -Force | Out-Null

Write-Host ""
Write-Host "FlowGuard Diagnostics Collector" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host "Install dir:  $InstallDir" -ForegroundColor Gray
Write-Host "Output:       $zipPath" -ForegroundColor Gray
Write-Host ""

# ─── Sanitization ───────────────────────────────────────────
function Sanitize-Text {
    param([string]$text)
    if (-not $text) { return $text }

    # Tokens & secrets
    $text = $text -replace '(?i)(TELEGRAM_TOKEN\s*[=:]\s*["'']?)[^\s\r\n"'']+', '${1}[REDACTED]'
    $text = $text -replace '(?i)(TELEGRAM_CHAT_ID\s*[=:]\s*["'']?)[^\s\r\n"'']+', '${1}[REDACTED]'
    $text = $text -replace '(?i)(api[_-]?key\s*[=:]\s*["'']?)[^\s\r\n"'']+', '${1}[REDACTED]'
    $text = $text -replace '(?i)(secret\s*[=:]\s*["'']?)[^\s\r\n"'']+', '${1}[REDACTED]'
    $text = $text -replace '(?i)(password\s*[=:]\s*["'']?)[^\s\r\n"'']+', '${1}[REDACTED]'
    $text = $text -replace '(?i)(token\s*[=:]\s*["'']?)[a-zA-Z0-9_\-]{16,}', '${1}[REDACTED]'

    # Bot token pattern (Telegram: digits:alphanumeric)
    $text = $text -replace '\b\d{7,12}:[A-Za-z0-9_\-]{30,}\b', '[REDACTED-BOT-TOKEN]'

    # Bearer tokens
    $text = $text -replace '(?i)(Bearer\s+)[A-Za-z0-9\._\-]{20,}', '${1}[REDACTED]'

    # User home paths
    $text = $text -replace [regex]::Escape("C:\Users\$env:USERNAME"), 'C:\Users\[USER]'
    $text = $text -replace [regex]::Escape("/Users/$env:USERNAME"),   '/Users/[USER]'
    $text = $text -replace [regex]::Escape("/home/$env:USERNAME"),    '/home/[USER]'

    # Raw username occurrences
    $text = $text -replace "(?i)\b$([regex]::Escape($env:USERNAME))\b", '[USER]'

    return $text
}

function Save-Sanitized {
    param([string]$source, [string]$dest)
    if (Test-Path $source) {
        $content   = Get-Content $source -Raw
        $sanitized = Sanitize-Text $content
        Set-Content -Path $dest -Value $sanitized -Encoding UTF8 -NoNewline
    }
}

# ─── 1. System Info ─────────────────────────────────────────
Write-Host "[1/8] Collecting system info..." -ForegroundColor Yellow

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")

$nodeVersion = try { (& node --version 2>&1) -join "`n" } catch { "NOT FOUND" }
$nodePath    = try { (Get-Command node).Source } catch { "NOT FOUND" }

$sysInfo = @"
FlowGuard Diagnostics Report
============================
Generated:       $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Hostname:        $hostname
User:            [USER]
Admin Rights:    $isAdmin

=== Operating System ===
OS:              $((Get-CimInstance Win32_OperatingSystem).Caption)
OS Version:      $([System.Environment]::OSVersion.Version)
OS Build:        $((Get-CimInstance Win32_OperatingSystem).BuildNumber)
Architecture:    $env:PROCESSOR_ARCHITECTURE
Locale:          $((Get-Culture).Name)

=== Runtime ===
PowerShell:      $($PSVersionTable.PSVersion)
Node.js:         $nodeVersion
Node.js Path:    $nodePath

=== FlowGuard Install ===
Install Dir:     $InstallDir
Dir Exists:      $(Test-Path $InstallDir)
VBS Exists:      $(Test-Path "$InstallDir\install\start-tray.vbs")
Tray.js Exists:  $(Test-Path "$InstallDir\agent\tray.js")
"@

$sysInfo | Out-File "$workDir\01-system-info.txt" -Encoding utf8

# ─── 2. Folder Structure ────────────────────────────────────
Write-Host "[2/8] Mapping install folder..." -ForegroundColor Yellow

if (Test-Path $InstallDir) {
    Get-ChildItem $InstallDir -Recurse -File |
        Select-Object @{N='Path';E={$_.FullName.Replace($InstallDir,'').TrimStart('\')}},
                       @{N='SizeKB';E={[math]::Round($_.Length/1KB,2)}},
                       @{N='Modified';E={$_.LastWriteTime}} |
        Sort-Object Path |
        Format-Table -AutoSize |
        Out-File "$workDir\02-folder-structure.txt" -Encoding utf8 -Width 200
} else {
    "Install directory not found: $InstallDir" | Out-File "$workDir\02-folder-structure.txt" -Encoding utf8
}

# ─── 3. Installer Logs ──────────────────────────────────────
Write-Host "[3/8] Collecting installer logs..." -ForegroundColor Yellow

$setupLogs = Get-ChildItem "$env:TEMP\Setup Log*.txt"
if ($setupLogs) {
    foreach ($log in $setupLogs) {
        Save-Sanitized -source $log.FullName -dest "$workDir\03-installer-$($log.Name)"
    }
} else {
    "No Inno Setup installer logs found in %TEMP%" | Out-File "$workDir\03-installer-none.txt" -Encoding utf8
}

# ─── 4. Config Files (Sanitized) ────────────────────────────
Write-Host "[4/8] Collecting config (sanitized)..." -ForegroundColor Yellow

$configFiles = @{
    "whitelist.json"    = "$InstallDir\whitelist.json"
    "package.json"      = "$InstallDir\package.json"
    "env-sanitized.txt" = "$InstallDir\.env"
}
foreach ($entry in $configFiles.GetEnumerator()) {
    if (Test-Path $entry.Value) {
        Save-Sanitized -source $entry.Value -dest "$workDir\04-config-$($entry.Key)"
    }
}

# ─── 5. Service Logs ────────────────────────────────────────
Write-Host "[5/8] Collecting service logs..." -ForegroundColor Yellow

$logDirs = @(
    "$InstallDir\collector\logs",
    "$InstallDir\logs",
    "$env:PROGRAMDATA\FlowGuard\logs"
)
$foundLogs = $false
foreach ($dir in $logDirs) {
    if (Test-Path $dir) {
        $logFiles = Get-ChildItem "$dir\*.log","$dir\*.txt" -File
        foreach ($f in $logFiles) {
            Save-Sanitized -source $f.FullName -dest "$workDir\05-log-$($f.Name)"
            $foundLogs = $true
        }
    }
}
if (-not $foundLogs) {
    "No service log files found" | Out-File "$workDir\05-logs-none.txt" -Encoding utf8
}

# ─── 6. Windows Event Log ───────────────────────────────────
Write-Host "[6/8] Collecting Event Log entries..." -ForegroundColor Yellow

try {
    $events = Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='*FlowGuard*'} -MaxEvents 100 -ErrorAction SilentlyContinue
    if ($events) {
        $events | Select-Object TimeCreated, LevelDisplayName, Id, Message |
            Format-List |
            Out-File "$workDir\06-event-log.txt" -Encoding utf8
    } else {
        "No FlowGuard events in Windows Event Log" | Out-File "$workDir\06-event-log.txt" -Encoding utf8
    }
} catch {
    "Failed to read Event Log: $_" | Out-File "$workDir\06-event-log.txt" -Encoding utf8
}

# ─── 7. Service Status ──────────────────────────────────────
Write-Host "[7/8] Checking service status..." -ForegroundColor Yellow

$serviceInfo = "FlowGuard Service Status`n=========================`n`n"
$serviceNames = @("FlowGuardCollector", "FlowGuard", "flowguard-collector")
$found = $false
foreach ($name in $serviceNames) {
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if ($svc) {
        $serviceInfo += @"
Service Name:  $($svc.Name)
Display Name:  $($svc.DisplayName)
Status:        $($svc.Status)
Start Type:    $($svc.StartType)

"@
        $found = $true
    }
}
if (-not $found) { $serviceInfo += "No FlowGuard service registered in Windows" }
$serviceInfo | Out-File "$workDir\07-service-status.txt" -Encoding utf8

# ─── 8. Port 3010 / Collector status ────────────────────────
Write-Host "[8/8] Checking collector port..." -ForegroundColor Yellow

$portInfo = "Collector Port Check`n====================`n`n"
$conn = Get-NetTCPConnection -LocalPort 3010 -ErrorAction SilentlyContinue
if ($conn) {
    $portInfo += "Port 3010: LISTENING (PID $($conn.OwningProcess))`n"
    try {
        $proc = Get-Process -Id $conn.OwningProcess
        $portInfo += "Process: $($proc.ProcessName) ($($proc.Path))`n"
    } catch {}
    try {
        $health = Invoke-WebRequest -Uri "http://localhost:3010/health" -UseBasicParsing -TimeoutSec 3
        $portInfo += "`nHealth endpoint response: $($health.StatusCode)`n$($health.Content)`n"
    } catch {
        $portInfo += "`nHealth endpoint: NOT RESPONDING`n"
    }
} else {
    $portInfo += "Port 3010: NOT LISTENING (collector service not running)`n"
}
$portInfo | Out-File "$workDir\08-port-check.txt" -Encoding utf8

# ─── Create ZIP ─────────────────────────────────────────────
Compress-Archive -Path "$workDir\*" -DestinationPath $zipPath -Force
Remove-Item $workDir -Recurse -Force

# ─── Done ───────────────────────────────────────────────────
$zipSize = [math]::Round((Get-Item $zipPath).Length / 1KB, 2)

Write-Host ""
Write-Host "================================================" -ForegroundColor Green
Write-Host "  DONE - Diagnostics ZIP created" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Green
Write-Host ""
Write-Host "File:       $zipPath" -ForegroundColor White
Write-Host "Size:       $zipSize KB" -ForegroundColor White
Write-Host ""

# ─── Open mail client with pre-filled email ─────────────────
if (-not $NoMail) {
    $subject = "FlowGuard Diagnostics - $hostname - $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
    $body    = @"
Hi Eran,

Attached: FlowGuard diagnostics report.

Hostname:  $hostname
Date:      $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
File size: $zipSize KB
File path: $zipPath

Describe the issue here:
[What were you trying to do? What happened? What error did you see?]

--
IMPORTANT: Please DRAG the ZIP file from the File Explorer window
(which just opened) into this email before sending.

All sensitive data has been sanitized automatically.
"@

    $encodedSubject = [System.Uri]::EscapeDataString($subject)
    $encodedBody    = [System.Uri]::EscapeDataString($body)
    $mailto         = "mailto:${SupportEmail}?subject=$encodedSubject&body=$encodedBody"

    Write-Host "Opening mail client..." -ForegroundColor Cyan
    Write-Host "  To: $SupportEmail" -ForegroundColor Gray
    Write-Host ""
    Write-Host "ACTION REQUIRED:" -ForegroundColor Yellow
    Write-Host "  1. Drag the ZIP file from File Explorer into the email" -ForegroundColor White
    Write-Host "  2. Add a short description of the issue" -ForegroundColor White
    Write-Host "  3. Click Send" -ForegroundColor White
    Write-Host ""

    try {
        Start-Process $mailto
    } catch {
        Write-Host "Could not open mail client automatically." -ForegroundColor Red
        Write-Host "Please send the ZIP manually to: $SupportEmail" -ForegroundColor Yellow
    }
}

Write-Host "All sensitive data (tokens, passwords, username) has been sanitized." -ForegroundColor Gray
Write-Host ""

if (-not $NoOpen) {
    explorer.exe "/select,$zipPath"
}
