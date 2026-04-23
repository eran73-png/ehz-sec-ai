# ============================================================
# FlowGuard Diagnostic Script v1.0
# Collects all info needed to debug installation issues
# Run as Administrator on the target machine
# Output: FlowGuard-Diag-Report.txt on Desktop
# ============================================================

$report = @()
$report += "============================================================"
$report += "FlowGuard Diagnostic Report"
$report += "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$report += "Computer: $env:COMPUTERNAME"
$report += "User: $env:USERNAME"
$report += "============================================================"
$report += ""

# 1. PowerShell Version
$report += "--- 1. PowerShell Version ---"
$report += "Version: $($PSVersionTable.PSVersion)"
$report += "Edition: $($PSVersionTable.PSEdition)"
$report += ""

# 2. Node.js
$report += "--- 2. Node.js ---"
try {
  $nodeVer = node --version 2>&1
  $report += "Node.js: $nodeVer"
  $nodePath = (Get-Command node -ErrorAction SilentlyContinue).Source
  $report += "Path: $nodePath"
} catch {
  $report += "Node.js: NOT FOUND"
}
$report += ""

# 3. FlowGuard Installation
$report += "--- 3. FlowGuard Installation ---"
$fgPaths = @("C:\FlowGuard", "C:\Program Files\FlowGuard")
foreach ($p in $fgPaths) {
  if (Test-Path $p) {
    $report += "Found: $p"
    $report += "  Files:"
    Get-ChildItem $p -File -ErrorAction SilentlyContinue | ForEach-Object { $report += "    $($_.Name) ($($_.Length) bytes)" }
    $report += "  Folders:"
    Get-ChildItem $p -Directory -ErrorAction SilentlyContinue | ForEach-Object { $report += "    $($_.Name)/" }
  } else {
    $report += "Not found: $p"
  }
}
$report += ""

# 4. Service Status
$report += "--- 4. FlowGuard Service ---"
$svc = Get-Service -Name "FlowGuardCollector" -ErrorAction SilentlyContinue
if ($svc) {
  $report += "Status: $($svc.Status)"
  $report += "StartType: $($svc.StartType)"
  # Get service path
  try {
    $svcPath = (Get-WmiObject Win32_Service -Filter "Name='FlowGuardCollector'" -ErrorAction SilentlyContinue).PathName
    $report += "PathName: $svcPath"
  } catch { }
} else {
  $report += "Service NOT FOUND"
}
$report += ""

# 5. Health Check
$report += "--- 5. Health Check (localhost:3010) ---"
try {
  $health = Invoke-RestMethod -Uri "http://127.0.0.1:3010/health" -TimeoutSec 5
  $report += "OK: true"
  $report += "project_root: $($health.project_root)"
  $report += "timestamp: $($health.ts)"
} catch {
  $report += "FAILED: $($_.Exception.Message)"
}
$report += ""

# 6. Claude settings.json (hooks)
$report += "--- 6. Claude settings.json ---"
$claudeSettings = "$env:USERPROFILE\.claude\settings.json"
if (Test-Path $claudeSettings) {
  $report += "Found: $claudeSettings"
  $report += "Size: $((Get-Item $claudeSettings).Length) bytes"
  try {
    $content = Get-Content $claudeSettings -Raw -Encoding UTF8
    $report += "Content:"
    $report += $content
  } catch {
    $report += "Cannot read: $($_.Exception.Message)"
  }
} else {
  $report += "NOT FOUND: $claudeSettings"
  $report += "*** THIS IS THE PROBLEM - hooks not installed ***"
}
$report += ""

# 7. .claude directory contents
$report += "--- 7. .claude directory ---"
$claudeDir = "$env:USERPROFILE\.claude"
if (Test-Path $claudeDir) {
  Get-ChildItem $claudeDir -ErrorAction SilentlyContinue | ForEach-Object {
    $type = if ($_.PSIsContainer) { "DIR" } else { "FILE ($($_.Length) bytes)" }
    $report += "  $($_.Name) - $type"
  }
} else {
  $report += "Directory not found: $claudeDir"
}
$report += ""

# 8. whitelist.json
$report += "--- 8. whitelist.json ---"
$wlPaths = @("C:\FlowGuard\agent\whitelist.json", "C:\Program Files\FlowGuard\agent\whitelist.json")
foreach ($wl in $wlPaths) {
  if (Test-Path $wl) {
    $report += "Found: $wl"
    try {
      $wlContent = Get-Content $wl -Raw | ConvertFrom-Json
      $report += "project_root: $($wlContent.project_root)"
      $report += "domains count: $($wlContent.domains.Count)"
      $report += "discovered count: $($wlContent.discovered_domains.Count)"
    } catch {
      $report += "Parse error: $($_.Exception.Message)"
    }
  }
}
$report += ""

# 9. .env file
$report += "--- 9. .env file ---"
$envPaths = @("C:\FlowGuard\.env", "C:\Program Files\FlowGuard\.env")
foreach ($envP in $envPaths) {
  if (Test-Path $envP) {
    $report += "Found: $envP"
    $report += (Get-Content $envP -Raw)
  }
}
if (-not (Test-Path "C:\FlowGuard\.env") -and -not (Test-Path "C:\Program Files\FlowGuard\.env")) {
  $report += "NOT FOUND - setup.ps1 probably failed"
}
$report += ""

# 10. setup.ps1 encoding test
$report += "--- 10. setup.ps1 Encoding Test ---"
$setupPaths = @("C:\FlowGuard\install\setup.ps1", "C:\Program Files\FlowGuard\install\setup.ps1")
foreach ($sp in $setupPaths) {
  if (Test-Path $sp) {
    $report += "Found: $sp"
    $report += "Size: $((Get-Item $sp).Length) bytes"
    # Check for non-ASCII characters
    $bytes = [System.IO.File]::ReadAllBytes($sp)
    $nonAscii = ($bytes | Where-Object { $_ -gt 127 }).Count
    $report += "Non-ASCII bytes: $nonAscii"
    if ($nonAscii -gt 0) {
      $report += "*** WARNING: setup.ps1 contains non-ASCII characters - will fail on PowerShell 5 ***"
    } else {
      $report += "OK - ASCII only"
    }
    # Check BOM
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
      $report += "BOM: UTF-8 BOM detected"
    } else {
      $report += "BOM: No BOM"
    }
  }
}
$report += ""

# 11. hook.js existence
$report += "--- 11. hook.js ---"
$hookPaths = @("C:\FlowGuard\agent\hook.js", "C:\Program Files\FlowGuard\agent\hook.js")
foreach ($hp in $hookPaths) {
  if (Test-Path $hp) {
    $report += "Found: $hp ($((Get-Item $hp).Length) bytes)"
  }
}
$report += ""

# 12. Collector logs
$report += "--- 12. Collector Logs (last 20 lines) ---"
$logPaths = @("C:\FlowGuard\logs\collector-stderr.log", "C:\FlowGuard\logs\collector-stdout.log")
foreach ($lp in $logPaths) {
  if (Test-Path $lp) {
    $report += "=== $lp ==="
    try {
      $lines = Get-Content $lp -Tail 20 -ErrorAction SilentlyContinue
      $lines | ForEach-Object { $report += "  $_" }
    } catch {
      $report += "  Cannot read: $($_.Exception.Message)"
    }
  }
}
$report += ""

# 13. Recent events (WebFetch check)
$report += "--- 13. Recent WebFetch Events ---"
try {
  $events = Invoke-RestMethod -Uri "http://127.0.0.1:3010/events?limit=50" -TimeoutSec 5
  $allEvents = if ($events.events) { $events.events } else { $events }
  $webEvents = $allEvents | Where-Object { $_.tool_name -match "Web|Fetch|Search" }
  if ($webEvents) {
    $report += "Found $($webEvents.Count) web events:"
    $webEvents | ForEach-Object { $report += "  [$($_.tool_name)] $($_.reason) ($($_.level))" }
  } else {
    $report += "No WebFetch/WebSearch events found in last 50 events"
    $report += "Tool names found:"
    $allEvents | Select-Object -Property tool_name -Unique | ForEach-Object { $report += "  $($_.tool_name)" }
  }
} catch {
  $report += "Cannot reach API: $($_.Exception.Message)"
}
$report += ""

# 14. FSW Status
$report += "--- 14. FSWatcher Status ---"
try {
  $fsw = Invoke-RestMethod -Uri "http://127.0.0.1:3010/fsw/status" -TimeoutSec 5
  $report += "Active: $($fsw.active)"
  $report += "Watch path: $($fsw.watch_path)"
  $report += "Events today: $($fsw.eventsToday)"
} catch {
  $report += "Cannot reach API: $($_.Exception.Message)"
}
$report += ""

# 15. Test hook.js directly
$report += "--- 15. hook.js Direct Test ---"
$hookScript = $null
foreach ($hp in $hookPaths) { if (Test-Path $hp) { $hookScript = $hp; break } }
if ($hookScript) {
  $report += "Testing: node `"$hookScript`""
  try {
    $testInput = '{"event":{"hook_event_name":"PreToolUse","tool_name":"WebFetch","session_id":"diag-test","tool_input":{"url":"https://example.com"}}}'
    $result = $testInput | node $hookScript 2>&1
    $report += "Output: $result"
  } catch {
    $report += "Error: $($_.Exception.Message)"
  }
} else {
  $report += "hook.js not found"
}
$report += ""

$report += "============================================================"
$report += "END OF DIAGNOSTIC REPORT"
$report += "============================================================"

# Save report
$outPath = Join-Path ([Environment]::GetFolderPath("Desktop")) "FlowGuard-Diag-Report.txt"
$report | Out-File -FilePath $outPath -Encoding ASCII
Write-Host ""
Write-Host "  Report saved to: $outPath" -ForegroundColor Green
Write-Host "  Send this file for analysis." -ForegroundColor Yellow
Write-Host ""
Write-Host "  Press Enter to close..."
Read-Host
