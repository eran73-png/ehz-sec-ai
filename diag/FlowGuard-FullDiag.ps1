# ============================================================
# FlowGuard Full Diagnostic + QA Report v1.0
# Runs all checks, tests API, tests hooks, exports full report
# Run as Administrator on the target machine
# Output: FlowGuard-FullDiag-[date].txt on Desktop
# ============================================================

$ErrorActionPreference = 'SilentlyContinue'
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$outPath = Join-Path ([Environment]::GetFolderPath("Desktop")) "FlowGuard-FullDiag-$timestamp.txt"
$r = @()

function Log($msg) { $script:r += $msg; Write-Host $msg }
function LogOK($msg) { $script:r += "[PASS] $msg"; Write-Host "  [PASS] $msg" -ForegroundColor Green }
function LogFAIL($msg) { $script:r += "[FAIL] $msg"; Write-Host "  [FAIL] $msg" -ForegroundColor Red }
function LogINFO($msg) { $script:r += "[INFO] $msg"; Write-Host "  [INFO] $msg" -ForegroundColor Cyan }
function LogWARN($msg) { $script:r += "[WARN] $msg"; Write-Host "  [WARN] $msg" -ForegroundColor Yellow }
function Sep() { $line = "=" * 60; $script:r += $line; Write-Host $line -ForegroundColor DarkGray }

$pass = 0
$fail = 0
$warn = 0

function TestPass($name) { $script:pass++; LogOK $name }
function TestFail($name, $detail) { $script:fail++; LogFAIL "$name -- $detail" }
function TestWarn($name, $detail) { $script:warn++; LogWARN "$name -- $detail" }

# Try API call
function ApiGet($path) {
  try {
    $result = Invoke-RestMethod -Uri "http://127.0.0.1:3010$path" -TimeoutSec 10 -ErrorAction Stop
    return $result
  } catch {
    return $null
  }
}

function ApiPost($path, $body) {
  try {
    $json = $body | ConvertTo-Json -Depth 5
    $result = Invoke-RestMethod -Uri "http://127.0.0.1:3010$path" -Method POST -Body $json -ContentType "application/json" -TimeoutSec 15 -ErrorAction Stop
    return $result
  } catch {
    return $null
  }
}

# ============================================================
Write-Host ""
Write-Host "  ========================================" -ForegroundColor Cyan
Write-Host "  FlowGuard Full Diagnostic + QA" -ForegroundColor Cyan
Write-Host "  ========================================" -ForegroundColor Cyan
Write-Host ""

Log "FlowGuard Full Diagnostic Report"
Log "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Log "Computer: $env:COMPUTERNAME"
Log "User: $env:USERNAME"
Sep

# ============================================================
# PART 1: SYSTEM DIAGNOSTICS
# ============================================================
Log ""
Log "PART 1: SYSTEM DIAGNOSTICS"
Sep

# 1.1 PowerShell
Log ""
Log "--- 1.1 PowerShell ---"
LogINFO "Version: $($PSVersionTable.PSVersion)"
LogINFO "Edition: $($PSVersionTable.PSEdition)"
if ($PSVersionTable.PSVersion.Major -le 5) {
  TestWarn "PowerShell 5.x" "UTF-8 scripts may fail - ASCII only required"
} else {
  TestPass "PowerShell $($PSVersionTable.PSVersion)"
}

# 1.2 Node.js
Log ""
Log "--- 1.2 Node.js ---"
$nodeCmd = Get-Command node -ErrorAction SilentlyContinue
if ($nodeCmd) {
  $nodeVer = node --version 2>&1
  TestPass "Node.js $nodeVer at $($nodeCmd.Source)"
} else {
  TestFail "Node.js" "NOT FOUND - FlowGuard requires Node.js v18+"
}

# 1.3 FlowGuard Installation
Log ""
Log "--- 1.3 Installation ---"
$fgDir = $null
foreach ($p in @("C:\FlowGuard", "C:\Program Files\FlowGuard")) {
  if (Test-Path $p) { $fgDir = $p; break }
}
if ($fgDir) {
  TestPass "FlowGuard installed at $fgDir"
  # Check critical files
  $criticalFiles = @(
    "agent\hook.js",
    "agent\whitelist.json",
    "agent\rules.js",
    "collector\server.js",
    "dashboard\index-v2.html",
    "install\setup.ps1",
    "install\set-project-root.js",
    "package.json"
  )
  foreach ($cf in $criticalFiles) {
    $fp = Join-Path $fgDir $cf
    if (Test-Path $fp) {
      LogINFO "  OK: $cf ($((Get-Item $fp).Length) bytes)"
    } else {
      TestFail "Missing file" $cf
    }
  }
} else {
  TestFail "FlowGuard installation" "Not found in C:\FlowGuard or Program Files"
}

# 1.4 setup.ps1 Encoding
Log ""
Log "--- 1.4 setup.ps1 Encoding ---"
if ($fgDir) {
  $setupFile = Join-Path $fgDir "install\setup.ps1"
  if (Test-Path $setupFile) {
    $bytes = [System.IO.File]::ReadAllBytes($setupFile)
    $nonAscii = ($bytes | Where-Object { $_ -gt 127 }).Count
    LogINFO "File size: $($bytes.Length) bytes"
    LogINFO "Non-ASCII bytes: $nonAscii"
    if ($nonAscii -gt 0) {
      TestFail "setup.ps1 encoding" "$nonAscii non-ASCII bytes found - WILL FAIL on PowerShell 5"
      # Show which bytes
      $positions = @()
      for ($i = 0; $i -lt $bytes.Length; $i++) {
        if ($bytes[$i] -gt 127) { $positions += $i }
      }
      LogINFO "  Non-ASCII at positions: $($positions[0..9] -join ', ')$(if($positions.Count -gt 10){' ...'})"
    } else {
      TestPass "setup.ps1 encoding - ASCII only"
    }
    # Check BOM
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
      LogINFO "BOM: UTF-8 BOM present"
    } else {
      LogINFO "BOM: None"
    }
  }
}

# 1.5 Service
Log ""
Log "--- 1.5 Windows Service ---"
$svc = Get-Service -Name "FlowGuardCollector" -ErrorAction SilentlyContinue
if ($svc) {
  LogINFO "Status: $($svc.Status)"
  LogINFO "StartType: $($svc.StartType)"
  if ($svc.Status -eq "Running") {
    TestPass "FlowGuardCollector service running"
  } else {
    TestFail "FlowGuardCollector service" "Status: $($svc.Status) - not running"
  }
  try {
    $svcPath = (Get-WmiObject Win32_Service -Filter "Name='FlowGuardCollector'").PathName
    LogINFO "PathName: $svcPath"
  } catch { }
} else {
  TestFail "FlowGuardCollector service" "NOT REGISTERED"
}

# 1.6 .env
Log ""
Log "--- 1.6 .env Configuration ---"
if ($fgDir) {
  $envFile = Join-Path $fgDir ".env"
  if (Test-Path $envFile) {
    TestPass ".env file exists"
    $envContent = Get-Content $envFile -Raw
    if ($envContent -match "PROJECT_ROOT=(.+)") {
      LogINFO "PROJECT_ROOT=$($matches[1].Trim())"
    } else {
      TestWarn ".env PROJECT_ROOT" "not set"
    }
    if ($envContent -match "TELEGRAM_TOKEN=(.+)") {
      $tok = $matches[1].Trim()
      if ($tok.Length -gt 10) { LogINFO "TELEGRAM_TOKEN=***set***" } else { LogINFO "TELEGRAM_TOKEN=(empty)" }
    }
    if ($envContent -match "HARDENING_LEVEL=(.+)") {
      LogINFO "HARDENING_LEVEL=$($matches[1].Trim())"
    }
  } else {
    TestFail ".env file" "NOT FOUND - setup.ps1 probably failed during install"
  }
}

# 1.7 whitelist.json
Log ""
Log "--- 1.7 whitelist.json ---"
if ($fgDir) {
  $wlFile = Join-Path $fgDir "agent\whitelist.json"
  if (Test-Path $wlFile) {
    TestPass "whitelist.json exists"
    try {
      $wl = Get-Content $wlFile -Raw | ConvertFrom-Json
      if ($wl.project_root) {
        TestPass "project_root: $($wl.project_root)"
      } else {
        TestFail "project_root in whitelist.json" "NOT SET - installer set-project-root.js failed"
      }
      LogINFO "Domains: $($wl.domains.Count) whitelisted, $($wl.discovered_domains.Count) discovered"
    } catch {
      TestFail "whitelist.json parse" $_.Exception.Message
    }
  } else {
    TestFail "whitelist.json" "NOT FOUND"
  }
}

# 1.8 Claude hooks
Log ""
Log "--- 1.8 Claude Code Hooks ---"
$claudeSettings = "$env:USERPROFILE\.claude\settings.json"
if (Test-Path $claudeSettings) {
  TestPass "settings.json exists at $claudeSettings"
  try {
    $cs = Get-Content $claudeSettings -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($cs.hooks) {
      TestPass "hooks section found in settings.json"
      if ($cs.hooks.PreToolUse) {
        $hookCmd = $cs.hooks.PreToolUse[0].hooks[0].command
        LogINFO "PreToolUse hook: $hookCmd"
        # Verify hook.js path exists
        if ($hookCmd -match '"([^"]+hook\.js)"') {
          $hookPath = $matches[1]
          if (Test-Path $hookPath) {
            TestPass "hook.js exists at $hookPath"
          } else {
            TestFail "hook.js path in settings.json" "File not found: $hookPath"
          }
        }
      } else {
        TestFail "PreToolUse hook" "not configured"
      }
      if ($cs.hooks.PostToolUse) {
        TestPass "PostToolUse hook configured"
      } else {
        TestFail "PostToolUse hook" "not configured"
      }
    } else {
      TestFail "hooks in settings.json" "NO HOOKS SECTION - WebFetch will not be captured"
    }
  } catch {
    TestFail "settings.json parse" $_.Exception.Message
  }
  LogINFO "Full content:"
  LogINFO (Get-Content $claudeSettings -Raw -Encoding UTF8)
} else {
  TestFail "Claude settings.json" "NOT FOUND at $claudeSettings - hooks not installed"
}

# 1.9 Collector Logs
Log ""
Log "--- 1.9 Collector Logs (last 10 lines) ---"
if ($fgDir) {
  foreach ($logFile in @("logs\collector-stderr.log", "logs\collector-stdout.log")) {
    $lp = Join-Path $fgDir $logFile
    if (Test-Path $lp) {
      LogINFO "=== $logFile ==="
      try {
        Get-Content $lp -Tail 10 | ForEach-Object { LogINFO "  $_" }
      } catch { }
    }
  }
}

# ============================================================
# PART 2: API TESTS (same as QA Suite)
# ============================================================
Log ""
Log "PART 2: API TESTS"
Sep

# 2.1 Health
Log ""
Log "--- 2.1 Health ---"
$health = ApiGet "/health"
if ($health -and $health.ok) {
  TestPass "GET /health - ok:true"
  LogINFO "project_root: $($health.project_root)"
  if ($health.project_root -match "systemprofile") {
    TestFail "project_root" "Still systemprofile - config not applied"
  } else {
    TestPass "project_root is valid: $($health.project_root)"
  }
} else {
  TestFail "GET /health" "Service not responding on port 3010"
  Log ""
  Log "*** Cannot continue API tests - service not running ***"
  Log ""
  # Save and exit
  $r | Out-File -FilePath $outPath -Encoding ASCII
  Write-Host ""
  Write-Host "  Report saved to: $outPath" -ForegroundColor Green
  Read-Host "  Press Enter to close"
  exit
}

# 2.2 Events
Log ""
Log "--- 2.2 Events ---"
$events = ApiGet "/events?limit=5"
if ($events) {
  $evList = if ($events.events) { $events.events } else { $events }
  TestPass "GET /events - returned data"
  LogINFO "Total events in DB: $(if($events.total){$events.total}else{'unknown'})"
  # Check tool_name types
  $toolNames = ($evList | Select-Object -Property tool_name -Unique).tool_name
  LogINFO "Tool types found: $($toolNames -join ', ')"
} else {
  TestFail "GET /events" "no response"
}

$recent = ApiGet "/recent"
if ($recent) { TestPass "GET /recent - live feed" } else { TestFail "GET /recent" "no response" }

$stats = ApiGet "/stats"
if ($stats) {
  TestPass "GET /stats"
  LogINFO "Total: $($stats.total), Critical: $($stats.critical), High: $($stats.high)"
} else { TestFail "GET /stats" "no response" }

# 2.3 Sessions
Log ""
Log "--- 2.3 Sessions ---"
$sessions = ApiGet "/sessions"
if ($sessions) { TestPass "GET /sessions" } else { TestFail "GET /sessions" "no response" }

# 2.4 File Audit
Log ""
Log "--- 2.4 File Audit ---"
$audit = ApiGet "/audit"
if ($audit) {
  TestPass "GET /audit"
  $allFiles = $audit.all_files
  $filesWithIssues = $audit.files
  LogINFO "All files scanned: $(if($allFiles){$allFiles.Count}else{0})"
  LogINFO "Files with issues: $(if($filesWithIssues){$filesWithIssues.Count}else{0})"
} else { TestFail "GET /audit" "no response" }

$scanResult = ApiPost "/audit/scan" @{}
if ($scanResult -and ($scanResult.summary -or $scanResult.all_files)) {
  TestPass "POST /audit/scan"
  if ($scanResult.summary) {
    LogINFO "Scan: $($scanResult.summary.total_files) files, $($scanResult.summary.clean) clean"
  }
} else { TestFail "POST /audit/scan" "no response or bad format" }

$auditSchedule = ApiGet "/audit/schedule"
if ($auditSchedule) { TestPass "GET /audit/schedule" } else { TestFail "GET /audit/schedule" "no response" }

$auditVerify = ApiGet "/audit/verify"
if ($auditVerify) { TestPass "GET /audit/verify - hash chain" } else { TestFail "GET /audit/verify" "no response" }

# 2.5 Configuration
Log ""
Log "--- 2.5 Configuration ---"
$config = ApiGet "/config"
if ($config) {
  TestPass "GET /config"
  LogINFO "Hardening: $($config.hardening_level)"
} else { TestFail "GET /config" "no response" }

$projRoot = ApiGet "/config/project-root"
if ($projRoot -and $projRoot.project_root) {
  TestPass "GET /config/project-root: $($projRoot.project_root)"
} else { TestFail "GET /config/project-root" "empty or no response" }

$gitRemotes = ApiGet "/config/git-remotes"
if ($gitRemotes) { TestPass "GET /config/git-remotes" } else { TestFail "GET /config/git-remotes" "no response" }

# 2.6 Skills
Log ""
Log "--- 2.6 Skills ---"
$skills = ApiGet "/skills"
if ($skills) {
  TestPass "GET /skills"
  $skillList = if ($skills.skills) { $skills.skills } else { $skills }
  $count = if ($skillList -is [System.Collections.IDictionary]) { $skillList.Count } else { 0 }
  LogINFO "Skills found: $count"
} else { TestFail "GET /skills" "no response" }

# 2.7 Projects
Log ""
Log "--- 2.7 Projects ---"
$projects = ApiGet "/projects"
if ($projects -and ($projects.root -or $projects.tree)) {
  TestPass "GET /projects"
  LogINFO "Root: $($projects.root), Folders: $($projects.tree.Count)"
} else { TestFail "GET /projects" "no response" }

# 2.8 Browse
Log ""
Log "--- 2.8 Browse Dirs ---"
$browse = ApiGet "/browse-dirs"
if ($browse -and $browse.items) {
  TestPass "GET /browse-dirs - $($browse.items.Count) drives"
} else { TestFail "GET /browse-dirs" "no response" }

$browseC = ApiGet "/browse-dirs?path=C:/"
if ($browseC -and $browseC.items -and $browseC.items.Count -gt 0) {
  TestPass "GET /browse-dirs C:/ - $($browseC.items.Count) folders"
} else { TestFail "GET /browse-dirs C:/" "no response" }

# 2.9 Web Access / Domains
Log ""
Log "--- 2.9 Web Access ---"
$domains = ApiGet "/domains"
if ($domains) {
  TestPass "GET /domains"
  $disc = $domains.discovered_domains
  if ($disc) { LogINFO "Discovered domains: $($disc.Count)" }
  $allowed = $domains.allowed_domains
  if ($allowed) { LogINFO "Allowed domains: $($allowed.Count)" }
} else { TestFail "GET /domains" "no response" }

$domHistory = ApiGet "/domains/history"
if ($domHistory) {
  TestPass "GET /domains/history"
  $histItems = if ($domHistory -is [Array]) { $domHistory } else { @() }
  LogINFO "WebFetch history entries: $($histItems.Count)"
  if ($histItems.Count -eq 0) {
    TestWarn "WebFetch history" "EMPTY - hooks may not be sending WebFetch events"
  }
} else { TestFail "GET /domains/history" "no response" }

# 2.10 FSWatcher
Log ""
Log "--- 2.10 FSWatcher ---"
$fsw = ApiGet "/fsw/status"
if ($fsw) {
  TestPass "GET /fsw/status"
  LogINFO "Active: $($fsw.active), Path: $($fsw.watch_path), Events today: $($fsw.eventsToday)"
  if (-not $fsw.active) { TestWarn "FSWatcher" "not active" }
} else { TestFail "GET /fsw/status" "no response" }

$fswExclude = ApiGet "/fsw/exclude"
if ($fswExclude) { TestPass "GET /fsw/exclude" } else { TestFail "GET /fsw/exclude" "no response" }

$fswQuiet = ApiGet "/fsw/quiet-hours"
if ($fswQuiet) { TestPass "GET /fsw/quiet-hours" } else { TestFail "GET /fsw/quiet-hours" "no response" }

# 2.11 SIEM
Log ""
Log "--- 2.11 SIEM ---"
$siem = ApiGet "/siem/config"
if ($siem) { TestPass "GET /siem/config" } else { TestFail "GET /siem/config" "no response" }

# 2.12 Notifications
Log ""
Log "--- 2.12 Notifications ---"
$notif = ApiGet "/notifications/config"
if ($notif) { TestPass "GET /notifications/config" } else { TestFail "GET /notifications/config" "no response" }

$silent = ApiGet "/silent"
if ($silent -and $null -ne $silent.silent) {
  TestPass "GET /silent - value: $($silent.silent)"
} else { TestFail "GET /silent" "no response" }

# 2.13 Baseline
Log ""
Log "--- 2.13 Baseline ---"
$baseline = ApiGet "/baseline/status"
if ($baseline) { TestPass "GET /baseline/status" } else { TestFail "GET /baseline/status" "no response" }

# 2.14 Retention
Log ""
Log "--- 2.14 Retention ---"
$retention = ApiGet "/retention"
if ($retention) { TestPass "GET /retention" } else { TestFail "GET /retention" "no response" }

# 2.15 Update
Log ""
Log "--- 2.15 Update ---"
$updateStatus = ApiGet "/update/status"
if ($updateStatus) { TestPass "GET /update/status" } else { TestFail "GET /update/status" "no response" }

$updateSchedule = ApiGet "/update/schedule"
if ($updateSchedule) { TestPass "GET /update/schedule" } else { TestFail "GET /update/schedule" "no response" }

# 2.16 Diagnostics
Log ""
Log "--- 2.16 Diagnostics ---"
$diag = ApiGet "/diag/files"
if ($diag) { TestPass "GET /diag/files" } else { TestFail "GET /diag/files" "no response" }

# ============================================================
# PART 3: INTEGRATION TESTS
# ============================================================
Log ""
Log "PART 3: INTEGRATION TESTS"
Sep

# 3.1 FSW Create File
Log ""
Log "--- 3.1 FSW File Create ---"
if ($health -and $health.project_root -and (Test-Path $health.project_root)) {
  $testFile = Join-Path $health.project_root "__diag_test_$(Get-Random).txt"
  $beforeFsw = ApiGet "/fsw/status"
  $countBefore = if ($beforeFsw) { $beforeFsw.eventsToday } else { 0 }

  "FlowGuard diagnostic test file" | Out-File $testFile -Encoding ASCII
  Start-Sleep -Seconds 5

  $afterFsw = ApiGet "/fsw/status"
  $countAfter = if ($afterFsw) { $afterFsw.eventsToday } else { 0 }

  Remove-Item $testFile -Force -ErrorAction SilentlyContinue

  if ($countAfter -gt $countBefore) {
    TestPass "FSW detected file creation (events: $countBefore -> $countAfter)"
  } else {
    TestFail "FSW file creation" "Event count did not increase ($countBefore -> $countAfter)"
  }
} else {
  TestWarn "FSW test" "Cannot test - project_root not accessible"
}

# 3.2 FSW Delete File
Log ""
Log "--- 3.2 FSW File Delete ---"
if ($health -and $health.project_root -and (Test-Path $health.project_root)) {
  $testFile = Join-Path $health.project_root "__diag_del_$(Get-Random).txt"
  "FlowGuard diagnostic delete test" | Out-File $testFile -Encoding ASCII
  Start-Sleep -Seconds 4

  $beforeFsw = ApiGet "/fsw/status"
  $countBefore = if ($beforeFsw) { $beforeFsw.eventsToday } else { 0 }

  Remove-Item $testFile -Force -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 5

  $afterFsw = ApiGet "/fsw/status"
  $countAfter = if ($afterFsw) { $afterFsw.eventsToday } else { 0 }

  if ($countAfter -gt $countBefore) {
    TestPass "FSW detected file deletion (events: $countBefore -> $countAfter)"
  } else {
    TestFail "FSW file deletion" "Event count did not increase ($countBefore -> $countAfter)"
  }
} else {
  TestWarn "FSW test" "Cannot test - project_root not accessible"
}

# 3.3 Hook Test
Log ""
Log "--- 3.3 Hook Direct Test ---"
if ($fgDir) {
  $hookScript = Join-Path $fgDir "agent\hook.js"
  if (Test-Path $hookScript) {
    try {
      $testEvent = '{"event":{"hook_event_name":"PreToolUse","tool_name":"WebFetch","session_id":"diag-test","tool_input":{"url":"https://example.com","prompt":"test"}}}'
      $hookResult = $testEvent | node $hookScript 2>&1
      LogINFO "Hook output: $hookResult"
      if ($hookResult -match "allow" -or $hookResult -match "result") {
        TestPass "hook.js responds correctly"
      } else {
        TestWarn "hook.js response" "Unexpected: $hookResult"
      }
    } catch {
      TestFail "hook.js execution" $_.Exception.Message
    }

    # Check if the event was received by collector
    Start-Sleep -Seconds 2
    $recentEvents = ApiGet "/events?limit=5"
    if ($recentEvents) {
      $evList = if ($recentEvents.events) { $recentEvents.events } else { $recentEvents }
      $diagEvent = $evList | Where-Object { $_.session_id -eq "diag-test" }
      if ($diagEvent) {
        TestPass "Hook event received by collector"
        LogINFO "Tool: $($diagEvent.tool_name), Level: $($diagEvent.level)"
      } else {
        TestFail "Hook event delivery" "Event sent but not found in collector DB"
      }
    }
  } else {
    TestFail "hook.js" "not found at $hookScript"
  }
}

# ============================================================
# SUMMARY
# ============================================================
Log ""
Sep
Log ""
$total = $pass + $fail + $warn
$pct = if ($total -gt 0) { [math]::Round(($pass / $total) * 100) } else { 0 }

if ($fail -eq 0) {
  Log "RESULT: ALL TESTS PASSED ($pass/$total = $pct%)"
  Write-Host ""
  Write-Host "  ALL TESTS PASSED ($pass/$total = $pct%)" -ForegroundColor Green
} else {
  Log "RESULT: $fail FAILURES, $warn WARNINGS ($pass/$total passed = $pct%)"
  Write-Host ""
  Write-Host "  $fail FAILURES, $warn WARNINGS ($pass/$total passed = $pct%)" -ForegroundColor Red
  Log ""
  Log "FAILED TESTS:"
  $r | Where-Object { $_ -match "^\[FAIL\]" } | ForEach-Object { Log "  $_" }
}

if ($warn -gt 0) {
  Log ""
  Log "WARNINGS:"
  $r | Where-Object { $_ -match "^\[WARN\]" } | ForEach-Object { Log "  $_" }
}

Sep

# Save
$r | Out-File -FilePath $outPath -Encoding ASCII
Write-Host ""
Write-Host "  Report: $outPath" -ForegroundColor Green
Write-Host "  Send this file for analysis." -ForegroundColor Yellow
Write-Host ""
Read-Host "  Press Enter to close"
