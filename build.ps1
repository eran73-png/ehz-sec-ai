# ============================================================
# FlowGuard — Build Script (MS8.1)
# אורז את כל הפרויקט לתיקיית dist/ מוכנה להתקנה
# שימוש: .\build.ps1
# ============================================================

$Version   = "1.0.0"
$BuildName = "flowguard-v$Version"
$DistRoot  = "$PSScriptRoot\dist"
$OutDir    = "$DistRoot\$BuildName"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  FlowGuard Build Script v$Version" -ForegroundColor Cyan
Write-Host "  by EHZ-AI" -ForegroundColor DarkCyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ── 1. נקה dist ישן ──────────────────────────────────────────
if (Test-Path $OutDir) {
    Write-Host "[1/5] Cleaning old build..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force $OutDir
}
New-Item -ItemType Directory -Path $OutDir | Out-Null
Write-Host "[1/5] Output folder: $OutDir" -ForegroundColor Green

# ── 2. העתק קבצי ליבה ────────────────────────────────────────
Write-Host "[2/5] Copying core files..." -ForegroundColor Yellow

$Folders = @("agent", "collector", "config", "dashboard", "install", "scanner")
foreach ($f in $Folders) {
    $src = "$PSScriptRoot\$f"
    if (Test-Path $src) {
        Copy-Item -Recurse -Force $src "$OutDir\$f"
        Write-Host "  + $f\" -ForegroundColor DarkGreen
    }
}

# קבצים בודדים
Copy-Item "$PSScriptRoot\package.json"  "$OutDir\package.json"
Copy-Item "$PSScriptRoot\README.md"     "$OutDir\README.md" -ErrorAction SilentlyContinue

Write-Host "[2/5] Core files copied." -ForegroundColor Green

# ── 3. נקה קבצים מיותרים מה-dist ────────────────────────────
Write-Host "[3/5] Cleaning unnecessary files..." -ForegroundColor Yellow

# מחק .env אם הועתק בטעות
Remove-Item "$OutDir\agent\.env" -ErrorAction SilentlyContinue

# מחק logs
Remove-Item -Recurse -Force "$OutDir\collector\*.log" -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force "$OutDir\collector\ccsm.db" -ErrorAction SilentlyContinue

Write-Host "[3/5] Cleaned." -ForegroundColor Green

# ── 4. npm install --production ──────────────────────────────
Write-Host "[4/5] Installing production dependencies..." -ForegroundColor Yellow
Push-Location $OutDir
    npm install --omit=dev --silent
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: npm install failed!" -ForegroundColor Red
        Pop-Location
        exit 1
    }
Pop-Location
Write-Host "[4/5] Dependencies installed." -ForegroundColor Green

# ── 5. צור ZIP ───────────────────────────────────────────────
Write-Host "[5/5] Creating ZIP archive..." -ForegroundColor Yellow
$ZipPath = "$DistRoot\$BuildName.zip"
if (Test-Path $ZipPath) { Remove-Item $ZipPath }
Compress-Archive -Path $OutDir -DestinationPath $ZipPath
Write-Host "[5/5] ZIP created: $ZipPath" -ForegroundColor Green

# ── סיכום ────────────────────────────────────────────────────
$ZipSize = [math]::Round((Get-Item $ZipPath).Length / 1MB, 2)
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  BUILD COMPLETE" -ForegroundColor Green
Write-Host "  Folder : dist\$BuildName\" -ForegroundColor White
Write-Host "  ZIP    : dist\$BuildName.zip ($ZipSize MB)" -ForegroundColor White
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next step: run .\install\setup.ps1" -ForegroundColor DarkCyan
Write-Host ""
