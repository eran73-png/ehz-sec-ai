# ============================================================
# FlowGuard — Build Script
# קורא גרסה מ-package.json → מעדכן FlowGuard.iss → בונה EXE
# שימוש: .\build.ps1
#        .\build.ps1 -BumpPatch     (מעלה x.x.X)
#        .\build.ps1 -BumpMinor     (מעלה x.X.0)
# ============================================================

param(
    [switch]$BumpPatch,
    [switch]$BumpMinor
)

$ErrorActionPreference = 'Stop'
$Root    = $PSScriptRoot
$PkgFile = Join-Path $Root 'package.json'
$IssFile = Join-Path $Root 'install\FlowGuard.iss'
$ISCC    = 'C:\Program Files (x86)\Inno Setup 6\ISCC.exe'

# ── 1. קרא גרסה נוכחית מ-package.json ──────────────────────
$pkg     = Get-Content $PkgFile -Raw | ConvertFrom-Json
$current = $pkg.version
$parts   = $current -split '\.'
$major   = [int]$parts[0]
$minor   = [int]$parts[1]
$patch   = [int]$parts[2]

# ── 2. Bump גרסה אם התבקש ──────────────────────────────────
if ($BumpMinor) {
    $minor++; $patch = 0
} elseif ($BumpPatch) {
    $patch++
}

$newVersion = "$major.$minor.$patch"

# ── 3. עדכן package.json ───────────────────────────────────
if ($newVersion -ne $current) {
    $content = Get-Content $PkgFile -Raw
    $content = $content -replace '"version": "[0-9]+\.[0-9]+\.[0-9]+"', "`"version`": `"$newVersion`""
    Set-Content $PkgFile $content -Encoding UTF8
    Write-Host "package.json: $current -> $newVersion" -ForegroundColor Cyan
} else {
    Write-Host "package.json: v$newVersion (ללא שינוי)" -ForegroundColor Gray
}

# ── 4. עדכן FlowGuard.iss ──────────────────────────────────
$iss = Get-Content $IssFile -Raw
$iss = $iss -replace '#define AppVersion "[0-9]+\.[0-9]+\.[0-9]+"', "#define AppVersion `"$newVersion`""
Set-Content $IssFile $iss -Encoding UTF8
Write-Host "FlowGuard.iss: AppVersion = $newVersion" -ForegroundColor Cyan

# ── 5. בנה EXE ──────────────────────────────────────────────
Write-Host ""
Write-Host "Building FlowGuard-Setup-v$newVersion.exe..." -ForegroundColor Yellow

if (-not (Test-Path $ISCC)) {
    Write-Error "Inno Setup לא נמצא: $ISCC"
    exit 1
}

& $ISCC $IssFile | Where-Object { $_ -match 'Compiling|Linking|Successfully' }

$exe = Join-Path $Root "dist\FlowGuard-Setup-v$newVersion.exe"
if (Test-Path $exe) {
    $size = [math]::Round((Get-Item $exe).Length / 1MB, 1)
    Write-Host ""
    Write-Host "OK  dist\FlowGuard-Setup-v$newVersion.exe ($size MB)" -ForegroundColor Green
} else {
    Write-Error "Build נכשל -- EXE לא נמצא"
}
