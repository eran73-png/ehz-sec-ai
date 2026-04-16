param([switch]$SkipScreenshots)
$ErrorActionPreference = "Stop"

$SlidesDir  = "C:\Claude-Repo\agents\EHZ-SEC-AI\marketing\slides-v2"
$FramesDir  = "C:\Claude-Repo\agents\EHZ-SEC-AI\marketing\out\frames-v2"
$OutDir     = "C:\Claude-Repo\agents\EHZ-SEC-AI\marketing\out"
$OutputFile = "$OutDir\FlowGuard-v2.mp4"
$FFmpeg     = "C:\Users\Eran\AppData\Local\Microsoft\WinGet\Packages\Gyan.FFmpeg_Microsoft.Winget.Source_8wekyb3d8bbwe\ffmpeg-8.0.1-full_build\bin\ffmpeg.exe"

$Durations = @{
  slide01=12; slide02=14; slide03=12; slide04=16; slide05=14
  slide06=14; slide07=12; slide08=12; slide09=11; slide10=14
}

New-Item -ItemType Directory -Force -Path $FramesDir | Out-Null
New-Item -ItemType Directory -Force -Path $OutDir    | Out-Null

Write-Host "FlowGuard Marketing Video Build v2" -ForegroundColor Cyan
Write-Host "====================================" -ForegroundColor Cyan

# STEP 1 - Screenshots
if (-not $SkipScreenshots) {
  Write-Host "Step 1: Taking screenshots..." -ForegroundColor Yellow

  $py = @"
import asyncio
from playwright.async_api import async_playwright

slides = ['slide01','slide02','slide03','slide04','slide05','slide06','slide07','slide08','slide09','slide10']

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        for name in slides:
            page = await browser.new_page(viewport={'width': 720, 'height': 1280})
            url = f'file:///C:/Claude-Repo/agents/EHZ-SEC-AI/marketing/slides-v2/{name}.html'
            await page.goto(url)
            await page.wait_for_timeout(800)
            out = f'C:/Claude-Repo/agents/EHZ-SEC-AI/marketing/out/frames-v2/{name}.png'
            await page.screenshot(path=out, full_page=False)
            await page.close()
            print(f'  OK {name}.png')
        await browser.close()

asyncio.run(main())
"@

  $tmp = "$env:TEMP\fg_ss_v2.py"
  [System.IO.File]::WriteAllText($tmp, $py, [System.Text.Encoding]::UTF8)
  & py $tmp
  if ($LASTEXITCODE -ne 0) { Write-Error "Screenshot failed"; exit 1 }
  Write-Host "  All 10 screenshots done." -ForegroundColor Green
} else {
  Write-Host "Skipping screenshots." -ForegroundColor Gray
}

# STEP 2 - Concat list
Write-Host "Step 2: Building FFmpeg concat list..." -ForegroundColor Yellow
$ConcatFile = "$env:TEMP\fg_concat_v2.txt"
$Order = @("slide01","slide02","slide03","slide04","slide05","slide06","slide07","slide08","slide09","slide10")
$Lines = @()
foreach ($s in $Order) {
  $png = "$FramesDir\$s.png"
  if (-not (Test-Path $png)) { Write-Error "Missing: $png"; exit 1 }
  $Lines += "file '$png'"
  $Lines += "duration $($Durations[$s])"
}
$Lines += "file '$FramesDir\slide10.png'"
[System.IO.File]::WriteAllLines($ConcatFile, $Lines, [System.Text.Encoding]::ASCII)

$total = ($Durations.Values | Measure-Object -Sum).Sum
Write-Host "  Total: $total seconds" -ForegroundColor Gray

# STEP 3 - Render
Write-Host "Step 3: Rendering video..." -ForegroundColor Yellow
if (Test-Path $OutputFile) { Remove-Item $OutputFile -Force }

& $FFmpeg -f concat -safe 0 -i $ConcatFile `
  -vf "scale=720:1280:force_original_aspect_ratio=decrease,pad=720:1280:(ow-iw)/2:(oh-ih)/2:color=#060d1a,fps=30" `
  -c:v libx264 -preset slow -crf 18 -pix_fmt yuv420p -movflags +faststart `
  -y $OutputFile 2>&1

if ($LASTEXITCODE -ne 0) { Write-Error "FFmpeg failed"; exit 1 }

$mb = [math]::Round((Get-Item $OutputFile).Length / 1MB, 1)
$min = [math]::Round($total / 60, 1)
Write-Host "Done! $mb MB, $total sec ($min min)" -ForegroundColor Green
Write-Host "Output: $OutputFile" -ForegroundColor Cyan
