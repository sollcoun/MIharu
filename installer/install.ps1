# Optional: source-tree install (dev). Prefer Miharu-Setup-*.exe for end users.
# This script is kept for developers who run from Python sources.
param(
    [string]$BotToken = "",
    [switch]$DesktopShortcut,
    [switch]$WithMonitor
)

$ErrorActionPreference = "Stop"
Write-Host "For end users install release\Miharu-Setup-*.exe" -ForegroundColor Yellow
Write-Host "This script installs from SOURCE (Python required)." -ForegroundColor Yellow

$SourceRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\Miharu"
$DataDir = Join-Path $env:LOCALAPPDATA "DiskDiagnostic"
$VenvDir = Join-Path $InstallDir "venv"

Write-Host "Source : $SourceRoot"
Write-Host "Install: $InstallDir"

$py = $null
foreach ($c in @("python", "py -3", "py")) {
    try {
        $v = & cmd /c "$c --version 2>&1"
        if ($v -match "Python 3\.(\d+)" -and [int]$Matches[1] -ge 10) { $py = $c; break }
    } catch {}
}
if (-not $py) { throw "Python 3.10+ required" }

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
foreach ($rel in @("config.py","installation.py","run.py","run_monitor.py","requirements.txt","core","ui","notifications","scripts","assets")) {
    $src = Join-Path $SourceRoot $rel
    $dst = Join-Path $InstallDir $rel
    if (-not (Test-Path $src)) { continue }
    if (Test-Path $src -PathType Container) {
        if (Test-Path $dst) { Remove-Item $dst -Recurse -Force }
        Copy-Item $src $dst -Recurse -Force
    } else {
        Copy-Item $src $dst -Force
    }
}

if (-not (Test-Path $VenvDir)) {
    if ($py -like "py*") { & py -3 -m venv $VenvDir } else { & python -m venv $VenvDir }
}
$VenvPython = Join-Path $VenvDir "Scripts\python.exe"
$VenvPythonw = Join-Path $VenvDir "Scripts\pythonw.exe"
& $VenvPython -m pip install --upgrade pip -q
& $VenvPython -m pip install -r (Join-Path $InstallDir "requirements.txt") -q

$bat = @"
@echo off
cd /d `"$InstallDir`"
start `"`" `"$VenvPythonw`" `"$InstallDir\run.py`"
"@
Set-Content (Join-Path $InstallDir "Miharu.bat") $bat -Encoding ASCII

$startMenu = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Miharu"
New-Item -ItemType Directory -Path $startMenu -Force | Out-Null
$Wsh = New-Object -ComObject WScript.Shell
$sc = $Wsh.CreateShortcut((Join-Path $startMenu "Miharu.lnk"))
$sc.TargetPath = Join-Path $InstallDir "Miharu.bat"
$sc.WorkingDirectory = $InstallDir
$sc.Save()

if ($DesktopShortcut) {
    $sc2 = $Wsh.CreateShortcut((Join-Path ([Environment]::GetFolderPath("Desktop")) "Miharu.lnk"))
    $sc2.TargetPath = Join-Path $InstallDir "Miharu.bat"
    $sc2.WorkingDirectory = $InstallDir
    $sc2.Save()
}

@(
    $DataDir,
    (Join-Path $DataDir "Reports"),
    (Join-Path $DataDir "Config"),
    (Join-Path $DataDir "Logs")
) | ForEach-Object { New-Item -ItemType Directory -Path $_ -Force | Out-Null }

if ($BotToken) {
    $settingsPath = Join-Path $DataDir "Config\settings.json"
    $settings = @{ notification_mode = "direct"; telegram_bot_token = $BotToken; schema_version = 1 }
    if (Test-Path $settingsPath) {
        try { $settings = (Get-Content $settingsPath -Raw | ConvertFrom-Json | ConvertTo-Json | ConvertFrom-Json); $settings["telegram_bot_token"] = $BotToken } catch {}
    }
    $settings | ConvertTo-Json | Set-Content $settingsPath -Encoding UTF8
}

Write-Host "[OK] Dev install complete: $InstallDir" -ForegroundColor Green
