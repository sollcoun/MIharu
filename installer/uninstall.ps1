param([switch]$KeepData)
$ErrorActionPreference = "Continue"
$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\Miharu"
$DataDir = Join-Path $env:LOCALAPPDATA "DiskDiagnostic"
$StartMenu = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Miharu"
schtasks /Delete /TN "DiskDiagnostic\BackgroundMonitor" /F 2>$null | Out-Null
schtasks /Delete /TN "Miharu\BackgroundMonitor" /F 2>$null | Out-Null
if (Test-Path $StartMenu) { Remove-Item $StartMenu -Recurse -Force -EA SilentlyContinue }
$desk = Join-Path ([Environment]::GetFolderPath("Desktop")) "Miharu.lnk"
if (Test-Path $desk) { Remove-Item $desk -Force -EA SilentlyContinue }
if (Test-Path $InstallDir) { Remove-Item $InstallDir -Recurse -Force -EA SilentlyContinue; Write-Host "Removed $InstallDir" }
if (-not $KeepData) {
    $a = Read-Host "Delete data $DataDir ? (y/N)"
    if ($a -eq "y") { Remove-Item $DataDir -Recurse -Force -EA SilentlyContinue }
}
Write-Host "Done."
