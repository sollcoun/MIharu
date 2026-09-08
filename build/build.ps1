[CmdletBinding()]
param(
    [switch]$Clean,
    [switch]$SkipInstaller
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$projectRoot = Split-Path -Parent $scriptDir

Write-Host ""
Write-Host "  Miharu - build" -ForegroundColor Cyan
Write-Host "  Root: $projectRoot"
Write-Host ""

function Test-VenvOk([string]$VenvDir) {
    $pyExe = Join-Path $VenvDir "Scripts\python.exe"
    $cfg = Join-Path $VenvDir "pyvenv.cfg"
    return (Test-Path $pyExe) -and (Test-Path $cfg)
}

function Get-SystemPython {
    $candidates = @()
    try {
        $c = Get-Command python -ErrorAction SilentlyContinue
        if ($c) { $candidates += $c.Source }
    } catch {}
    try {
        $c = Get-Command py -ErrorAction SilentlyContinue
        if ($c) { $candidates += $c.Source }
    } catch {}
    $candidates += @(
        "$env:LocalAppData\Programs\Python\Python314\python.exe",
        "$env:LocalAppData\Programs\Python\Python313\python.exe",
        "$env:LocalAppData\Programs\Python\Python312\python.exe",
        "$env:LocalAppData\Python\pythoncore-3.14-64\python.exe",
        "$env:LocalAppData\Python\pythoncore-3.13-64\python.exe",
        "C:\Python314\python.exe",
        "C:\Python313\python.exe"
    )
    foreach ($p in $candidates) {
        if ($p -and (Test-Path $p)) {
            # skip broken venv shims
            if ($p -match '\\build\\\.venv') { continue }
            return $p
        }
    }
    # last resort: python on PATH
    return "python"
}

if ($Clean) {
    Write-Host "[*] Cleaning dist / pyinstaller workdir"
    foreach ($p in @(
        (Join-Path $projectRoot "dist"),
        (Join-Path $projectRoot "build\pyinstaller")
    )) {
        if (Test-Path $p) {
            try { Remove-Item -Recurse -Force $p -ErrorAction Stop }
            catch { Write-Host "[WARNING] $p : $($_.Exception.Message)" -ForegroundColor Yellow }
        }
    }
    Write-Host "[OK] Clean" -ForegroundColor Green
}

$venvPath = Join-Path $projectRoot "build\.venv"
$sysPy = Get-SystemPython
Write-Host "[*] System Python: $sysPy"

if (-not (Test-VenvOk $venvPath)) {
    Write-Host "[*] Build venv missing or broken - recreating"
    if (Test-Path $venvPath) {
        $trashName = ".venv.trash-" + [guid]::NewGuid().ToString("N").Substring(0, 8)
        try {
            Rename-Item -Path $venvPath -NewName $trashName -ErrorAction Stop
            Write-Host "[*] Renamed broken venv -> build\$trashName"
        } catch {
            try {
                Remove-Item -Recurse -Force $venvPath -ErrorAction Stop
            } catch {
                Write-Host "[WARNING] Cannot remove broken venv (locked). Using build\.venv-new" -ForegroundColor Yellow
                $venvPath = Join-Path $projectRoot "build\.venv-new"
            }
        }
    }
    New-Item -ItemType Directory -Path (Split-Path $venvPath -Parent) -Force | Out-Null
    & $sysPy -m venv $venvPath
    if (-not (Test-VenvOk $venvPath)) {
        throw "Failed to create working venv at $venvPath"
    }
    Write-Host "[OK] venv created" -ForegroundColor Green
} else {
    Write-Host "[*] Using existing build venv" -ForegroundColor Cyan
}

$py = Join-Path $venvPath "Scripts\python.exe"

Write-Host "[*] Dependencies"
& $py -m pip install --upgrade pip -q
if ($LASTEXITCODE -ne 0) { throw "pip upgrade failed" }
& $py -m pip install "pyinstaller>=6.0" -q
if ($LASTEXITCODE -ne 0) { throw "pyinstaller install failed" }
$req = Join-Path $projectRoot "requirements.txt"
if (Test-Path $req) {
    & $py -m pip install -r $req -q
    if ($LASTEXITCODE -ne 0) { throw "requirements install failed" }
}
Write-Host "[OK] Dependencies" -ForegroundColor Green

$secretsDir = Join-Path $projectRoot "secrets"
$defaultsPath = Join-Path $secretsDir "product_defaults.json"
if (Test-Path $defaultsPath) {
    Write-Host "[*] Using existing secrets/product_defaults.json" -ForegroundColor Cyan
} else {
    $tok = $env:TELEGRAM_BOT_TOKEN
    if (-not $tok) { $tok = $env:MIHARU_TELEGRAM_BOT_TOKEN }
    if ($tok) {
        New-Item -ItemType Directory -Path $secretsDir -Force | Out-Null
        $obj = @{ telegram_bot_token = $tok; notification_mode = "direct" } | ConvertTo-Json
        Set-Content -Path $defaultsPath -Value $obj -Encoding UTF8
        Write-Host "[*] Wrote secrets/product_defaults.json from env" -ForegroundColor Cyan
    } else {
        Write-Host "[!] No product_defaults.json - installs will need token manually" -ForegroundColor Yellow
    }
}

Write-Host "[*] Syntax check"
& $py -m py_compile (Join-Path $projectRoot "run.py")
if ($LASTEXITCODE -ne 0) { throw "syntax check failed" }
Write-Host "[OK] Syntax" -ForegroundColor Green

$spec = Join-Path $scriptDir "Miharu.spec"
if (-not (Test-Path $spec)) {
    $spec = Join-Path $scriptDir "DiskDiagnostic.spec"
}
if (-not (Test-Path $spec)) {
    throw "Spec not found: Miharu.spec"
}

$distPath = Join-Path $projectRoot "dist"
$workPath = Join-Path $projectRoot "build\pyinstaller"
Write-Host "[*] PyInstaller: $([IO.Path]::GetFileName($spec))"
& $py -m PyInstaller $spec --noconfirm --distpath $distPath --workpath $workPath
if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller failed with exit $LASTEXITCODE"
}

$exe = Join-Path $projectRoot "dist\Miharu\Miharu.exe"
if (-not (Test-Path $exe)) {
    Write-Host "[ERROR] Expected EXE not found. Dist contents:" -ForegroundColor Red
    if (Test-Path $distPath) {
        Get-ChildItem $distPath -Recurse -Filter "*.exe" | ForEach-Object { Write-Host "  $($_.FullName)" }
    }
    throw "Build failed: $exe not found"
}
Write-Host "[OK] $exe" -ForegroundColor Green

if ($SkipInstaller) {
    Write-Host "[*] SkipInstaller - done"
    exit 0
}

$possibleInno = @(
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
    "D:\Inno Setup 6\ISCC.exe",
    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    "C:\Program Files\Inno Setup 6\ISCC.exe"
)
$reg = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Inno Setup 6_is1"
if (Test-Path $reg) {
    $loc = (Get-ItemProperty $reg -ErrorAction SilentlyContinue).InstallLocation
    if ($loc) { $possibleInno += (Join-Path $loc "ISCC.exe") }
}
$iscc = $possibleInno | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) {
    Write-Host "[WARNING] Inno Setup not found - EXE ready at dist\Miharu\Miharu.exe" -ForegroundColor Yellow
    exit 0
}

$iss = Join-Path $scriptDir "installer.iss"
Write-Host "[*] Inno Setup: $iscc"
& $iscc $iss
if ($LASTEXITCODE -ne 0) {
    throw "Inno Setup failed with exit $LASTEXITCODE"
}
$setup = Join-Path $projectRoot "release\Miharu-Setup-1.1.0.exe"
if (Test-Path $setup) {
    Write-Host "[OK] $setup" -ForegroundColor Green
} else {
    Write-Host "[OK] Installer finished (check release folder)" -ForegroundColor Green
}