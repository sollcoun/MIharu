<#
.SYNOPSIS
    Диагностика диска + базовая проверка на признаки малвари + история изменений.

.DESCRIPTION
    - Считает размеры дисков C:/D:, топ-папок, AppData, Temp
    - Ищет крупные и старые файлы
    - Ищет подозрительные исполняемые файлы (эвристика: расположение, имя, двойное расширение)
    - Проверяет автозагрузку: реестр Run/RunOnce, папки автозагрузки, запланированные задачи,
      неподписанные процессы
    - Сохраняет структурированный снимок (JSON) каждого запуска в историю и сравнивает
      с предыдущим запуском: новые автозагрузки, новые подозрительные файлы, рост папок
    - Сохраняет итоговый report.json (диагностика + история диска + рекомендации)
    - Ничего не удаляет и не изменяет, только читает и формирует отчёт

.NOTES
    GUI запускает этот скрипт автоматически.
#>

param(
    [ValidateSet("Quick", "Full")]
    [string]$Mode = "Full",
    [string[]]$Drives = @()
)

# Handle comma-separated drives (PowerShell passes "C:,D:,Z:" as single string)
if ($Drives.Count -eq 1 -and $Drives[0] -match ',') {
    $Drives = @($Drives[0].Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

$ProgressPreference = "SilentlyContinue"
try {
    [Console]::InputEncoding = [System.Text.Encoding]::UTF8
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
    $PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
    $PSDefaultParameterValues['Set-Content:Encoding'] = 'utf8'
    $PSDefaultParameterValues['Add-Content:Encoding'] = 'utf8'
} catch {}

$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

if ($Host.UI.RawUI) {
    $Host.UI.RawUI.WindowTitle = "Диагностика диска"
}

# UTF-8 для консоли (chcp может отсутствовать в PATH)
try {
    $chcp = Get-Command chcp.com -ErrorAction SilentlyContinue
    if ($chcp) { & $chcp.Source 65001 | Out-Null }
} catch {}

# ===================== НАСТРОЙКИ =====================
$AppDataDir = if ($env:DISK_DIAGNOSTIC_DATA_DIR) {
    $env:DISK_DIAGNOSTIC_DATA_DIR
} else {
    "$env:LOCALAPPDATA\DiskDiagnostic"
}
$ReportDir    = Join-Path $AppDataDir "Reports"
$HistoryDir   = Join-Path $AppDataDir "History"
$Timestamp    = Get-Date -Format 'yyyy-MM-dd_HH-mm'
$ReportFile   = "$ReportDir\report.json"
$SnapshotFile = "$HistoryDir\snapshot_$Timestamp.json"

$OldDays         = 365
$MinOldFileMB    = 50
$LargeFileMB     = 300
$SuspiciousMinKB = 50
$FolderDeltaGB   = 0.5
$MaxSuspicious   = 60
$MaxSignatureChecks = 40

Write-Host "Scan mode: $Mode"
$IsQuick = ($Mode -eq 'Quick')

# All mounted drives (any drive type: fixed, network, removable, etc.)
$allMountedDisks = @(Get-CimInstance Win32_LogicalDisk -ErrorAction SilentlyContinue |
    Where-Object { $_.DeviceID -match '^[A-Z]:$' } |
    Sort-Object DeviceID)
$allLetters = @($allMountedDisks | ForEach-Object { $_.DeviceID.ToUpper() })

# Fixed disks for default selection
$availableFixedDisks = @($allMountedDisks | Where-Object { $_.DriveType -eq 3 })
$availableLetters = @($availableFixedDisks | ForEach-Object { $_.DeviceID.ToUpper() })

# Selected drives: use all mounted drives for validation (not just fixed)
$selectedLetters = @($Drives | ForEach-Object {
    $v = ([string]$_).Trim().ToUpper().TrimEnd('\\')
    if ($v -and $v.Length -eq 1) { $v = "${v}:" }
    $v
} | Where-Object { $_ -and ($allLetters -contains $_) } | Select-Object -Unique)

# Drop network/removable unless they were explicitly requested via -Drives
$networkLetters = @($allMountedDisks | Where-Object { $_.DriveType -eq 4 } | ForEach-Object { $_.DeviceID.ToUpper() })
if ($Drives.Count -eq 0) {
    # default: fixed only, never network
    if ($selectedLetters.Count -eq 0) {
        $selectedLetters = $availableLetters
    } else {
        $selectedLetters = @($selectedLetters | Where-Object { $availableLetters -contains $_ })
    }
} else {
    # explicit list — still warn on network
    foreach ($nl in $networkLetters) {
        if ($selectedLetters -contains $nl) {
            Write-Host "WARNING: network drive $nl included — scan may be very slow" -ForegroundColor Yellow
        }
    }
}
if ($selectedLetters.Count -eq 0) {
    $selectedLetters = $availableLetters
}
if ($selectedLetters.Count -eq 0) {
    $selectedLetters = @("C:")
}
$selectedRoots = @($selectedLetters | ForEach-Object { "$_\" })
Write-Host ("Selected drives: " + ($selectedLetters -join ", "))

$SkipDirNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$skipList = if ($IsQuick) {
    @(
        'node_modules', '.git', '.svn', '.hg', 'Windows', 'WinSxS', 'System Volume Information',
        '$Recycle.Bin', 'Recycler', 'PerfLogs', 'Cache', 'CachedData', 'Code Cache', 'GPUCache',
        'ShaderCache', 'INetCache', 'Temporary Internet Files', 'Packages', 'WinGet',
        'Package Cache', 'Installer', 'WindowsApps', 'Microsoft Edge', 'CrashDumps'
    )
} else {
    @(
        'System Volume Information', '$Recycle.Bin', 'Recycler', 'WinSxS', 'WindowsApps'
    )
}
$skipList | ForEach-Object { [void]$SkipDirNames.Add($_) }

if ($IsQuick) {
    $PathsToScanForFiles = New-Object System.Collections.Generic.List[string]
    if ($selectedLetters -contains 'C:') {
        foreach ($path in @($env:USERPROFILE, "$env:LOCALAPPDATA\Temp", "$env:TEMP", "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "C:\Users\Public", "C:\ProgramData")) {
            if ($path -and (Test-Path -LiteralPath $path)) { [void]$PathsToScanForFiles.Add($path) }
        }
    }
    foreach ($root in $selectedRoots) {
        if ($root -ne 'C:\' -and (Test-Path -LiteralPath $root)) { [void]$PathsToScanForFiles.Add($root) }
    }
    $PathsToScanForFiles = @($PathsToScanForFiles | Select-Object -Unique)
} else {
    $PathsToScanForFiles = New-Object System.Collections.Generic.List[string]
    if ($selectedLetters -contains 'C:') {
        foreach ($path in @("C:\Users", "C:\ProgramData")) {
            if (Test-Path -LiteralPath $path) { [void]$PathsToScanForFiles.Add($path) }
        }
    }
    foreach ($root in $selectedRoots) {
        if ($root -ne 'C:\' -and (Test-Path -LiteralPath $root)) { [void]$PathsToScanForFiles.Add($root) }
    }
    $PathsToScanForFiles = @($PathsToScanForFiles | Select-Object -Unique)
}

Write-Host ("Scan roots: " + ($PathsToScanForFiles -join "; "))

$SuspiciousExtRegex  = '\.(exe|scr|bat|cmd|vbs|js|jse|wsf)$'
$SuspiciousNameRegex = '(invoice|payment|resume|cv|photo|update|setup|crack|keygen|activator|svchost|explorer|winlogon|csrss|lsass)'
$DoubleExtRegex      = '\.(pdf|doc|docx|xls|xlsx|jpg|jpeg|png|txt|zip|rar)\s*\.(exe|scr|bat|cmd|vbs|js|jse|wsf)$'

# ===================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ =====================

function Format-GB { param([Nullable[long]]$Bytes); if ($null -eq $Bytes) { return 0 }; return [math]::Round($Bytes / 1GB, 2) }
function Format-MB { param([Nullable[long]]$Bytes); if ($null -eq $Bytes) { return 0 }; return [math]::Round($Bytes / 1MB, 2) }

function Get-FolderSizeGB {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return 0 }
    $sum = 0L
    try {
        $enum = [System.IO.Directory]::EnumerateFiles($Path, '*', [System.IO.SearchOption]::AllDirectories)
        foreach ($f in $enum) {
            try { $sum += (New-Object System.IO.FileInfo $f).Length } catch {}
        }
    } catch {}
    return [double](Format-GB $sum)
}

function Get-FolderSizeGB-Fast {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return 0 }
    $tmp = [System.IO.Path]::GetTempFileName()
    try {
        $null = & robocopy $Path $Path /L /S /NJH /NJS /NDL /NC /BYTES /FLT /R:0 /W:0 2>$null | Out-File -FilePath $tmp -Encoding ascii
        $bytes = 0L
        Get-Content $tmp -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_ -match 'Bytes\s*:\s*([\d\s]+)') {
                $n = ($Matches[1] -replace '\s','')
                if ($n) { [void][long]::TryParse($n, [ref]$bytes) }
            }
        }
        if ($bytes -le 0) {
            $lines = Get-Content $tmp -ErrorAction SilentlyContinue
            foreach ($line in $lines) {
                if ($line -match '^\s*Bytes\s+([\d,]+)') {
                    $n = ($Matches[1] -replace ',','')
                    [void][long]::TryParse($n, [ref]$bytes)
                }
            }
        }
        return [double](Format-GB $bytes)
    } catch {
        return (Get-FolderSizeGB $Path)
    } finally {
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    }
}

function Get-DirEntries {
    param([string]$BasePath, [int]$MaxDepthFiles = 0)
    $result = @()
    if ([string]::IsNullOrWhiteSpace($BasePath)) { return $result }
    if (-not (Test-Path -LiteralPath $BasePath)) { return $result }
    $dirs = Get-ChildItem -LiteralPath $BasePath -Directory -Force -ErrorAction SilentlyContinue
    foreach ($d in $dirs) {
        if ($SkipDirNames.Contains($d.Name)) { continue }
        $size = 0.0
        try {
            $sum = 0L
            $files = [System.IO.Directory]::EnumerateFiles($d.FullName, '*', [System.IO.SearchOption]::TopDirectoryOnly)
            foreach ($f in $files) {
                try { $sum += (New-Object System.IO.FileInfo $f).Length } catch {}
            }
            $sub = [System.IO.Directory]::EnumerateDirectories($d.FullName)
            foreach ($sd in $sub) {
                $leaf = [System.IO.Path]::GetFileName($sd)
                if ($SkipDirNames.Contains($leaf)) { continue }
                try {
                    foreach ($f in [System.IO.Directory]::EnumerateFiles($sd, '*', [System.IO.SearchOption]::AllDirectories)) {
                        try { $sum += (New-Object System.IO.FileInfo $f).Length } catch {}
                    }
                } catch {}
            }
            $size = [double](Format-GB $sum)
        } catch {}
        $result += [PSCustomObject]@{ Path = $d.FullName; SizeGB = $size }
    }
    return $result
}

function Get-NewItems {
    # Элементы $Current, которых не было в $Previous (сравнение по составному ключу $KeyProps).
    # На первом запуске (нет предыдущего снимка) возвращает пустой список - сравнивать не с чем.
    param($Current, $Previous, [string[]]$KeyProps)
    if (-not $Previous) { return @() }
    $prevKeys = @($Previous | ForEach-Object {
        $item = $_
        ($KeyProps | ForEach-Object { $item.$_ }) -join '|'
    })
    return @($Current | Where-Object {
        $item = $_
        $key = ($KeyProps | ForEach-Object { $item.$_ }) -join '|'
        -not ($prevKeys -contains $key)
    })
}

function Get-FolderDeltas {
    # Сравнивает размеры папок между текущим и предыдущим снимком, возвращает
    # только те, где изменение превышает $FolderDeltaGB
    param($Current, $Previous)
    if (-not $Previous) { return @() }
    $prevMap = @{}
    foreach ($p in $Previous) { $prevMap[$p.Path] = $p.SizeGB }
    $deltas = foreach ($c in $Current) {
        if ($prevMap.ContainsKey($c.Path)) {
            $delta = [math]::Round($c.SizeGB - $prevMap[$c.Path], 2)
            if ([math]::Abs($delta) -ge $FolderDeltaGB) {
                [PSCustomObject]@{ Path = $c.Path; OldGB = $prevMap[$c.Path]; NewGB = $c.SizeGB; DeltaGB = $delta }
            }
        }
    }
    return @($deltas | Sort-Object { [math]::Abs($_.DeltaGB) } -Descending)
}

function Get-SignatureInfo {
    # Возвращает статус подписи и имя подписанта для файла
    param([string]$FilePath)
    try {
        $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop
        $signer = ""
        if ($sig.SignerCertificate) { $signer = $sig.SignerCertificate.Subject -replace '^CN=([^,]+).*$', '$1' }
        return @{ Status = "$($sig.Status)"; Signer = $signer }
    } catch {
        return @{ Status = "Error"; Signer = "" }
    }
}

function Get-DuplicateFiles {
    # Ищет дубликаты файлов по имени + размеру (быстрый метод, без хэширования).
    # Возвращает группы файлов, у которых совпадают имя и размер.
    param($Files)
    $groups = @{}
    foreach ($f in $Files) {
        $key = "$($f.Name)|$($f.Length)"
        if (-not $groups.ContainsKey($key)) { $groups[$key] = @() }
        $groups[$key] += $f
    }
    $duplicates = @()
    foreach ($key in $groups.Keys) {
        $items = $groups[$key]
        if ($items.Count -gt 1) {
            $duplicates += [PSCustomObject]@{
                Name      = $items[0].Name
                SizeMB    = (Format-MB $items[0].Length)
                Count     = $items.Count
                Paths     = @($items | ForEach-Object { $_.FullName })
            }
        }
    }
    return @($duplicates | Sort-Object Count -Descending | Select-Object -First 30)
}

New-Item -ItemType Directory -Path $ReportDir  -Force | Out-Null
New-Item -ItemType Directory -Path $HistoryDir -Force | Out-Null

# ===================== ЗАГРУЗКА ПРЕДЫДУЩЕГО СНИМКА =====================
$PreviousSnapshot = $null
$prevFile = Get-ChildItem $HistoryDir -Filter "snapshot_*.json" -ErrorAction SilentlyContinue |
    Sort-Object Name -Descending | Select-Object -First 1
if ($prevFile) {
    try { $PreviousSnapshot = Get-Content $prevFile.FullName -Raw | ConvertFrom-Json } catch { $PreviousSnapshot = $null }
}
if ($PreviousSnapshot) {
    Write-Host "Found previous snapshot: $($prevFile.Name) - will compute diff."
} else {
    Write-Host "No previous snapshot found - this is the baseline run."
}

# ===================== СТАРТ СЕКУНДОМЕРА =====================
$sw = [System.Diagnostics.Stopwatch]::StartNew()

# ===================== СБОР ДАННЫХ =====================

# --- Диски ---
$disks = [ordered]@{}
foreach ($disk in $availableFixedDisks) {
    if ($selectedLetters -notcontains $disk.DeviceID.ToUpper()) { continue }
    $letter = $disk.DeviceID.Substring(0, 1).ToUpper()
    $total = [double](Format-GB $disk.Size)
    $free  = [double](Format-GB $disk.FreeSpace)
    $used  = [double](Format-GB ($disk.Size - $disk.FreeSpace))
    $pct   = if ($total -gt 0) { [math]::Round(($used / $total) * 100, 1) } else { 0 }
    $disks[$letter] = [ordered]@{
        TotalGB = $total
        FreeGB  = $free
        UsedGB  = $used
        UsedPct = $pct
        Label   = $disk.VolumeName
    }
}

# --- Единый проход по файлам (.NET Enumerate + skip dirs) ---
Write-Host "Scanning file system (single pass)..."
$allFiles = New-Object System.Collections.Generic.List[System.IO.FileInfo]
$fileCount = 0
$largeFilesList = New-Object System.Collections.Generic.List[System.IO.FileInfo]
$oldFilesList = New-Object System.Collections.Generic.List[System.IO.FileInfo]
$suspiciousHits = New-Object System.Collections.Generic.List[System.IO.FileInfo]
$doubleExtensions = New-Object System.Collections.Generic.List[string]
$dupMap = @{}
$cutoff = (Get-Date).AddDays(-$OldDays)
$largeThreshold = [long]($LargeFileMB * 1MB)
$oldThreshold = [long]($MinOldFileMB * 1MB)
$susThreshold = [long]($SuspiciousMinKB * 1KB)
$userPrefix = $env:USERPROFILE

function Test-SkipDir([string]$name) {
    return $SkipDirNames.Contains($name)
}

function Get-FilesSafe([string]$root) {
    if (-not $root -or -not (Test-Path -LiteralPath $root)) {
        Write-Host "  skip missing: $root"
        return
    }
    $stack = New-Object System.Collections.Generic.Stack[string]
    $stack.Push($root)
    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        try {
            foreach ($f in [System.IO.Directory]::EnumerateFiles($dir)) {
                try {
                    $fi = New-Object System.IO.FileInfo $f
                    [void]$script:allFiles.Add($fi)
                    $script:fileCount++

                    if ($fi.Length -gt $script:largeThreshold) { [void]$script:largeFilesList.Add($fi) }
                    if ($fi.Length -gt $script:oldThreshold -and $fi.LastWriteTime -lt $script:cutoff -and $fi.FullName.StartsWith($script:userPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                        [void]$script:oldFilesList.Add($fi)
                    }
                    $ext = $fi.Extension
                    if ($fi.Length -gt $script:susThreshold -and $ext -match $script:SuspiciousExtRegex) {
                        [void]$script:suspiciousHits.Add($fi)
                    }
                    if ($fi.Name -match $script:DoubleExtRegex) {
                        [void]$script:doubleExtensions.Add($fi.FullName)
                    }
                    $dupKey = "$($fi.Name)|$($fi.Length)"
                    if (-not $script:dupMap.ContainsKey($dupKey)) {
                        $script:dupMap[$dupKey] = New-Object System.Collections.Generic.List[string]
                    }
                    [void]$script:dupMap[$dupKey].Add($fi.FullName)
                } catch {}
            }
        } catch {}
        try {
            foreach ($sd in [System.IO.Directory]::EnumerateDirectories($dir)) {
                $leaf = [System.IO.Path]::GetFileName($sd)
                if (Test-SkipDir $leaf) { continue }
                $stack.Push($sd)
            }
        } catch {}
    }
}

if (-not $PathsToScanForFiles -or $PathsToScanForFiles.Count -eq 0) {
    Write-Host "WARNING: no scan roots — fallback to user profile"
    $PathsToScanForFiles = @($env:USERPROFILE)
}

foreach ($root in $PathsToScanForFiles) {
    Write-Host "  scan: $root"
    Get-FilesSafe $root
}
$fileCount = [int]$script:fileCount
Write-Host "Files indexed: $fileCount"

# --- Корневые папки (без повторного полного скана всего диска) ---
$rootC = @()
$rootD = @()
$rootFolders = [ordered]@{}
$userFolders = @()
$appDataTop = [ordered]@{}
$duplicateFiles = @()
$folderDeltas = @()

if (-not $IsQuick) {
    Write-Host "Measuring top-level folders..."
    foreach ($letter in $selectedLetters) {
        $root = "$letter\"
        if (-not (Test-Path -LiteralPath $root)) { continue }
        $entries = @(Get-DirEntries $root)
        $rootFolders[$letter.Substring(0,1)] = $entries
        if ($letter -eq 'C:') { $rootC = $entries }
        if ($letter -eq 'D:') { $rootD = $entries }
        $previousKey = if ($letter -eq 'C:') { 'RootFoldersC' } elseif ($letter -eq 'D:') { 'RootFoldersD' } else { $null }
        if ($previousKey) { $folderDeltas += Get-FolderDeltas $entries $PreviousSnapshot.$previousKey }
    }
    if ($env:USERPROFILE) { $userFolders = Get-DirEntries $env:USERPROFILE }
    foreach ($base in @($env:LOCALAPPDATA, $env:APPDATA)) {
        if ([string]::IsNullOrWhiteSpace($base)) { continue }
        if (-not (Test-Path -LiteralPath $base)) { continue }
        $appDataTop[$base] = @(Get-DirEntries $base | Sort-Object SizeGB -Descending | Select-Object -First 15)
    }
    Write-Host "Checking duplicates..."
    foreach ($key in $dupMap.Keys) {
        $paths = $dupMap[$key]
        if ($paths.Count -gt 1) {
            $parts = $key.Split('|')
            $duplicateFiles += [PSCustomObject]@{
                Name   = $parts[0]
                SizeMB = (Format-MB ([long]$parts[1]))
                Count  = $paths.Count
                Paths  = @($paths | Select-Object -First 8)
            }
        }
    }
    $duplicateFiles = @($duplicateFiles | Sort-Object Count -Descending | Select-Object -First 30)
} else {
    Write-Host "Quick mode: skip folder sizes and duplicates"
}

$largeFiles = @($largeFilesList | Sort-Object Length -Descending | Select-Object -First $(if ($IsQuick) { 15 } else { 40 }))
$oldFiles = @($oldFilesList | Sort-Object Length -Descending | Select-Object -First $(if ($IsQuick) { 10 } else { 30 }))

$tempSizes = [ordered]@{}
@($env:TEMP, $(if ($env:WINDIR) { Join-Path $env:WINDIR "Temp" } else { $null })) | Where-Object { $_ } | ForEach-Object {
    if (Test-Path -LiteralPath $_) {
        $sum = 0L
        try {
            foreach ($f in [System.IO.Directory]::EnumerateFiles($_, '*', [System.IO.SearchOption]::TopDirectoryOnly)) {
                try { $sum += (New-Object System.IO.FileInfo $f).Length } catch {}
            }
        } catch {}
        $tempSizes[$_] = [double](Format-GB $sum)
    }
}

$defender = $null
try {
    $status = Get-MpComputerStatus -ErrorAction Stop
    $defender = [ordered]@{
        Enabled      = $status.AntivirusEnabled
        RealTime     = $status.RealTimeProtectionEnabled
        SignatureAge = $status.AntivirusSignatureAge
        QuickScanAge = $status.QuickScanAge
        FullScanAge  = $status.FullScanAge
    }
} catch {
    $defender = $null
}

if ($IsQuick) {
    $MaxSignatureChecks = 15
    $MaxSuspicious = 30
} else {
    $MaxSignatureChecks = 80
    $MaxSuspicious = 120
}
Write-Host "Checking signatures (max $MaxSignatureChecks)..."
$suspiciousHits = @($suspiciousHits | Select-Object -First $MaxSuspicious)
$suspiciousFiles = @()
$sigCount = 0
foreach ($f in $suspiciousHits) {
    $sigInfo = @{ Status = "NotChecked"; Signer = "" }
    if ($sigCount -lt $MaxSignatureChecks -and $f.Extension -match '\.(exe|scr|dll|msi|sys)$') {
        $sigInfo = Get-SignatureInfo $f.FullName
        $sigCount++
    } elseif ($f.Extension -match '\.(exe|scr|dll|msi|sys)$') {
        $sigInfo = @{ Status = "NotSigned"; Signer = "" }
    }
    $nameRisk = if ($f.Name -match $SuspiciousNameRegex) { "HIGH" } else { "LOW" }
    $sha = $null
    if ($f.Extension -match '\.(exe|scr|dll|msi|sys)$' -and $f.Length -gt 1KB -and $f.Length -lt 50MB) {
        try {
            $sha = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
        } catch { $sha = $null }
    }
    $suspiciousFiles += [PSCustomObject]@{
        Name          = $f.Name
        Path          = $f.FullName
        SizeMB        = (Format-MB $f.Length)
        Modified      = $f.LastWriteTime.ToString('yyyy-MM-dd')
        Signature     = $sigInfo.Status
        Signer        = $sigInfo.Signer
        HeuristicRisk = $nameRisk
        SHA256        = $sha
    }
}
$doubleExtensions = @($doubleExtensions)

# --- Автозагрузка (реестр Run/RunOnce) ---
$runKeys = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
)
$autorun = @()
foreach ($key in $runKeys) {
    if (-not (Test-Path $key)) { continue }
    $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
    if (-not $props) { continue }
    $props.PSObject.Properties |
        Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Provider)$' } |
        ForEach-Object {
            $autorun += [PSCustomObject]@{ Key = $key; Name = $_.Name; Value = "$($_.Value)" }
        }
}

# --- Папки автозагрузки ---
$startupFolders = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)
$startupItems = @()
foreach ($folder in $startupFolders) {
    if (-not (Test-Path $folder)) { continue }
    $startupItems += Get-ChildItem $folder -File -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ne 'desktop.ini' -and $_.Extension -match '\.(lnk|exe|bat|cmd|vbs|ps1|js|msc|scr)$' } |
        ForEach-Object { $_.FullName }
}

# --- Запланированные задачи ---
$scheduledTasks = @()
try {
    $scheduledTasks = @(Get-ScheduledTask -ErrorAction Stop |
        Where-Object { $_.State -ne 'Disabled' -and $_.TaskPath -notmatch '\\Microsoft\\' } |
        ForEach-Object {
            [PSCustomObject]@{ TaskPath = $_.TaskPath; TaskName = $_.TaskName; State = "$($_.State)" }
        })
} catch {
    $scheduledTasks = @()
}

# --- Процессы (context + parent) ---
$processes = @()
$unsignedProcesses = @()
try {
    $cimProcs = @(Get-CimInstance Win32_Process -ErrorAction Stop)
    $procById = @{}
    foreach ($cp in $cimProcs) { $procById[[int]$cp.ProcessId] = $cp }

    $seenPaths = @{}
    $sigCache = @{}
    $maxProcSig = if ($IsQuick) { 25 } else { 60 }
    $sigDone = 0

    foreach ($cp in $cimProcs) {
        $exePath = $cp.ExecutablePath
        if (-not $exePath) { continue }

        $ppid = [int]$cp.ParentProcessId
        $parent = $null
        if ($procById.ContainsKey($ppid)) { $parent = $procById[$ppid] }
        $parentName = if ($parent) { $parent.Name } else { "" }
        $parentPath = if ($parent) { $parent.ExecutablePath } else { "" }

        $sigStatus = "NotChecked"
        $signer = ""
        if (-not $seenPaths.ContainsKey($exePath.ToLowerInvariant())) {
            $seenPaths[$exePath.ToLowerInvariant()] = $true
            if ($sigDone -lt $maxProcSig) {
                if ($sigCache.ContainsKey($exePath)) {
                    $si = $sigCache[$exePath]
                } else {
                    $si = Get-SignatureInfo $exePath
                    $sigCache[$exePath] = $si
                    $sigDone++
                }
                $sigStatus = $si.Status
                $signer = $si.Signer
            }
            if ($sigStatus -ne "Valid" -and $sigStatus -ne "NotChecked") {
                $unsignedProcesses += [PSCustomObject]@{
                    Path   = $exePath
                    Status = $sigStatus
                    Signer = $signer
                }
            }
        } elseif ($sigCache.ContainsKey($exePath)) {
            $sigStatus = $sigCache[$exePath].Status
            $signer = $sigCache[$exePath].Signer
        }

        $processes += [PSCustomObject]@{
            Pid            = [int]$cp.ProcessId
            Name           = $cp.Name
            Path           = $exePath
            ParentPid      = $ppid
            ParentName     = $parentName
            ParentPath     = $parentPath
            CommandLine    = if ($cp.CommandLine) { $cp.CommandLine.Substring(0, [Math]::Min(300, $cp.CommandLine.Length)) } else { "" }
            Signature      = $sigStatus
            Signer         = $signer
        }
    }
} catch {
    $processes = @()
    $unsignedProcesses = @()
}

# --- Службы Windows ---
$services = @()
try {
    $svcList = @(Get-CimInstance Win32_Service -ErrorAction Stop)
    $maxSvcSig = if ($IsQuick) { 20 } else { 50 }
    $svcSigDone = 0
    foreach ($svc in $svcList) {
        $img = "$($svc.PathName)"
        $binPath = $img
        if ($img -match '"([^"]+)"') { $binPath = $Matches[1] }
        elseif ($img -match '^(.*?\.exe)') { $binPath = $Matches[1] }

        $sigStatus = "NotChecked"
        $signer = ""
        if ($binPath -and (Test-Path -LiteralPath $binPath) -and $svcSigDone -lt $maxSvcSig) {
            $si = Get-SignatureInfo $binPath
            $sigStatus = $si.Status
            $signer = $si.Signer
            $svcSigDone++
        }

        $services += [PSCustomObject]@{
            Name        = $svc.Name
            DisplayName = $svc.DisplayName
            State       = $svc.State
            StartMode   = $svc.StartMode
            Path        = $binPath
            PathName    = $img
            StartName   = $svc.StartName
            Signature   = $sigStatus
            Signer      = $signer
        }
    }
} catch {
    $services = @()
}

# ===================== СНИМОК ДЛЯ ИСТОРИИ =====================
$Snapshot = [ordered]@{
    Timestamp          = $Timestamp
    SelectedDrives      = $selectedLetters
    DiskC              = $disks.C
    DiskD              = $disks.D
    RootFoldersC       = $rootC
    RootFoldersD       = $rootD
    RootFolders         = $rootFolders
    UserFolders        = $userFolders
    AppDataTop         = $appDataTop
    Defender           = $defender
    SuspiciousFiles    = $suspiciousFiles
    AutorunRegistry    = $autorun
    ScheduledTasks     = $scheduledTasks
    UnsignedProcesses  = $unsignedProcesses
    Processes          = $processes
    Services           = $services
}

# ===================== ДИФФЫ С ПРОШЛЫМ ЗАПУСКОМ =====================
$newAutorun = Get-NewItems $autorun $PreviousSnapshot.AutorunRegistry @('Key','Name')
$newTasks   = Get-NewItems $scheduledTasks $PreviousSnapshot.ScheduledTasks @('TaskPath','TaskName')
$newUnsigned = Get-NewItems $unsignedProcesses $PreviousSnapshot.UnsignedProcesses @('Path')
$newSuspicious = Get-NewItems $suspiciousFiles $PreviousSnapshot.SuspiciousFiles @('Path')
$newServices = Get-NewItems $services $PreviousSnapshot.Services @('Name')

# ===================== ИСТОРИЯ ИСПОЛЬЗОВАНИЯ ДИСКА =====================
# Собираем историю из всех снимков в HistoryDir (для графика изменения диска во времени)
$diskHistory = @()
Get-ChildItem $HistoryDir -Filter "snapshot_*.json" -ErrorAction SilentlyContinue |
    Sort-Object Name | ForEach-Object {
        try {
            $snap = Get-Content $_.FullName -Raw | ConvertFrom-Json
            if ($snap.DiskC) {
                $diskHistory += [PSCustomObject]@{
                    Date    = $snap.Timestamp
                    Disk    = "C"
                    TotalGB = $snap.DiskC.TotalGB
                    FreeGB  = $snap.DiskC.FreeGB
                    UsedGB  = $snap.DiskC.UsedGB
                }
            }
            if ($snap.DiskD) {
                $diskHistory += [PSCustomObject]@{
                    Date    = $snap.Timestamp
                    Disk    = "D"
                    TotalGB = $snap.DiskD.TotalGB
                    FreeGB  = $snap.DiskD.FreeGB
                    UsedGB  = $snap.DiskD.UsedGB
                }
            }
        } catch {}
    }
# Добавляем текущий запуск
foreach ($letter in $selectedLetters) {
    $key = $letter.Substring(0,1)
    if ($disks[$key]) {
        $diskHistory += [PSCustomObject]@{
            Date    = $Timestamp
            Disk    = $key
            TotalGB = $disks[$key].TotalGB
            FreeGB  = $disks[$key].FreeGB
            UsedGB  = $disks[$key].UsedGB
        }
    }
}

# ===================== СТРУКТУРИРОВАННЫЙ ОТЧЁТ ДЛЯ GATEWAY =====================
# ===================== РЕКОМЕНДАЦИИ =====================
$recommendations = @()
foreach ($letter in $selectedLetters) {
    $key = $letter.Substring(0,1)
    if (-not $disks[$key]) { continue }
    if ($disks[$key].UsedPct -gt 90) {
        $recommendations += "Диск $key заполнен на $($disks[$key].UsedPct)% - рекомендуется освободить место."
    } elseif ($disks[$key].UsedPct -gt 80) {
        $recommendations += "Диск $key заполнен на $($disks[$key].UsedPct)% - стоит обратить внимание на крупные файлы."
    }
}
if ($defender -and -not $defender.RealTime) {
    $recommendations += "Реальная защита Windows Defender отключена - включите её."
}
if ($defender -and $defender.SignatureAge -gt 7) {
    $recommendations += "Подписи Windows Defender устарели ($($defender.SignatureAge) дн) - обновите через Update-MpSignature."
}
if ($newAutorun.Count -gt 0) {
    $recommendations += "Обнаружены новые записи автозагрузки ($($newAutorun.Count)) - проверьте их вручную."
}
if ($newSuspicious.Count -gt 0) {
    $recommendations += "Обнаружены новые подозрительные файлы ($($newSuspicious.Count)) - проверьте через VirusTotal."
}
if ($newServices.Count -gt 0) {
    $recommendations += "Обнаружены новые службы Windows ($($newServices.Count)) - проверьте их происхождение."
}
if ($doubleExtensions.Count -gt 0) {
    $recommendations += "Найдены файлы с двойным расширением ($($doubleExtensions.Count)) - возможная малварь."
}
if ($recommendations.Count -eq 0) {
    $recommendations += "Существенных проблем не обнаружено. Продолжайте регулярные проверки."
}

# ===================== ОСТАНОВКА СЕКУНДОМЕРА =====================
$sw.Stop()
$durationSec = [math]::Round($sw.Elapsed.TotalSeconds, 1)

# ===================== ИТОГОВЫЙ REPORT.JSON =====================
$pcName = $env:COMPUTERNAME
if ([string]::IsNullOrWhiteSpace($pcName)) { $pcName = $env:HOSTNAME }
if ([string]::IsNullOrWhiteSpace($pcName)) {
    try { $pcName = [System.Net.Dns]::GetHostName() } catch { $pcName = "UNKNOWN" }
}
$pcUser = $env:USERNAME
if ([string]::IsNullOrWhiteSpace($pcUser)) { $pcUser = $env:USER }
$pcOs = $null
try { $pcOs = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption } catch {}
if ([string]::IsNullOrWhiteSpace($pcOs)) { $pcOs = "Windows" }

$report = [ordered]@{
    meta = [ordered]@{
        version        = "1.0"
        mode           = $Mode
        generated_at   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        duration_sec   = $durationSec
        files_scanned  = $fileCount
        selected_drives = $selectedLetters
    }
    computer = [ordered]@{
        name      = "$pcName"
        user      = "$pcUser"
        os        = "$pcOs"
    }
    scan = [ordered]@{
        timestamp = $Timestamp
        duration_sec = $durationSec
        files_scanned = $fileCount
        selected_drives = $selectedLetters
    }
    disks = $disks
    disk_history = $diskHistory
    defender = $defender
    suspicious_files = $suspiciousFiles
    double_extensions = $doubleExtensions
    autorun = $autorun
    startup_items = $startupItems
    scheduled_tasks = $scheduledTasks
    unsigned_processes = $unsignedProcesses
    processes = $processes
    services = $services
    large_files = @($largeFiles | ForEach-Object { [PSCustomObject]@{ Path = $_.FullName; SizeGB = (Format-GB $_.Length) } })
    old_files = @($oldFiles | ForEach-Object { [PSCustomObject]@{ Path = $_.FullName; SizeMB = (Format-MB $_.Length); Modified = $_.LastWriteTime.ToString('yyyy-MM-dd') } })
    temp_sizes = $tempSizes
    user_folders = $userFolders
    root_folders_c = $rootC
    root_folders_d = $rootD
    root_folders = $rootFolders
    selected_drives = $selectedLetters
    appdata_top = $appDataTop
    duplicate_files      = $duplicateFiles
    changes = [ordered]@{
        new_autorun = $newAutorun
        new_scheduled_tasks = $newTasks
        new_unsigned_processes = $newUnsigned
        new_suspicious_files = $newSuspicious
        new_services = $newServices
        folder_deltas = $folderDeltas
    }
    recommendations = $recommendations
}

$jsonBody = $report | ConvertTo-Json -Depth 12
[System.IO.File]::WriteAllText($ReportFile, $jsonBody, [System.Text.Encoding]::UTF8)

# ===================== СОХРАНЕНИЕ СНИМКА В ИСТОРИЮ =====================
try {
    $jsonSnapshot = $Snapshot | ConvertTo-Json -Depth 8
    [System.IO.File]::WriteAllText($SnapshotFile, $jsonSnapshot, [System.Text.Encoding]::UTF8)
} catch {
    Write-Host "Warning: could not save history snapshot: $($_.Exception.Message)"
}

# Чистим старые снимки - храним последние 30, чтобы папка История не росла бесконечно
Get-ChildItem $HistoryDir -Filter "snapshot_*.json" -ErrorAction SilentlyContinue |
    Sort-Object Name -Descending | Select-Object -Skip 30 | Remove-Item -Force -ErrorAction SilentlyContinue

# ===================== ВЫВОД В STDOUT (для GUI) =====================
Write-Host ""
Write-Host "REPORT_FILE: $ReportFile"
Write-Host "DONE"