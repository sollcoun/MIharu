# Miharu — Windows build

## Requirements

- Windows 10/11 x64
- Python 3.10+
- Inno Setup 6

## Build

```powershell
.\build\build.ps1 -Clean
```

Result:

```text
dist\Miharu\Miharu.exe
release\Miharu-Setup-1.1.0.exe
```

EXE only:

```powershell
.\build\build.ps1 -Clean -SkipInstaller
```

## Install paths

| What | Where |
|------|--------|
| Application | `C:\Program Files\Miharu` |
| User data | `%LOCALAPPDATA%\DiskDiagnostic` |

Legacy **Disk Diagnostic** is removed automatically on install (same/old AppId).
