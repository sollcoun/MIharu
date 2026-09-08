"""Path/name allowlist to suppress known-benign noise in Risk Engine."""
from __future__ import annotations

from typing import Any


# Built-in: Microsoft Defender platform binaries often lack readable publisher in quick scan
DEFAULT_PATH_PREFIXES = (
    r"c:\programdata\microsoft\windows defender\\",
    r"c:\program files\windows defender\\",
    r"c:\program files (x86)\windows defender\\",
    r"c:\windows\system32\driverstore\\",
    r"c:\windows\winsxs\\",
    r"c:\program files\windowsapps\\",
    r"c:\program files\microsoft\edgeupdate\\",
    r"c:\program files (x86)\microsoft\edgeupdate\\",
    r"c:\programdata\microsoft\windows defender advanced threat protection\\",
)

DEFAULT_NAME_EQUALS = {
    "mpcmdrun.exe",
    "msmpeng.exe",
    "nissrv.exe",
    "securityhealthservice.exe",
    "smartscreen.exe",
}


def _norm(path: str) -> str:
    return (path or "").strip().lower().replace("/", "\\")


def _load_user_rules() -> tuple[list[str], list[str]]:
    prefixes: list[str] = []
    names: list[str] = []
    try:
        from config import load_settings
        data = load_settings().get("allowlist") or {}
        if isinstance(data, dict):
            for p in data.get("path_prefixes") or []:
                s = _norm(str(p))
                if s:
                    prefixes.append(s if s.endswith("\\") else s + "\\")
            for n in data.get("names") or []:
                s = _norm(str(n))
                if s:
                    names.append(s)
        elif isinstance(data, list):
            for item in data:
                s = _norm(str(item))
                if "\\" in s or "/" in str(item):
                    prefixes.append(s if s.endswith("\\") else s + "\\")
                elif s:
                    names.append(s)
    except Exception:
        pass
    return prefixes, names


def is_allowlisted(path: str = "", name: str = "") -> bool:
    """True if object matches built-in or user allowlist."""
    p = _norm(path)
    n = _norm(name) or (p.split("\\")[-1] if p else "")

    if n in DEFAULT_NAME_EQUALS:
        return True

    for pref in DEFAULT_PATH_PREFIXES:
        if p.startswith(pref):
            return True

    user_pref, user_names = _load_user_rules()
    if n in user_names:
        return True
    for pref in user_pref:
        if p.startswith(pref):
            return True
    return False


def allowlist_hit(path: str = "", name: str = "") -> dict[str, Any] | None:
    if is_allowlisted(path, name):
        return {"type": "allowlisted", "weight": -50}
    return None


def add_path_to_allowlist(path: str) -> dict:
    """Persist path prefix (directory) or exact file name into settings."""
    from config import load_settings, save_settings
    p = (path or "").strip()
    if not p:
        raise ValueError("empty path")
    settings = load_settings()
    al = settings.get("allowlist")
    if not isinstance(al, dict):
        al = {"path_prefixes": [], "names": []}
    prefixes = list(al.get("path_prefixes") or [])
    names = list(al.get("names") or [])
    norm = _norm(p)
    if norm.endswith(".exe") or norm.endswith(".dll") or norm.endswith(".sys"):
        leaf = norm.split("\\")[-1]
        if leaf and leaf not in names:
            names.append(leaf)
    else:
        pref = norm if norm.endswith("\\") else norm + "\\"
        if pref not in [_norm(x) for x in prefixes]:
            prefixes.append(path if path.endswith("\\") else path + "\\")
    al = {"path_prefixes": prefixes, "names": names}
    return save_settings({"allowlist": al})