"""Application paths and runtime configuration.

The application is local-first: every installation gets its own data directory.
No user data is stored on Desktop.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

APP_NAME = "DiskDiagnostic"  # data folder name — do not change (compat)
PRODUCT_NAME = "Miharu"
PRODUCT_NAME_JP = "見張る"
PRODUCT_TAGLINE = "See what changed. Understand what matters."
SCHEMA_VERSION = 3
SETTINGS_SCHEMA_VERSION = 1
SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPT_PATH = SCRIPT_DIR / "scripts" / "disk_diagnostic.ps1"

# Office builds may ship secrets/product_defaults.json (gitignored).
PRODUCT_DEFAULTS_NAME = "product_defaults.json"


def resource_root() -> Path:
    """App root: PyInstaller bundle or source tree."""
    import sys
    meipass = getattr(sys, "_MEIPASS", None)
    if getattr(sys, "frozen", False) and meipass:
        return Path(str(meipass))
    return SCRIPT_DIR


def product_defaults_path() -> Path | None:
    """Bundled defaults next to install / in _internal / secrets/.

    Preference order:
      1. product_defaults.json (office / explicit)
      2. product_defaults.example.json (dev fallback so Telegram works from source)
    """
    names = (PRODUCT_DEFAULTS_NAME, "product_defaults.example.json")
    bases: list[Path] = []
    import sys
    if getattr(sys, "frozen", False):
        # onedir: next to exe, then _MEIPASS
        bases.append(Path(sys.executable).resolve().parent)
        bases.append(Path(sys.executable).resolve().parent / "secrets")
    bases.extend(
        [
            resource_root(),
            resource_root() / "secrets",
            SCRIPT_DIR,
            SCRIPT_DIR / "secrets",
        ]
    )
    # Prefer real product_defaults.json over example across all bases
    for name in names:
        for base in bases:
            p = base / name
            if p.is_file():
                return p
    return None


def load_product_defaults() -> dict:
    path = product_defaults_path()
    if not path:
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


LOCAL_APP_DATA = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
APP_DATA_DIR = LOCAL_APP_DATA / APP_NAME

REPORT_DIR = APP_DATA_DIR / "Reports"
HISTORY_DIR = APP_DATA_DIR / "History"
SNAPSHOT_DIR = APP_DATA_DIR / "Snapshots"
CACHE_DIR = APP_DATA_DIR / "Cache"
LOG_DIR = APP_DATA_DIR / "Logs"
CONFIG_DIR = APP_DATA_DIR / "Config"

SETTINGS_PATH = CONFIG_DIR / "settings.json"
INSTALLATION_ID_PATH = CONFIG_DIR / "installation_id"
TELEGRAM_STATE_PATH = APP_DATA_DIR / "Alerts" / "telegram_state.json"

DEFAULT_BACKEND_URL = os.environ.get("DISK_DIAGNOSTIC_BACKEND_URL", "").strip()

# Never hardcode tokens in git. Office Setup may embed secrets/product_defaults.json.
# Priority at runtime: env → settings.json → product_defaults → (empty)
DEFAULT_TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()


def ensure_app_dirs() -> None:
    for path in (
        APP_DATA_DIR,
        REPORT_DIR,
        HISTORY_DIR,
        SNAPSHOT_DIR,
        CACHE_DIR,
        LOG_DIR,
        CONFIG_DIR,
        TELEGRAM_STATE_PATH.parent,
    ):
        path.mkdir(parents=True, exist_ok=True)


def load_settings() -> dict:
    try:
        if SETTINGS_PATH.exists():
            data = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return migrate_settings(data)
    except (OSError, ValueError, TypeError):
        pass
    return migrate_settings({})


def migrate_settings(data: dict) -> dict:
    """Bump settings schema without breaking older installs."""
    out = dict(data or {})
    ver = int(out.get("schema_version") or 0)
    if ver < 1:
        out.setdefault("notification_mode", out.get("notification_mode") or "off")
        out.setdefault("monitor_interval_hours", out.get("monitor_interval_hours") or 6)
        out.setdefault("monitor_mode", out.get("monitor_mode") or "Quick")
        out.setdefault("monitor_smart", True if "monitor_smart" not in out else out.get("monitor_smart"))
        out["schema_version"] = SETTINGS_SCHEMA_VERSION
    elif ver < SETTINGS_SCHEMA_VERSION:
        out["schema_version"] = SETTINGS_SCHEMA_VERSION
    return out


def save_settings(update: dict) -> dict:
    """Merge update into settings.json and return the full settings dict."""
    ensure_app_dirs()
    data = load_settings()
    data.update(update)
    tmp = SETTINGS_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(SETTINGS_PATH)
    return data



def seed_product_defaults() -> dict:
    """On first run, copy bundled bot token (and optional keys) into settings.json.

    chat_id is NEVER auto-filled — each PC/user links via TELEGRAM button.
    """
    ensure_app_dirs()
    defaults = load_product_defaults()
    if not defaults:
        return load_settings()
    data = load_settings()
    update: dict = {}
    bundled_token = str(defaults.get("telegram_bot_token") or defaults.get("TELEGRAM_BOT_TOKEN") or "").strip()
    if bundled_token and not str(data.get("telegram_bot_token") or "").strip():
        update["telegram_bot_token"] = bundled_token
        # office distribution: enable direct when we ship a token
        if not str(data.get("notification_mode") or "").strip() or data.get("notification_mode") == "off":
            update["notification_mode"] = "direct"
    for key in ("mistral_api_key", "nvidia_api_key", "vt_api_key"):
        val = str(defaults.get(key) or "").strip()
        if val and not str(data.get(key) or "").strip():
            update[key] = val
    if update:
        return save_settings(update)
    return data


def notification_mode() -> str:
    """off by default; backend or direct Telegram are explicit opt-in."""
    mode = os.environ.get("DISK_DIAGNOSTIC_NOTIFICATION_MODE", "").strip().lower()
    if not mode:
        mode = str(load_settings().get("notification_mode") or "").strip().lower()
    mode = mode or "off"
    return mode if mode in {"backend", "direct", "off"} else "off"
