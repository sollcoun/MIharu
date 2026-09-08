"""Stable per-installation identifier without exposing account data."""
from __future__ import annotations

import secrets
from pathlib import Path

from config import INSTALLATION_ID_PATH, ensure_app_dirs


def get_installation_id() -> str:
    try:
        if INSTALLATION_ID_PATH.exists():
            value = INSTALLATION_ID_PATH.read_text(encoding="utf-8").strip()
            if len(value) >= 24:
                return value
        ensure_app_dirs()
        value = secrets.token_hex(16)
        tmp = INSTALLATION_ID_PATH.with_suffix(".tmp")
        tmp.write_text(value, encoding="utf-8")
        tmp.replace(INSTALLATION_ID_PATH)
        return value
    except OSError:
        # Still provide a process-stable identifier if the data directory is unavailable.
        return "ephemeral-" + secrets.token_hex(12)
