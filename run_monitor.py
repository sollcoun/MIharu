"""Headless background monitor entry point for Task Scheduler.

    pythonw run_monitor.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import ensure_app_dirs


def main() -> int:
    ensure_app_dirs()
    from core.monitor import run_monitor_once

    result = run_monitor_once()
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
