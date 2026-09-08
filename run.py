"""Miharu entry point.

Development:
    python run.py

Background monitor:
    python run.py --monitor
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import ensure_app_dirs, seed_product_defaults


def run_monitor() -> int:
    ensure_app_dirs()
    seed_product_defaults()
    from core.monitor import run_monitor_once

    result = run_monitor_once()
    return 0 if result.get("ok") else 1


def main() -> int:
    if "--monitor" in sys.argv[1:]:
        return run_monitor()

    ensure_app_dirs()
    seed_product_defaults()
    from PySide6.QtWidgets import QApplication
    from ui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("Miharu")
    app.setStyle("Fusion")
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())