"""Точка входа в приложение Miharu."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from PySide6.QtWidgets import QApplication

from config import ensure_app_dirs
from ui.main_window import MainWindow


def main():
    ensure_app_dirs()
    app = QApplication(sys.argv)
    app.setApplicationName("Miharu")
    app.setStyle("Fusion")

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()