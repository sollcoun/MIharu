"""Главное окно Miharu — стиль как на референсе."""

from __future__ import annotations

import glob
import json
import os
from pathlib import Path

from PySide6.QtCore import Qt, QStorageInfo, QThread, Signal
from PySide6.QtGui import QAction, QIcon, QPixmap, QTextCursor
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QFormLayout,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QStackedWidget,
    QSystemTrayIcon,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    QMenu,
)

from config import REPORT_DIR, SCRIPT_DIR, SCRIPT_PATH, notification_mode, load_settings, save_settings
from core.hash_vt import enrich_hashes_and_vt
from core.risk_engine import enrich_report
from core.ai_explain import enrich_with_ai
from core.snapshot import apply_snapshot_pipeline
from notifications.backend_notifications import BackendNotificationProvider
from notifications.notifications import NotificationManager
from notifications.telegram_alerts import (
    deep_link,
    is_configured,
    link_chat_id_async,
    send_summary_async,
    telegram_chat_id,
    telegram_token,
)
from installation import get_installation_id
from core.monitor import (
    monitor_enabled,
    monitor_interval_hours,
    next_run_eta,
    register_scheduled_task,
    scheduled_task_exists,
    unregister_scheduled_task,
)
from .dashboard import format_report_preview, generate_dashboard
from .scan_worker import ScanWorker


# ---------------------------------------------------------------------------
# Палитра (как на скрине)
# ---------------------------------------------------------------------------
BG = "#0B0B0D"
BG_SIDEBAR = "#0E0E10"
BG_HEADER = "#0E0E10"
BORDER = "#1E1E22"
BORDER_SOFT = "#2A2A30"
TEXT = "#E8E8EC"
TEXT_MUTED = "#8A8A92"
TEXT_DIM = "#5C5C64"
RED = "#E31B23"
GREEN = "#22C55E"
ORANGE = "#F59E0B"


STYLE = f"""
* {{
    font-family: "Segoe UI", "Inter", system-ui, -apple-system, sans-serif;
    font-size: 13px;
}}

QMainWindow {{
    background: {BG};
}}

QWidget {{
    color: {TEXT};
    background: transparent;
}}

QFrame#sidebar {{
    background: #0A0A0C;
    border-right: 1px solid {BORDER};
}}

QFrame#header {{
    background: #0C0C0E;
    border-bottom: 1px solid {BORDER};
}}

QFrame#statusbar {{
    background: #0A0A0C;
    border-top: 1px solid {BORDER};
}}

QFrame#contentCard {{
    background: #101014;
    border: 1px solid {BORDER};
    border-radius: 14px;
}}

QLabel#logo_jp {{
    color: {RED};
    font-size: 16px;
    font-weight: 700;
    letter-spacing: 2px;
}}

QLabel#title {{
    color: {TEXT};
    font-size: 15px;
    font-weight: 700;
    letter-spacing: 1.5px;
}}

QLabel#meta_label {{
    color: {TEXT_DIM};
    font-size: 9px;
    letter-spacing: 0.8px;
}}

QLabel#meta_value {{
    color: {TEXT};
    font-size: 12px;
    font-weight: 600;
}}

QLabel#status {{
    color: {TEXT_MUTED};
    font-size: 11px;
}}

QLabel#status_value {{
    color: {TEXT};
    font-size: 11px;
    font-weight: 600;
}}

QPushButton#scanBtn {{
    background: {RED};
    color: white;
    border: none;
    border-radius: 10px;
    padding: 10px 26px;
    font-weight: 700;
    letter-spacing: 1px;
    font-size: 12px;
}}

QPushButton#scanBtn:hover {{
    background: #FF2A32;
}}

QPushButton#scanBtn:disabled {{
    background: #3A1518;
    color: #7A4044;
}}

QPushButton#navBtn {{
    background: transparent;
    color: {TEXT_MUTED};
    border: none;
    padding: 12px 18px;
    text-align: left;
    font-size: 13px;
    border-radius: 10px;
    margin: 2px 10px;
}}

QPushButton#navBtn:hover {{
    background: rgba(255, 255, 255, 0.04);
    color: {TEXT};
}}

QPushButton#navBtn:checked {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 rgba(227, 27, 35, 0.28), stop:1 rgba(227, 27, 35, 0.06));
    color: {TEXT};
    font-weight: 600;
    border-left: 3px solid {RED};
    padding-left: 15px;
}}

QPushButton#secondaryBtn {{
    background: transparent;
    color: {TEXT_MUTED};
    border: 1px solid {BORDER};
    border-radius: 10px;
    padding: 8px 16px;
    font-size: 11px;
    letter-spacing: 0.4px;
}}

QPushButton#secondaryBtn:hover {{
    border-color: {BORDER_SOFT};
    color: {TEXT};
    background: rgba(255,255,255,0.02);
}}

QPushButton#secondaryBtn:disabled {{
    color: {TEXT_DIM};
    border-color: {BORDER};
}}

QPushButton#primaryBtn {{
    background: {RED};
    color: white;
    border: none;
    border-radius: 10px;
    padding: 9px 18px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.5px;
}}

QPushButton#primaryBtn:hover {{
    background: #FF2A32;
}}

QPushButton#primaryBtn:disabled {{
    background: #3A1518;
    color: #7A4044;
}}

QPlainTextEdit {{
    background: transparent;
    color: {TEXT};
    border: none;
    padding: 16px 18px;
    font-family: "Cascadia Code", "Consolas", "Segoe UI", monospace;
    font-size: 12px;
    selection-background-color: rgba(227, 27, 35, 0.28);
    selection-color: {TEXT};
}}

QTextEdit {{
    background: transparent;
    color: {TEXT};
    border: none;
    padding: 12px 14px;
    selection-background-color: rgba(227, 27, 35, 0.28);
    selection-color: {TEXT};
}}

QStackedWidget {{
    border: none;
    background: transparent;
}}
"""



class ReportEnrichThread(QThread):
    """Heavy post-scan work off the UI thread (VT + AI can block 10-60s)."""

    progress = Signal(str)
    finished_ok = Signal(object, object)
    finished_err = Signal(str)

    def __init__(self, report_path: Path, report: dict, parent=None):
        super().__init__(parent)
        self.report_path = report_path
        self.report = report

    def run(self) -> None:
        try:
            report = self.report
            self.progress.emit("Snapshot / Diff…")
            report = apply_snapshot_pipeline(report)
            self.progress.emit("Hash / VirusTotal…")
            report = enrich_hashes_and_vt(report)
            self.progress.emit("Risk Engine…")
            report = enrich_report(report)
            self.progress.emit("AI (Mistral/NVIDIA)…")
            report = enrich_with_ai(report)
            self.report_path.write_text(
                json.dumps(report, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            self.finished_ok.emit(report, self.report_path)
        except Exception as exc:
            self.finished_err.emit(str(exc))


class MainWindow(QMainWindow):
    """Главное окно — только оболочка со стилем, дашборд открывается отдельно."""

    def __init__(self):
        super().__init__()

        self.setWindowTitle("Miharu // 見張る")
        self.resize(1100, 680)
        self.setStyleSheet(STYLE)
        self._apply_app_icon()

        self.worker: ScanWorker | None = None
        self.latest_report_path: Path | None = None
        self.latest_dashboard_path: Path | None = None
        self.computer_label: QLabel
        self.last_scan_label: QLabel
        self.duration_label: QLabel
        self.files_label: QLabel
        self.status_dot: QLabel
        self.status_label: QLabel
        self.status_detail: QLabel
        self.scan_btn: QPushButton
        self.quick_btn: QPushButton
        self.open_dashboard_btn: QPushButton
        self.open_json_btn: QPushButton
        self.export_btn: QPushButton
        self.open_folder_btn: QPushButton
        self.telegram_btn: QPushButton
        self.monitor_btn: QPushButton
        self.disk_btn: QPushButton
        self.selected_drives: list[str] = self._load_selected_drives()
        self.log_view: QPlainTextEdit
        self.report_view: QTextEdit
        self.stack: QStackedWidget
        self.nav_btns: list[QPushButton]
        self.tray: QSystemTrayIcon | None = None

        central = QWidget()
        self.setCentralWidget(central)

        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ===== Header =====
        header = QFrame()
        header.setObjectName("header")
        header.setFixedHeight(64)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(20, 0, 20, 0)
        header_layout.setSpacing(16)

        logo_jp = QLabel()
        logo_jp.setObjectName("logo_jp")
        logo_jp.setFixedSize(36, 36)
        logo_path = Path(__file__).resolve().parent.parent / "assets" / "logo_64.png"
        if logo_path.exists():
            pix = QPixmap(str(logo_path)).scaled(
                36, 36,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
            logo_jp.setPixmap(pix)
        else:
            logo_jp.setText("診")
            logo_jp.setStyleSheet(f"color: {RED}; font-size: 18px; font-weight: 700;")

        title = QLabel("MIHARU")
        title.setObjectName("title")

        header_layout.addWidget(logo_jp)
        header_layout.addWidget(title)
        header_layout.addSpacing(24)

        def meta_col(label: str, attr: str) -> QVBoxLayout:
            box = QVBoxLayout()
            box.setSpacing(1)
            t = QLabel(label)
            t.setObjectName("meta_label")
            v = QLabel("—")
            v.setObjectName("meta_value")
            setattr(self, attr, v)
            box.addWidget(t)
            box.addWidget(v)
            return box

        header_layout.addLayout(meta_col("КОМПЬЮТЕР", "computer_label"))
        header_layout.addLayout(meta_col("ПОСЛЕДНЕЕ СКАНИРОВАНИЕ", "last_scan_label"))
        header_layout.addLayout(meta_col("ДЛИТЕЛЬНОСТЬ", "duration_label"))
        header_layout.addLayout(meta_col("ФАЙЛОВ", "files_label"))
        header_layout.addStretch()

        self.disk_btn = QPushButton("DISKS: ALL")
        self.disk_btn.setObjectName("secondaryBtn")
        self.disk_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.disk_btn.setToolTip("Выбрать один или несколько дисков для файлового и storage-сканирования")
        self.disk_btn.clicked.connect(self.select_drives)
        header_layout.addWidget(self.disk_btn)

        self.quick_btn = QPushButton("QUICK")
        self.quick_btn.setObjectName("scanBtn")
        self.quick_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.quick_btn.setToolTip("Быстрый скан: security + diff, без размеров папок")
        self.quick_btn.clicked.connect(lambda: self.start_scan("Quick"))
        self.quick_btn.setStyleSheet(
            f"""
            QPushButton {{
                background: transparent;
                color: {RED};
                border: 1px solid {RED};
                border-radius: 8px;
                padding: 10px 18px;
                font-weight: 700;
                letter-spacing: 1px;
                font-size: 12px;
            }}
            QPushButton:hover {{ background: rgba(227,27,35,0.12); }}
            QPushButton:disabled {{ color: #7A4044; border-color: #3A1518; }}
            """
        )
        header_layout.addWidget(self.quick_btn)

        self.scan_btn = QPushButton("FULL SCAN")
        self.scan_btn.setObjectName("scanBtn")
        self.scan_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.scan_btn.setToolTip("Полная диагностика: папки, дубликаты, deep storage")
        self.scan_btn.clicked.connect(lambda: self.start_scan("Full"))
        header_layout.addWidget(self.scan_btn)

        root.addWidget(header)

        # ===== Body =====
        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)

        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(210)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(0, 14, 0, 14)
        sidebar_layout.setSpacing(2)

        nav_items = [
            ("Лог", "▶"),
            ("Превью", "▢"),
        ]

        self.nav_btns: list[QPushButton] = []
        for i, (name, icon) in enumerate(nav_items):
            btn = QPushButton(f"  {icon}  {name}")
            btn.setObjectName("navBtn")
            btn.setCheckable(True)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            if i == 0:
                btn.setChecked(True)
            btn.clicked.connect(lambda checked, idx=i: self._switch_view(idx))
            sidebar_layout.addWidget(btn)
            self.nav_btns.append(btn)

        sidebar_layout.addStretch()

        self.side_tg = QLabel("  Telegram: —")
        self.side_tg.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px; padding: 4px 16px;")
        sidebar_layout.addWidget(self.side_tg)

        self.side_mon = QLabel("  Monitor: —")
        self.side_mon.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px; padding: 4px 16px;")
        sidebar_layout.addWidget(self.side_mon)

        ver = QLabel("  v1.1.0")
        ver.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px; padding: 8px 16px;")
        sidebar_layout.addWidget(ver)

        body.addWidget(sidebar)

        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(16, 14, 16, 12)
        content_layout.setSpacing(12)

        card = QFrame()
        card.setObjectName("contentCard")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(0, 0, 0, 0)
        card_layout.setSpacing(0)

        self.stack = QStackedWidget()

        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setPlainText(
            "MIHARU  ·  見張る\n"
            "See what changed. Understand what matters.\n"
            "────────────────────────────────────\n\n"
            "  QUICK   быстрый скан (security + diff)\n"
            "  FULL    полный скан (папки, дубликаты)\n"
            "  DISKS   выбор дисков\n\n"
            "После скана откройте Dashboard или вкладку Превью.\n"
            "MONITOR — фон   ·   TELEGRAM — уведомления\n"
        )

        self.report_view = QTextEdit()
        self.report_view.setReadOnly(True)
        self.report_view.setHtml(
            f"""
            <div style="padding:40px 24px;max-width:560px;">
              <div style="color:#5C5C64;font-size:10px;letter-spacing:2px;">MIHARU</div>
              <div style="color:#E8E8EC;font-size:18px;font-weight:700;margin-top:8px;">
                Готов к наблюдению
              </div>
              <div style="color:#8A8A92;font-size:12px;margin-top:12px;line-height:1.7;">
                Запустите <b style="color:#E8E8EC;">QUICK</b> или <b style="color:#E8E8EC;">FULL SCAN</b>.<br>
                Здесь появится статус защиты, диски и краткие изменения.
              </div>
              <div style="margin-top:22px;height:1px;background:#1E1E22;"></div>
              <div style="color:#5C5C64;font-size:11px;margin-top:14px;line-height:1.6;">
                See what changed. Understand what matters.
              </div>
            </div>
            """
        )

        self.stack.addWidget(self.log_view)
        self.stack.addWidget(self.report_view)
        card_layout.addWidget(self.stack, 1)
        content_layout.addWidget(card, 1)

        footer_btns = QHBoxLayout()
        footer_btns.setSpacing(8)

        self.open_dashboard_btn = QPushButton("ОТКРЫТЬ DASHBOARD")
        self.open_dashboard_btn.setObjectName("primaryBtn")
        self.open_dashboard_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.open_dashboard_btn.setEnabled(False)
        self.open_dashboard_btn.setToolTip("Открыть HTML-дашборд последнего скана")
        self.open_dashboard_btn.clicked.connect(self.open_dashboard)

        self.open_json_btn = QPushButton("JSON")
        self.open_json_btn.setObjectName("secondaryBtn")
        self.open_json_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.open_json_btn.setEnabled(False)
        if hasattr(self, 'export_btn'):
            self.export_btn.setEnabled(False)
        self.open_json_btn.setToolTip("Открыть report.json")
        self.open_json_btn.clicked.connect(self.open_json)

        self.export_btn = QPushButton("ЭКСПОРТ")
        self.export_btn.setObjectName("secondaryBtn")
        self.export_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.export_btn.setEnabled(False)
        self.export_btn.setToolTip("Экспорт HTML+TXT для передачи (без сырого JSON)")
        self.export_btn.clicked.connect(self.export_report_files)

        self.open_folder_btn = QPushButton("ПАПКА ОТЧЁТОВ")
        self.open_folder_btn.setObjectName("secondaryBtn")
        self.open_folder_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.open_folder_btn.setToolTip("Папка отчётов в LocalAppData")
        self.open_folder_btn.clicked.connect(self.open_report_folder)

        self.telegram_btn = QPushButton("TELEGRAM")
        self.telegram_btn.setObjectName("secondaryBtn")
        self.telegram_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.telegram_btn.setToolTip("Привязать чат: откроется бот, нажмите Start")
        self.telegram_btn.clicked.connect(self.link_telegram)
        self._refresh_telegram_btn()

        footer_btns.addWidget(self.open_dashboard_btn)
        footer_btns.addWidget(self.open_json_btn)
        footer_btns.addWidget(self.export_btn)
        footer_btns.addWidget(self.open_folder_btn)
        footer_btns.addWidget(self.telegram_btn)

        self.monitor_btn = QPushButton("MONITOR")
        self.monitor_btn.setObjectName("secondaryBtn")
        self.monitor_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.monitor_btn.setToolTip("Фоновый скан через Task Scheduler")
        self.monitor_btn.clicked.connect(self.toggle_monitor)
        self._refresh_monitor_btn()
        footer_btns.addWidget(self.monitor_btn)

        self.settings_btn = QPushButton("НАСТРОЙКИ")
        self.settings_btn.setObjectName("secondaryBtn")
        self.settings_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.settings_btn.setToolTip("API-ключи: Mistral, NVIDIA, VirusTotal")
        self.settings_btn.clicked.connect(self.open_settings)
        footer_btns.addWidget(self.settings_btn)
        footer_btns.addStretch()
        content_layout.addLayout(footer_btns)

        body.addWidget(content, 1)
        root.addLayout(body, 1)

        statusbar = QFrame()
        statusbar.setObjectName("statusbar")
        statusbar.setFixedHeight(36)
        statusbar_layout = QHBoxLayout(statusbar)
        statusbar_layout.setContentsMargins(20, 0, 20, 0)

        self.status_dot = QLabel("●")
        self.status_dot.setStyleSheet(f"color: {GREEN}; font-size: 9px;")
        self.status_label = QLabel("СТАТУС: ГОТОВ")
        self.status_label.setObjectName("status")

        statusbar_layout.addWidget(self.status_dot)
        statusbar_layout.addWidget(self.status_label)
        statusbar_layout.addStretch()

        self.status_detail = QLabel("Готов к сканированию")
        self.status_detail.setObjectName("status_value")
        statusbar_layout.addWidget(self.status_detail)

        root.addWidget(statusbar)
        self._refresh_telegram_btn()
        self._refresh_monitor_btn()
        self._refresh_disk_button()
        self._try_load_last_report()

        self._setup_tray()

        if not SCRIPT_PATH.exists():
            self.status_label.setText("ОШИБКА: скрипт не найден")
            self.status_dot.setStyleSheet(f"color: {RED}; font-size: 9px;")
            self.scan_btn.setEnabled(False)
            self.quick_btn.setEnabled(False)


    def _available_drives(self) -> list[dict]:
        drives = []
        for storage in QStorageInfo.mountedVolumes():
            if not storage.isReady() or not storage.isValid():
                continue
            root = storage.rootPath()
            if not root or len(root) < 2 or root[1] != ":":
                continue
            letter = root[0].upper()
            if letter in {"A", "B"}:
                continue
            drives.append({
                "letter": f"{letter}:",
                "name": storage.displayName() or "Локальный диск",
                "total": storage.bytesTotal(),
                "free": storage.bytesFree(),
            })
        return sorted({d["letter"]: d for d in drives}.values(), key=lambda x: x["letter"])

    def _load_selected_drives(self) -> list[str]:
        available = [d["letter"] for d in self._available_drives()]
        saved = load_settings().get("selected_drives")
        if isinstance(saved, list):
            selected = [str(x).upper().rstrip("\\") for x in saved]
            selected = [x if x.endswith(":") else f"{x}:" for x in selected]
            selected = [x for x in selected if x in available]
            if selected:
                return selected
        return available

    @staticmethod
    def _format_bytes(value: int) -> str:
        if value < 1024 ** 3:
            return f"{value / 1024 ** 3:.1f} GB"
        return f"{value / 1024 ** 3:.1f} GB"

    def _refresh_disk_button(self) -> None:
        if not self.selected_drives:
            self.disk_btn.setText("DISKS: NONE")
            self.disk_btn.setStyleSheet(f"color: {RED}; border-color: {RED};")
            return
        all_drives = [d["letter"] for d in self._available_drives()]
        if self.selected_drives == all_drives:
            text = "DISKS: ALL"
        else:
            text = "DISKS: " + ", ".join(self.selected_drives)
        self.disk_btn.setText(text)
        self.disk_btn.setStyleSheet("")

    def select_drives(self) -> None:
        available = self._available_drives()
        if not available:
            QMessageBox.warning(self, "Диски", "Не удалось определить доступные локальные диски.")
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("Выбор дисков")
        dialog.setMinimumWidth(480)
        dialog.setStyleSheet(STYLE + f"""
            QDialog {{ background: {BG}; }}
            QCheckBox {{ color: {TEXT}; spacing: 10px; padding: 10px 6px; }}
            QCheckBox:hover {{ background: rgba(255,255,255,0.03); }}
            QLabel#drive_hint {{ color: {TEXT_MUTED}; font-size: 11px; }}
        """)
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(24, 22, 24, 18)
        layout.setSpacing(12)

        title = QLabel("ДИСКИ ДЛЯ СКАНИРОВАНИЯ")
        title.setObjectName("title")
        layout.addWidget(title)
        hint = QLabel("Выберите один или несколько дисков. Системные проверки Windows (процессы, службы, задачи и автозагрузка) выполняются независимо от выбранного диска.")
        hint.setObjectName("drive_hint")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        grid = QGridLayout()
        grid.setHorizontalSpacing(8)
        grid.setVerticalSpacing(4)
        checks: list[tuple[QCheckBox, str]] = []
        for i, drive in enumerate(available):
            cb = QCheckBox()
            cb.setChecked(drive["letter"] in self.selected_drives)
            label = f"{drive['letter']}  {drive['name']}"
            if drive["total"]:
                label += f"   ·   {self._format_bytes(drive['total'])}   ·   свободно {self._format_bytes(drive['free'])}"
            cb.setText(label)
            grid.addWidget(cb, i, 0)
            checks.append((cb, drive["letter"]))
        layout.addLayout(grid)

        select_row = QHBoxLayout()
        select_all = QPushButton("ВСЕ")
        select_all.setObjectName("secondaryBtn")
        clear_all = QPushButton("СБРОСИТЬ")
        clear_all.setObjectName("secondaryBtn")
        select_row.addWidget(select_all)
        select_row.addWidget(clear_all)
        select_row.addStretch()
        layout.addLayout(select_row)

        select_all.clicked.connect(lambda: [cb.setChecked(True) for cb, _ in checks])
        clear_all.clicked.connect(lambda: [cb.setChecked(False) for cb, _ in checks])

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)

        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        selected = [letter for cb, letter in checks if cb.isChecked()]
        if not selected:
            QMessageBox.warning(self, "Диски", "Выберите хотя бы один диск.")
            return

        self.selected_drives = selected
        save_settings({"selected_drives": selected})
        self._refresh_disk_button()
        self.append_log(f"[ CONFIG ] Выбраны диски: {', '.join(selected)}\n")
        self.status_detail.setText(f"Диски: {', '.join(selected)}")

    def _try_load_last_report(self) -> None:
        """Подтянуть последний отчёт при старте — не нужно сканировать заново."""
        path = self._find_latest_report()
        if not path:
            return
        try:
            report = json.loads(path.read_text(encoding="utf-8-sig"))
        except Exception:
            return
        self.latest_report_path = path
        computer = report.get("computer") or {}
        meta = report.get("meta") or {}
        scan = report.get("scan") or {}
        self.computer_label.setText(str(computer.get("name") or "—"))
        self.last_scan_label.setText(str(meta.get("generated_at") or scan.get("timestamp") or "—"))
        dur = meta.get("duration_sec") or scan.get("duration_sec")
        self.duration_label.setText(f"{dur} сек" if dur is not None else "—")
        files = meta.get("files_scanned") or scan.get("files_scanned") or 0
        self.files_label.setText(f"{int(files):,}".replace(",", " "))
        try:
            self.report_view.setHtml(format_report_preview(report))
        except Exception:
            pass
        # Prefer existing HTML next to report
        html_candidates = sorted(path.parent.glob("Отчёт_*.html"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not html_candidates:
            html_candidates = sorted(path.parent.glob("*.html"), key=lambda p: p.stat().st_mtime, reverse=True)
        if html_candidates:
            self.latest_dashboard_path = html_candidates[0]
            self.open_dashboard_btn.setEnabled(True)
        self.open_json_btn.setEnabled(True)
        self.export_btn.setEnabled(True)
        risk = ((report.get("risk_summary") or {}).get("overall_risk") or "—")
        self.status_detail.setText(f"Последний отчёт · risk {risk}")
        self.append_log(f"[ STARTUP ] Загружен отчёт: {path.name}\n")



    def _setup_tray(self) -> None:
        if not QSystemTrayIcon.isSystemTrayAvailable():
            self.tray = None
            return
        icon = self.windowIcon()
        if icon.isNull():
            logo = Path(__file__).resolve().parent.parent / "assets" / "logo_32.png"
            if logo.exists():
                icon = QIcon(str(logo))
        self.tray = QSystemTrayIcon(icon, self)
        self.tray.setToolTip("Miharu")

        menu = QMenu()
        act_show = QAction("Показать Miharu", self)
        act_show.triggered.connect(self.show_from_tray)
        act_quick = QAction("Quick Scan", self)
        act_quick.triggered.connect(lambda: self.start_scan("Quick"))
        act_quit = QAction("Выход", self)
        act_quit.triggered.connect(self.quit_app)

        menu.addAction(act_show)
        menu.addAction(act_quick)
        menu.addSeparator()
        menu.addAction(act_quit)
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(self._on_tray_activated)
        self.tray.show()

    def _on_tray_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason in (
            QSystemTrayIcon.ActivationReason.Trigger,
            QSystemTrayIcon.ActivationReason.DoubleClick,
        ):
            self.show_from_tray()

    def show_from_tray(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def quit_app(self) -> None:
        if self.tray is not None:
            self.tray.hide()
        from PySide6.QtWidgets import QApplication
        app = QApplication.instance()
        if app is not None:
            app.quit()

    def closeEvent(self, event) -> None:  # noqa: N802
        """Close to tray if available; full quit via tray menu."""
        if self.tray is not None and self.tray.isVisible():
            self.hide()
            self.tray.showMessage(
                "Miharu",
                "Свернуто в трей. Monitor и уведомления продолжают работать по расписанию.",
                QSystemTrayIcon.MessageIcon.Information,
                2500,
            )
            event.ignore()
            return
        event.accept()


    def _apply_app_icon(self) -> None:
        root = Path(__file__).resolve().parent.parent
        for name in ("logo.png", "logo_64.png", "logo_32.png"):
            path = root / "assets" / name
            if path.exists():
                self.setWindowIcon(QIcon(str(path)))
                break

    def _switch_view(self, index: int):
        self.stack.setCurrentIndex(index)
        for i, btn in enumerate(self.nav_btns):
            btn.setChecked(i == index)

    def start_scan(self, mode: str = "Full"):
        if self.worker and self.worker.is_running():
            return

        self.scan_btn.setEnabled(False)
        self.quick_btn.setEnabled(False)
        self.open_dashboard_btn.setEnabled(False)
        self.open_json_btn.setEnabled(False)
        if hasattr(self, 'export_btn'):
            self.export_btn.setEnabled(False)

        mode_label = "QUICK" if mode == "Quick" else "FULL"
        self.status_label.setText(f"СТАТУС: {mode_label} SCAN…")
        self.status_dot.setStyleSheet(f"color: {ORANGE}; font-size: 9px;")
        self.status_detail.setText(f"{mode_label} scanning…")
        self.log_view.clear()
        self.stack.setCurrentWidget(self.log_view)
        self._switch_view(0)
        self.log_view.setPlainText(f"[ {mode_label} SCAN… ]\n")

        drives = list(self.selected_drives)
        self.append_log(f"[ TARGETS ] Диски: {', '.join(drives)}\n")

        self.worker = ScanWorker(
            SCRIPT_PATH,
            on_output=self.append_log,
            on_finished=self.scan_finished,
            on_error=self.scan_error,
            mode=mode,
            drives=drives,
        )
        self.worker.start()

    def append_log(self, text: str):
        self.log_view.moveCursor(QTextCursor.MoveOperation.End)
        self.log_view.insertPlainText(text)
        self.log_view.moveCursor(QTextCursor.MoveOperation.End)

    def scan_error(self, message: str):
        self.scan_btn.setEnabled(True)
        self.quick_btn.setEnabled(True)
        self.status_label.setText("СТАТУС: ОШИБКА")
        self.status_dot.setStyleSheet(f"color: {RED}; font-size: 9px;")
        self.status_detail.setText("Scan failed")
        QMessageBox.critical(
            self,
            "Ошибка",
            f"Не удалось запустить PowerShell:\n{message}\n\n"
            "Проверьте, что PowerShell доступен в PATH.",
        )

    def scan_finished(self, exit_code: int):
        self.scan_btn.setEnabled(True)
        self.quick_btn.setEnabled(True)

        # A PowerShell parser/runtime failure must never be interpreted as a LOW-risk scan.
        if int(exit_code) != 0:
            self.status_label.setText("СТАТУС: ОШИБКА СКАНИРОВАНИЯ")
            self.status_dot.setStyleSheet(f"color: {RED}; font-size: 9px;")
            self.status_detail.setText(f"PowerShell exit code {exit_code}")
            self.append_log(
                f"\n[ SCAN FAILED ] PowerShell завершился с кодом {exit_code}. "
                "Старый report.json не используется.\n"
            )
            QMessageBox.critical(
                self,
                "Сканирование не выполнено",
                f"PowerShell завершился с кодом {exit_code}.\n\n"
                "Результат этого запуска недействителен. "
                "Предыдущий отчёт не использовался и уведомление LOW не отправлялось.",
            )
            return

        report_path = self._find_latest_report()

        if not report_path:
            self.status_label.setText("СТАТУС: ОТЧЁТ НЕ НАЙДЕН")
            self.status_dot.setStyleSheet(f"color: {RED}; font-size: 9px;")
            self.status_detail.setText("Report not found")
            return


        try:
            raw = report_path.read_text(encoding="utf-8-sig")
            report = json.loads(raw)
            report_drives = report.get("selected_drives") or (report.get("scan") or {}).get("selected_drives") or []
            expected_drives = list(self.selected_drives)
            if expected_drives and report_drives:
                normalized_report = {str(x).upper().rstrip("\\") for x in report_drives}
                normalized_expected = {str(x).upper().rstrip("\\") for x in expected_drives}
                if not normalized_report or not normalized_report.issubset(normalized_expected):
                    raise RuntimeError(
                        "Отчёт содержит другой набор дисков: "
                        f"{', '.join(sorted(normalized_report)) or '—'}; ожидалось "
                        f"{', '.join(sorted(normalized_expected))}."
                    )
        except Exception as exc:
            self.status_label.setText("СТАТУС: ОШИБКА ЧТЕНИЯ")
            self.status_dot.setStyleSheet(f"color: {RED}; font-size: 9px;")
            self.status_detail.setText(str(exc))
            return

        # Keep UI responsive: Risk/VT/AI run in background thread
        self.scan_btn.setEnabled(False)
        self.quick_btn.setEnabled(False)
        self.status_label.setText("СТАТУС: АНАЛИЗ…")
        self.status_dot.setStyleSheet(f"color: {ORANGE}; font-size: 9px;")
        self.status_detail.setText("Snapshot → Risk → AI")
        self.append_log("\n[ ANALYZE ] Фоновый анализ (Risk / VT / AI)…\n")

        self._enrich_thread = ReportEnrichThread(report_path, report, self)
        self._enrich_thread.progress.connect(self._on_enrich_progress)
        self._enrich_thread.finished_ok.connect(self._on_enrich_ok)
        self._enrich_thread.finished_err.connect(self._on_enrich_err)
        self._enrich_thread.start()

    def _on_enrich_progress(self, msg: str) -> None:
        self.status_detail.setText(msg)
        self.append_log(f"[ ANALYZE ] {msg}\n")

    def _on_enrich_err(self, message: str) -> None:
        self.scan_btn.setEnabled(True)
        self.quick_btn.setEnabled(True)
        self.status_label.setText("СТАТУС: ОШИБКА АНАЛИЗА")
        self.status_dot.setStyleSheet(f"color: {RED}; font-size: 9px;")
        self.status_detail.setText(message[:120])
        self.append_log(f"\n[ ANALYZE FAIL ] {message}\n")

    def _on_enrich_ok(self, report: object, report_path: object) -> None:
        self.scan_btn.setEnabled(True)
        self.quick_btn.setEnabled(True)
        report_path = Path(str(report_path))
        if not isinstance(report, dict):
            self._on_enrich_err("invalid report")
            return

        self.latest_report_path = report_path

        computer = report.get("computer") or {}
        meta = report.get("meta") or {}
        scan = report.get("scan") or {}
        self.computer_label.setText(str(computer.get("name") or "—"))
        self.last_scan_label.setText(str(meta.get("generated_at") or scan.get("timestamp") or "—"))
        dur = meta.get("duration_sec") or scan.get("duration_sec")
        self.duration_label.setText(f"{dur} сек" if dur is not None else "—")
        files = meta.get("files_scanned") or scan.get("files_scanned") or 0
        self.files_label.setText(f"{int(files):,}".replace(",", " "))

        try:
            dashboard = generate_dashboard(report, report_path)
            self.latest_dashboard_path = dashboard

            self.open_dashboard_btn.setEnabled(True)
            self.open_json_btn.setEnabled(True)
            self.export_btn.setEnabled(True)

            try:
                from core.export_report import export_report as _export_report
                _export_report(report)
            except Exception as ex:
                self.append_log(f"[ EXPORT ] auto: {ex}\n")

            self.report_view.setHtml(format_report_preview(report))
            self.stack.setCurrentWidget(self.report_view)
            self._switch_view(1)

            self.status_label.setText("СТАТУС: ГОТОВ")
            self.status_dot.setStyleSheet(f"color: {GREEN}; font-size: 9px;")
            risk = ((report.get("risk_summary") or {}).get("overall_risk") or "—")
            self.status_detail.setText(f"Risk {risk} · {dashboard.name}")
            self.append_log(
                f"\n[ DONE ] Risk: {risk}\n"
                f"[ DONE ] Dashboard готов — нажмите ОТКРЫТЬ DASHBOARD\n"
            )
            self._dispatch_security_alert(report)
        except Exception as exc:
            self.status_label.setText("СТАТУС: ОШИБКА DASHBOARD")
            self.status_dot.setStyleSheet(f"color: {RED}; font-size: 9px;")
            self.status_detail.setText("Dashboard generation failed")
            self.stack.setCurrentWidget(self.report_view)
            self.report_view.setHtml(
                f"""
                <div style="color:#FF3B30;padding:30px;">
                    <span style="font-size:12px;">[ DASHBOARD ERROR ]</span><br>
                    {exc}
                </div>
                """
            )


    def _find_latest_report(self) -> Path | None:
        fixed = REPORT_DIR / "report.json"
        if fixed.exists():
            return fixed
        files = glob.glob(str(REPORT_DIR / "Report_*.json"))
        if not files:
            return None
        return Path(max(files, key=os.path.getmtime))



    def open_settings(self) -> None:
        """Dialog: optional AI / VirusTotal API keys (stored in local settings.json)."""
        data = load_settings()
        dlg = QDialog(self)
        dlg.setWindowTitle("Miharu — настройки")
        dlg.setMinimumWidth(460)
        dlg.setStyleSheet(
            f"""
            QDialog {{ background: {BG}; color: {TEXT}; }}
            QLabel {{ color: {TEXT_MUTED}; font-size: 12px; }}
            QLineEdit {{
                background: #121214; color: {TEXT};
                border: 1px solid {BORDER}; border-radius: 8px;
                padding: 8px 10px; font-size: 12px;
            }}
            QLineEdit:focus {{ border-color: {RED}; }}
            """
        )
        layout = QVBoxLayout(dlg)
        layout.setContentsMargins(20, 18, 20, 16)
        layout.setSpacing(12)

        title = QLabel("API-ключи (только на этом ПК)")
        title.setStyleSheet(f"color: {TEXT}; font-size: 14px; font-weight: 700;")
        layout.addWidget(title)
        hint = QLabel(
            "Пустое поле = не менять. Один пробел = очистить ключ.\n"
            "Ключи не уходят в Telegram и не в git. Telegram-бот настраивается кнопкой TELEGRAM."
        )
        hint.setWordWrap(True)
        layout.addWidget(hint)

        form = QFormLayout()
        form.setSpacing(10)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)

        def field(key: str) -> QLineEdit:
            edit = QLineEdit()
            edit.setEchoMode(QLineEdit.EchoMode.Password)
            edit.setPlaceholderText("не задан" if not str(data.get(key) or "").strip() else "••••••••  (задан)")
            edit.setMinimumWidth(280)
            return edit

        ed_mistral = field("mistral_api_key")
        ed_nvidia = field("nvidia_api_key")
        ed_vt = field("vt_api_key")
        form.addRow("Mistral", ed_mistral)
        form.addRow("NVIDIA", ed_nvidia)
        form.addRow("VirusTotal", ed_vt)
        layout.addLayout(form)

        tg = QLabel(
            f"Telegram bot: {'задан' if telegram_token() else 'нет'} · "
            f"chat: {telegram_chat_id() or 'не привязан'}"
        )
        tg.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px;")
        layout.addWidget(tg)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Save).setText("Сохранить")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("Отмена")
        buttons.rejected.connect(dlg.reject)

        def on_save() -> None:
            update: dict = {}
            mapping = (
                ("mistral_api_key", ed_mistral),
                ("nvidia_api_key", ed_nvidia),
                ("vt_api_key", ed_vt),
            )
            for key, edit in mapping:
                raw = edit.text()
                if raw == "":
                    continue
                if raw.strip() == "":
                    update[key] = ""
                else:
                    update[key] = raw.strip()
            if update:
                save_settings(update)
                self.append_log(
                    "\n[ SETTINGS ] Ключи обновлены: "
                    + ", ".join(update.keys())
                    + "\n"
                )
            dlg.accept()

        buttons.accepted.connect(on_save)
        layout.addWidget(buttons)
        dlg.exec()



    def _dispatch_security_alert(self, report: dict) -> None:
        """Telegram / backend summary — never block UI."""
        try:
            mode = notification_mode()
            if mode == "off":
                return
            if mode == "direct":
                if not telegram_token() or not telegram_chat_id():
                    self.append_log("[ TELEGRAM ] нет token/chat — сводка не отправлена\n")
                    return
                self.append_log("[ TELEGRAM ] отправка сводки…\n")

                def _done(ok: bool, msg: str) -> None:
                    self.append_log(f"[ TELEGRAM ] {msg}\n")

                send_summary_async(report, on_done=_done)
                return
            if mode == "backend":
                try:
                    from notifications.telegram_alerts import build_summary

                    mgr = NotificationManager(BackendNotificationProvider())
                    msg = build_summary(report)
                    mgr.send_async(msg)
                    self.append_log("[ BACKEND ] уведомление поставлено в очередь\n")
                except Exception as exc:
                    self.append_log(f"[ BACKEND ] {exc}\n")
        except Exception as exc:
            self.append_log(f"[ NOTIFY ] {exc}\n")

    def _refresh_telegram_btn(self) -> None:
        if is_configured():
            self.telegram_btn.setText("TELEGRAM ✓")
            self.telegram_btn.setToolTip(f"Привязан chat_id={telegram_chat_id()}")
            if getattr(self, "side_tg", None) is not None:
                self.side_tg.setText("  Telegram: ON")
                self.side_tg.setStyleSheet(f"color: {GREEN}; font-size: 11px; padding: 4px 16px;")
        elif telegram_token():
            self.telegram_btn.setText("TELEGRAM")
            self.telegram_btn.setToolTip("Токен есть — нажмите, чтобы привязать чат")
            if getattr(self, "side_tg", None) is not None:
                self.side_tg.setText("  Telegram: нет chat")
                self.side_tg.setStyleSheet(f"color: {ORANGE}; font-size: 11px; padding: 4px 16px;")
        else:
            self.telegram_btn.setText("TELEGRAM")
            self.telegram_btn.setToolTip("Нет bot token — пересоберите Setup с secrets/product_defaults.json")
            if getattr(self, "side_tg", None) is not None:
                self.side_tg.setText("  Telegram: OFF")
                self.side_tg.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px; padding: 4px 16px;")

    def link_telegram(self) -> None:
        if not telegram_token():
            QMessageBox.warning(
                self,
                "Telegram",
                "Bot token не задан.\n\n"
                "Офисная сборка: переустановите Miharu-Setup,\n"
                "собранный с secrets/product_defaults.json.\n\n"
                "Вручную: settings.json → telegram_bot_token",
            )
            return

        if is_configured():
            ret = QMessageBox.question(
                self,
                "Telegram",
                f"Уже привязан chat_id={telegram_chat_id()}.\nПривязать заново?",
            )
            if ret != QMessageBox.StandardButton.Yes:
                return

        self.telegram_btn.setEnabled(False)
        self.append_log("\n[ TELEGRAM ] Привязка чата…\n")
        try:
            payload = get_installation_id()[:16]
            url = deep_link(start_payload=payload)
            self.append_log(f"[ TELEGRAM ] Откройте: {url}\n")
            self.append_log("[ TELEGRAM ] В боте нажмите Start.\n")
            os.startfile(url)
        except Exception as exc:
            self.append_log(f"[ TELEGRAM ] deep link: {exc}\n")
            payload = None

        def on_status(msg: str) -> None:
            self.append_log(f"[ TELEGRAM ] {msg}\n")

        def on_done(ok: bool, msg: str) -> None:
            self.telegram_btn.setEnabled(True)
            self._refresh_telegram_btn()
            self.append_log(f"[ TELEGRAM ] {msg}\n")
            if ok:
                QMessageBox.information(self, "Telegram", "Чат успешно привязан.")
            else:
                QMessageBox.warning(self, "Telegram", msg)

        link_chat_id_async(
            timeout_sec=120,
            start_payload=payload,
            on_status=on_status,
            on_done=on_done,
        )


    def _refresh_monitor_btn(self) -> None:
        on = monitor_enabled() or scheduled_task_exists()
        hours = monitor_interval_hours()
        if on:
            eta = next_run_eta() or f"каждые {hours} ч"
            self.monitor_btn.setText("MONITOR ✓")
            self.monitor_btn.setToolTip(f"Включён · {eta}")
            if getattr(self, "status_detail", None) is not None:
                self.status_detail.setText(f"Monitor: {eta}")
            if getattr(self, "side_mon", None) is not None:
                self.side_mon.setText(f"  Monitor: {eta}")
                self.side_mon.setStyleSheet(f"color: {GREEN}; font-size: 11px; padding: 4px 16px;")
        else:
            self.monitor_btn.setText("MONITOR")
            self.monitor_btn.setToolTip(f"Выключен · интервал {hours} ч")
            if getattr(self, "side_mon", None) is not None:
                self.side_mon.setText(f"  Monitor: OFF · {hours}ч")
                self.side_mon.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px; padding: 4px 16px;")

    def toggle_monitor(self) -> None:
        try:
            if monitor_enabled() or scheduled_task_exists():
                msg = unregister_scheduled_task()
                self.append_log(f"\n[ MONITOR ] Выключен. {msg}\n")
                QMessageBox.information(self, "Monitor", "Фоновый мониторинг выключен.")
            else:
                hours = monitor_interval_hours()
                msg = register_scheduled_task(hours)
                self.append_log(f"\n[ MONITOR ] Включён (каждые {hours} ч).\n{msg}\n")
                QMessageBox.information(
                    self,
                    "Monitor",
                    f"Фоновый мониторинг включён.\n"
                    f"Интервал: каждые {hours} ч (Quick-скан).\n"
                    f"Алерты: только HIGH / новая persistence.",
                )
        except Exception as exc:
            self.append_log(f"\n[ MONITOR ] Ошибка: {exc}\n")
            QMessageBox.warning(self, "Monitor", str(exc))
        self._refresh_monitor_btn()

    def open_dashboard(self):
        if not self.latest_dashboard_path or not self.latest_dashboard_path.exists():
            return
        os.startfile(str(self.latest_dashboard_path))

    def open_json(self):
        if not self.latest_report_path or not self.latest_report_path.exists():
            return
        os.startfile(str(self.latest_report_path))

    def export_report_files(self):
        """Shareable HTML + TXT into Reports folder."""
        try:
            report = None
            path = self.latest_report_path
            if path and path.exists():
                import json
                report = json.loads(path.read_text(encoding="utf-8-sig"))
            if not report:
                QMessageBox.information(self, "Экспорт", "Нет отчёта для экспорта. Сначала выполните скан.")
                return
            from core.export_report import export_report
            paths = export_report(report)
            self.append_log(f"[ EXPORT ] HTML: {paths['html']}\n")
            self.append_log(f"[ EXPORT ] TXT:  {paths['txt']}\n")
            self.status_detail.setText(f"Экспорт: {paths['html'].name}")
            os.startfile(str(paths["html"]))
        except Exception as exc:
            self.append_log(f"[ EXPORT ] error: {exc}\n")
            QMessageBox.warning(self, "Экспорт", str(exc))


    def open_report_folder(self):
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        os.startfile(str(REPORT_DIR))