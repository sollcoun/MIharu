from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable

from config import (
    APP_DATA_DIR,
    HISTORY_DIR,
    LOG_DIR,
    REPORT_DIR,
    SCRIPT_PATH,
    ensure_app_dirs,
    load_settings,
    save_settings,
)

TASK_NAME = "DiskDiagnostic\\BackgroundMonitor"
DEFAULT_INTERVAL_HOURS = 6


def monitor_enabled() -> bool:
    return bool(load_settings().get("monitor_enabled"))


def monitor_interval_hours() -> int:
    try:
        h = int(load_settings().get("monitor_interval_hours") or DEFAULT_INTERVAL_HOURS)
    except (TypeError, ValueError):
        h = DEFAULT_INTERVAL_HOURS
    return max(1, min(h, 168))


def monitor_mode() -> str:
    mode = str(load_settings().get("monitor_mode") or "Quick").strip()
    return mode if mode in ("Quick", "Full") else "Quick"


def set_monitor_settings(
    *,
    enabled: bool | None = None,
    interval_hours: int | None = None,
    mode: str | None = None,
) -> dict:
    update: dict[str, Any] = {}
    if enabled is not None:
        update["monitor_enabled"] = bool(enabled)
    if interval_hours is not None:
        update["monitor_interval_hours"] = max(1, min(int(interval_hours), 168))
    if mode is not None and mode in ("Quick", "Full"):
        update["monitor_mode"] = mode
    return save_settings(update)


def _log(msg: str) -> None:
    try:
        from core.app_log import get_logger
        get_logger("monitor").info("%s", msg)
    except Exception:
        ensure_app_dirs()
        try:
            with (LOG_DIR / "monitor.log").open("a", encoding="utf-8") as f:
                f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")
        except OSError:
            pass


def run_powershell_scan(mode: str = "Quick", drives: list[str] | None = None, timeout_sec: int = 3600) -> tuple[int, str]:
    ensure_app_dirs()
    if not SCRIPT_PATH.exists():
        raise FileNotFoundError(f"Script not found: {SCRIPT_PATH}")
    env = os.environ.copy()
    env["DISK_DIAGNOSTIC_DATA_DIR"] = str(APP_DATA_DIR)
    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(SCRIPT_PATH),
        "-Mode",
        mode,
    ]
    selected = drives if drives is not None else load_settings().get("selected_drives")
    if isinstance(selected, list) and selected:
        cmd.extend(["-Drives", ",".join(str(d) for d in selected)])
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        timeout=timeout_sec,
    )
    out = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode, out


def _latest_report() -> Path | None:
    fixed = REPORT_DIR / "report.json"
    if fixed.exists():
        return fixed
    files = list(REPORT_DIR.glob("Report_*.json"))
    if not files:
        return None
    return max(files, key=lambda p: p.stat().st_mtime)


def process_report(report: dict) -> dict:
    from core.ai_explain import enrich_with_ai
    from core.hash_vt import enrich_hashes_and_vt
    from core.risk_engine import enrich_report
    from core.snapshot import apply_snapshot_pipeline

    report = apply_snapshot_pipeline(report)
    report = enrich_hashes_and_vt(report)
    report = enrich_report(report)
    report = enrich_with_ai(report)
    return report


def _count_list(value) -> int:
    if isinstance(value, list):
        return len(value)
    return 0


_BENIGN_STARTUP_NAMES = {
    "ollama.lnk",
    "desktop.ini",
    "ccleaner.lnk",
    "onedrive.lnk",
    "dropbox.lnk",
    "steam.lnk",
    "discord.lnk",
    "telegram.lnk",
    "slack.lnk",
    "docker desktop.lnk",
}


def _startup_path(item) -> str:
    if isinstance(item, str):
        return item.replace("/", "\\").lower()
    if isinstance(item, dict):
        return str(
            item.get("path")
            or item.get("Path")
            or item.get("name")
            or item.get("Name")
            or ""
        ).replace("/", "\\").lower()
    return ""


def _is_benign_startup(item) -> bool:
    path = _startup_path(item)
    if not path:
        return True
    name = path.rsplit("\\", 1)[-1]
    if name in _BENIGN_STARTUP_NAMES:
        return True
    if name == "desktop.ini":
        return True
    # plain shortcut of a well-known app name
    stem = name[:-4] if name.endswith(".lnk") else name
    if stem in ("ollama", "docker desktop", "onedrive", "dropbox", "steam", "discord"):
        return True
    return False


def _count_actionable_persistence(changes: dict) -> tuple[int, list[str]]:
    reasons: list[str] = []
    n = 0

    ar = _count_list(changes.get("new_autorun"))
    if ar:
        n += ar
        reasons.append(f"autorun x{ar}")

    svc = _count_list(changes.get("new_services"))
    if svc:
        n += svc
        reasons.append(f"services x{svc}")

    tasks = _count_list(changes.get("new_scheduled_tasks"))
    if tasks:
        n += tasks
        reasons.append(f"tasks x{tasks}")

    startup_items = changes.get("new_startup") or []
    if not isinstance(startup_items, list):
        startup_items = []
    actionable = [x for x in startup_items if not _is_benign_startup(x)]
    if actionable:
        n += len(actionable)
        reasons.append(f"startup x{len(actionable)}")

    return n, reasons


def needs_deep_scan(report: dict) -> tuple[bool, str]:
    """Decide if Quick result warrants a Full follow-up scan."""
    summary = report.get("risk_summary") or {}
    overall = str(summary.get("overall_risk") or "LOW").upper()
    counts = summary.get("counts") or {}
    high = int(counts.get("HIGH") or 0)
    med = int(counts.get("MEDIUM") or 0)
    changes = report.get("changes") or {}

    if overall == "HIGH" or high > 0:
        return True, f"HIGH risk (high={high})"

    persist, reasons = _count_actionable_persistence(changes)
    if persist > 0:
        return True, "new persistence: " + ", ".join(reasons)

    suspicious = _count_list(changes.get("new_suspicious_files"))
    if suspicious >= 5:
        return True, f"new suspicious files x{suspicious}"

    if overall == "MEDIUM" and med >= 3:
        return True, f"MEDIUM density (med={med})"

    return False, "no deep trigger"


def smart_monitor_enabled() -> bool:
    settings = load_settings()
    if "monitor_smart" in settings:
        return bool(settings.get("monitor_smart"))
    return True


def dispatch_monitor_alerts(report: dict) -> str:
    """Background: only HIGH / new persistence, not full summary spam."""
    from config import notification_mode
    from notifications.telegram_alerts import (
        DirectTelegramProvider,
        finalize_alert,
        is_configured,
        prepare_alert,
    )

    mode = notification_mode()
    message, delta = prepare_alert(report)
    if not message:
        return "no new HIGH/persistence events"

    if mode == "backend":
        from notifications.backend_notifications import BackendNotificationProvider
        from notifications.notifications import NotificationManager

        try:
            provider = BackendNotificationProvider()
        except Exception as exc:
            return f"backend not configured: {exc}"
        try:
            provider.send(message)
            finalize_alert(delta, True)
            return "backend: sent"
        except Exception as exc:
            finalize_alert(delta, False)
            return f"backend error: {exc}"

    if mode == "direct" or is_configured():
        try:
            DirectTelegramProvider().send(message)
            finalize_alert(delta, True)
            return "telegram: alert sent"
        except Exception as exc:
            finalize_alert(delta, False)
            return f"telegram error: {exc}"

    return "alerts channel not configured"


def run_monitor_once(
    *,
    mode: str | None = None,
    generate_html: bool = True,
    on_log: Callable[[str], None] | None = None,
    force_full: bool = False,
) -> dict[str, Any]:
    """Headless cycle: Quick first, Full only if Risk/changes demand it."""
    preferred = mode or monitor_mode()
    smart = smart_monitor_enabled() and not force_full
    # Smart path always starts Quick; explicit Full only if smart off or forced
    phase1 = "Quick" if smart else preferred
    if force_full:
        phase1 = "Full"
    selected_drives = load_settings().get("selected_drives")
    started = time.time()
    result: dict[str, Any] = {
        "ok": False,
        "mode": phase1,
        "phases": [phase1],
        "deep_reason": None,
        "selected_drives": selected_drives if isinstance(selected_drives, list) else None,
        "report_path": None,
        "dashboard_path": None,
        "alert": None,
        "overall_risk": None,
        "duration_sec": None,
        "error": None,
    }

    def log(msg: str) -> None:
        _log(msg)
        if on_log:
            on_log(msg)

    def run_phase(scan_mode: str) -> dict:
        log(f"monitor phase mode={scan_mode}")
        code, output = run_powershell_scan(mode=scan_mode, drives=selected_drives)
        for line in (output or "").splitlines()[-15:]:
            log(f"ps: {line}")
        if code != 0:
            raise RuntimeError(f"powershell exit {code}")
        path = _latest_report()
        if not path:
            raise FileNotFoundError("report.json not found")
        report = json.loads(path.read_text(encoding="utf-8-sig"))
        report = process_report(report)
        path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        return {"path": path, "report": report}

    try:
        log(f"monitor start smart={smart} preferred={preferred}")
        phase = run_phase(phase1)
        path = phase["path"]
        report = phase["report"]
        result["report_path"] = str(path)
        result["overall_risk"] = (report.get("risk_summary") or {}).get("overall_risk")

        if smart and phase1 == "Quick":
            deep, reason = needs_deep_scan(report)
            if deep:
                log(f"deep trigger: {reason} → Full")
                result["deep_reason"] = reason
                result["phases"].append("Full")
                result["mode"] = "Quick→Full"
                phase = run_phase("Full")
                path = phase["path"]
                report = phase["report"]
                result["report_path"] = str(path)
                result["overall_risk"] = (report.get("risk_summary") or {}).get("overall_risk")
            else:
                log(f"deep skip: {reason}")
                result["deep_reason"] = reason

        if generate_html:
            try:
                from ui.dashboard import generate_dashboard

                dash = generate_dashboard(report, path)
                result["dashboard_path"] = str(dash)
            except Exception as exc:
                log(f"dashboard error: {exc}")

        alert_msg = dispatch_monitor_alerts(report)
        result["alert"] = alert_msg
        log(f"alert: {alert_msg}")

        save_settings({
            "monitor_last_run": datetime.now().isoformat(timespec="seconds"),
            "monitor_last_mode": result["mode"],
            "monitor_last_risk": result["overall_risk"],
        })
        result["ok"] = True
        result["duration_sec"] = round(time.time() - started, 1)
        log(
            f"monitor done risk={result['overall_risk']} "
            f"mode={result['mode']} {result['duration_sec']}s"
        )
        return result
    except Exception as exc:
        result["error"] = str(exc)
        log(f"monitor failed: {exc}")
        return result


def next_run_eta() -> str | None:
    settings = load_settings()
    last = settings.get("monitor_last_run")
    if not monitor_enabled():
        return None
    hours = monitor_interval_hours()
    if not last:
        return f"каждые {hours} ч (ещё не запускался)"
    try:
        dt = datetime.fromisoformat(str(last))
        nxt = dt + timedelta(hours=hours)
        delta = nxt - datetime.now()
        if delta.total_seconds() <= 0:
            return "скоро / просрочен"
        h = int(delta.total_seconds() // 3600)
        m = int((delta.total_seconds() % 3600) // 60)
        return f"через {h:02d}:{m:02d}"
    except ValueError:
        return f"каждые {hours} ч"


def _pythonw() -> str:
    exe = Path(sys.executable)
    if exe.name.lower() == "python.exe":
        candidate = exe.with_name("pythonw.exe")
        if candidate.exists():
            return str(candidate)
    return str(exe)


def _runner_command() -> str:
    """Return the Task Scheduler command for the current runtime."""
    if getattr(sys, "frozen", False):
        exe = Path(sys.executable)
        if not exe.exists():
            raise FileNotFoundError(f"Application executable not found: {exe}")
        return f'"{exe}" --monitor'

    runner = Path(__file__).resolve().parent.parent / "run.py"
    py = _pythonw()
    return f'"{py}" "{runner}" --monitor'


def register_scheduled_task(interval_hours: int | None = None) -> str:
    """Register Windows Task Scheduler job. Returns status message."""
    hours = interval_hours or monitor_interval_hours()
    tr = _runner_command()
    # HOURLY with /MO N
    cmd = [
        "schtasks",
        "/Create",
        "/TN",
        TASK_NAME,
        "/TR",
        tr,
        "/SC",
        "HOURLY",
        "/MO",
        str(hours),
        "/RL",
        "LIMITED",
        "/F",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    out = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        raise RuntimeError(out.strip() or f"schtasks exit {proc.returncode}")
    set_monitor_settings(enabled=True, interval_hours=hours)
    _log(f"scheduled task registered every {hours}h")
    return out.strip() or f"Task registered: every {hours}h"


def unregister_scheduled_task() -> str:
    cmd = ["schtasks", "/Delete", "/TN", TASK_NAME, "/F"]
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    set_monitor_settings(enabled=False)
    _log("scheduled task removed")
    out = (proc.stdout or "") + (proc.stderr or "")
    return out.strip() or "Task removed"


def scheduled_task_exists() -> bool:
    proc = subprocess.run(
        ["schtasks", "/Query", "/TN", TASK_NAME],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return proc.returncode == 0