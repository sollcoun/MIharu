"""Генерация HTML-дашборда — стиль как на референсе."""

from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path
from typing import Any, overload

from config import HISTORY_DIR, REPORT_DIR
from core.risk_engine import enrich_report
from core.snapshot import diff_snapshots, list_snapshots, load_snapshot


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _esc(value) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


@overload
def _num(value, default: float = ...) -> float: ...


@overload
def _num(value, default: None) -> float | None: ...


def _num(value, default: Any = 0.0) -> Any:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _fmt_gb(value) -> str:
    n = _num(value)
    return f"{n:.1f} GB"


def _fmt_int(value) -> str:
    try:
        return f"{int(float(value)):,}".replace(",", " ")
    except (TypeError, ValueError):
        return "0"


def _health_score(report: dict) -> tuple[int, str, str, list[tuple[str, str]]]:
    disks = report.get("disks") or {}
    defender = report.get("defender") or {}
    summary = report.get("risk_summary") or {}
    counts = summary.get("counts") or {}
    high_n = int(counts.get("HIGH") or 0)
    med_n = int(counts.get("MEDIUM") or 0)

    score = 100
    worst_pct = 0.0
    for d in disks.values():
        if isinstance(d, dict):
            worst_pct = max(worst_pct, _num(d.get("UsedPct")))

    if worst_pct >= 95:
        score -= 30
    elif worst_pct >= 90:
        score -= 20
    elif worst_pct >= 80:
        score -= 10

    score -= min(30, high_n * 10)
    score -= min(15, med_n * 3)

    if defender and not defender.get("RealTime"):
        score -= 15
    if defender and _num(defender.get("SignatureAge")) > 7:
        score -= 10

    overall = str(summary.get("overall_risk") or "").upper()
    if overall == "HIGH":
        score -= 10
    score = max(0, min(100, int(score)))

    checks = []
    if defender and defender.get("Enabled"):
        checks.append(("ok", "Защита включена"))
    else:
        checks.append(("bad", "Защита выключена"))

    if high_n == 0:
        checks.append(("ok", "Критических проблем нет"))
    else:
        checks.append(("warn", f"{high_n} объектов высокого риска"))

    if worst_pct >= 90:
        checks.append(("warn", "Требуется внимание к диску"))
    elif worst_pct >= 80:
        checks.append(("warn", "Диск заполнен >80%"))
    else:
        checks.append(("ok", "Место на дисках в норме"))

    if score >= 80:
        return score, "ХОРОШО", "good", checks
    if score >= 55:
        return score, "ВНИМАНИЕ", "warn", checks
    return score, "ПЛОХО", "bad", checks


def _risk_level(report: dict) -> tuple[str, str, str, list[tuple[str, str]]]:
    changes = report.get("changes") or {}
    summary = report.get("risk_summary") or {}
    new_sus = changes.get("new_suspicious_files") or []
    new_autorun = changes.get("new_autorun") or []
    new_unsigned = changes.get("new_unsigned_processes") or []
    new_tasks = changes.get("new_scheduled_tasks") or []

    counts = summary.get("counts") or {}
    high_n = counts.get("HIGH", 0)
    med_n = counts.get("MEDIUM", 0)

    checks = [
        ("warn" if new_unsigned else "ok", f"{len(new_unsigned)} новых процессов"),
        ("ok" if not new_autorun else "warn", f"{len(new_autorun)} новых автозагрузок"),
        ("ok" if not new_tasks else "warn", f"{len(new_tasks)} новых задач"),
        ("warn" if (new_sus or high_n or med_n) else "ok",
         f"{high_n + med_n} объектов требует проверки" if (high_n or med_n) else f"{len(new_sus)} файлов требует проверки"),
    ]

    overall = str(summary.get("overall_risk") or "").upper()
    if overall == "HIGH":
        return "HIGH", "Высокий риск", "bad", checks
    if overall == "MEDIUM":
        return "MED", "Средний риск", "warn", checks
    if overall == "LOW":
        return "LOW", "Низкий риск", "good", checks

    if high_n:
        return "HIGH", "Высокий риск", "bad", checks
    if med_n:
        return "MED", "Средний риск", "warn", checks
    return "LOW", "Низкий риск", "good", checks


def _disk_svg_ring(pct: float, color: str, size: int = 110) -> str:
    r = (size - 16) / 2
    circ = 2 * 3.14159 * r
    offset = circ * (1 - max(0, min(100, pct)) / 100)
    return f"""
    <svg width="{size}" height="{size}" viewBox="0 0 {size} {size}">
      <circle cx="{size/2}" cy="{size/2}" r="{r}" fill="none"
              stroke="#1F1F24" stroke-width="10"/>
      <circle cx="{size/2}" cy="{size/2}" r="{r}" fill="none"
              stroke="{color}" stroke-width="10"
              stroke-linecap="round"
              stroke-dasharray="{circ:.1f}"
              stroke-dashoffset="{offset:.1f}"
              transform="rotate(-90 {size/2} {size/2})"/>
      <text x="50%" y="48%" text-anchor="middle" dominant-baseline="central"
            fill="#E8E8EC" font-size="22" font-weight="700" font-family="Segoe UI,sans-serif">
        {int(pct)}%
      </text>
      <text x="50%" y="64%" text-anchor="middle" dominant-baseline="central"
            fill="#8A8A92" font-size="9" font-family="Segoe UI,sans-serif">
        ЗАНЯТО
      </text>
    </svg>
    """


def _health_svg_ring(score: int, color: str) -> str:
    size = 120
    r = (size - 16) / 2
    circ = 2 * 3.14159 * r
    offset = circ * (1 - score / 100)
    return f"""
    <svg width="{size}" height="{size}" viewBox="0 0 {size} {size}">
      <circle cx="{size/2}" cy="{size/2}" r="{r}" fill="none"
              stroke="#1F1F24" stroke-width="10"/>
      <circle cx="{size/2}" cy="{size/2}" r="{r}" fill="none"
              stroke="{color}" stroke-width="10"
              stroke-linecap="round"
              stroke-dasharray="{circ:.1f}"
              stroke-dashoffset="{offset:.1f}"
              transform="rotate(-90 {size/2} {size/2})"/>
      <text x="50%" y="46%" text-anchor="middle" dominant-baseline="central"
            fill="#E8E8EC" font-size="28" font-weight="700" font-family="Segoe UI,sans-serif">
        {score}
      </text>
      <text x="50%" y="62%" text-anchor="middle" dominant-baseline="central"
            fill="#8A8A92" font-size="10" font-family="Segoe UI,sans-serif">
        /100
      </text>
    </svg>
    """


def _risk_svg_ring(label: str, color: str) -> str:
    size = 120
    r = (size - 16) / 2
    circ = 2 * 3.14159 * r
    # visual fill based on label
    pct = 15 if label == "LOW" else (45 if label == "MED" else 85)
    offset = circ * (1 - pct / 100)
    return f"""
    <svg width="{size}" height="{size}" viewBox="0 0 {size} {size}">
      <circle cx="{size/2}" cy="{size/2}" r="{r}" fill="none"
              stroke="#1F1F24" stroke-width="10"/>
      <circle cx="{size/2}" cy="{size/2}" r="{r}" fill="none"
              stroke="{color}" stroke-width="10"
              stroke-linecap="round"
              stroke-dasharray="{circ:.1f}"
              stroke-dashoffset="{offset:.1f}"
              transform="rotate(-90 {size/2} {size/2})"/>
      <text x="50%" y="46%" text-anchor="middle" dominant-baseline="central"
            fill="#E8E8EC" font-size="20" font-weight="700" font-family="Segoe UI,sans-serif">
        {label}
      </text>
      <text x="50%" y="62%" text-anchor="middle" dominant-baseline="central"
            fill="#8A8A92" font-size="9" font-family="Segoe UI,sans-serif">
        RISK
      </text>
    </svg>
    """


def _sparkline_svg(points: list[float], width: int = 280, height: int = 48) -> str:
    if len(points) < 2:
        return f'<div class="empty-spark">Недостаточно данных для графика</div>'
    mn, mx = min(points), max(points)
    span = max(mx - mn, 0.1)
    pad = 4
    coords = []
    for i, v in enumerate(points):
        x = pad + i * (width - 2 * pad) / (len(points) - 1)
        y = height - pad - (v - mn) / span * (height - 2 * pad)
        coords.append(f"{x:.1f},{y:.1f}")
    poly = " ".join(coords)
    # area fill
    area = f"{pad},{height - pad} " + poly + f" {width - pad},{height - pad}"
    return f"""
    <svg width="100%" height="{height}" viewBox="0 0 {width} {height}" preserveAspectRatio="none">
      <polygon points="{area}" fill="rgba(227,27,35,0.12)"/>
      <polyline points="{poly}" fill="none" stroke="#E31B23" stroke-width="2"
                stroke-linejoin="round" stroke-linecap="round"/>
    </svg>
    """


def _check_icon(kind: str) -> str:
    if kind == "ok":
        return '<span class="dot ok">●</span>'
    if kind == "warn":
        return '<span class="dot warn">▲</span>'
    return '<span class="dot bad">●</span>'


def _history_data(report: dict, limit: int = 30) -> dict:
    """Build a stable, presentation-ready history model from stored snapshots."""
    files = list_snapshots(HISTORY_DIR)
    if not files:
        return {"scans": [], "events": [], "chart": []}

    snapshots = []
    for path in files[-limit:]:
        snap = load_snapshot(path)
        if isinstance(snap, dict) and snap.get("timestamp"):
            snapshots.append(snap)
    snapshots.sort(key=lambda x: str(x.get("timestamp") or ""))

    scans = []
    events = []
    previous = None
    for snap in snapshots:
        diff = diff_snapshots(snap, previous)
        storage = snap.get("storage") or {}
        disks = storage.get("disks") or {}
        c = disks.get("C") or disks.get("c") or {}
        used = _num(c.get("UsedGB"))
        total = _num(c.get("TotalGB"))
        pct = _num(c.get("UsedPct"))
        if not pct and total:
            pct = used / total * 100

        categories = {
            "processes": len(diff.get("new_unsigned_processes") or []),
            "autoruns": len(diff.get("new_autorun") or []),
            "services": len(diff.get("new_services") or []),
            "tasks": len(diff.get("new_scheduled_tasks") or []),
            "files": len(diff.get("new_suspicious_files") or []),
            "startup": len(diff.get("new_startup") or []),
            "disk": len(diff.get("folder_deltas") or []) + len(diff.get("disk_deltas") or []),
        }
        added = sum(categories.values())
        removed = (
            len(diff.get("removed_unsigned_processes") or [])
            + len(diff.get("removed_autorun") or [])
            + len(diff.get("removed_services") or [])
            + len(diff.get("removed_scheduled_tasks") or [])
            + len(diff.get("removed_suspicious_files") or [])
        )

        scored = (snap.get("security") or {}).get("scored_files") or []
        max_score = 0
        max_risk = "LOW"
        for item in scored:
            if not isinstance(item, dict):
                continue
            score = int(_num(item.get("score")))
            if score > max_score:
                max_score = score
                max_risk = str(item.get("risk") or "LOW").upper()
        if diff.get("new_suspicious_files") and max_risk == "LOW":
            max_risk = "MEDIUM"
        security_added = (
            categories["processes"]
            + categories["autoruns"]
            + categories["services"]
            + categories["tasks"]
            + categories["files"]
            + categories["startup"]
        )
        if diff.get("baseline"):
            severity = "INFO"
        elif max_risk == "HIGH":
            severity = "HIGH"
        elif max_risk == "MEDIUM" or security_added > 0:
            severity = "MEDIUM"
        else:
            severity = "INFO"

        ts = str(snap.get("timestamp") or "—")
        scans.append({
            "timestamp": ts, "used_gb": used, "total_gb": total, "used_pct": pct,
            "added": added, "removed": removed, "categories": categories,
            "severity": severity, "risk": max_risk, "score": max_score,
            "baseline": bool(diff.get("baseline")), "summary": str(diff.get("summary") or ""),
        })

        if diff.get("baseline"):
            events.append({"timestamp": ts, "severity": "INFO", "title": "Создан базовый снимок", "detail": "История мониторинга начата.", "count": 0})
        else:
            event_specs = [
                ("HIGH" if max_risk == "HIGH" else "MEDIUM", len(diff.get("new_suspicious_files") or []), "Новые подозрительные файлы"),
                ("MEDIUM", len(diff.get("new_autorun") or []), "Новые автозагрузки"),
                ("MEDIUM", len(diff.get("new_scheduled_tasks") or []), "Новые задачи планировщика"),
                ("MEDIUM", len(diff.get("new_services") or []), "Новые службы"),
                ("MEDIUM", len(diff.get("new_unsigned_processes") or []), "Новые неподписанные процессы"),
                ("INFO", len(diff.get("folder_deltas") or []) + len(diff.get("disk_deltas") or []), "Изменения хранилища"),
                ("INFO", len(diff.get("removed_autorun") or []) + len(diff.get("removed_services") or []) + len(diff.get("removed_scheduled_tasks") or []), "Элементы удалены"),
            ]
            emitted = False
            for sev, count, title in event_specs:
                if count:
                    events.append({"timestamp": ts, "severity": sev, "title": title, "detail": f"Обнаружено: {count}", "count": count})
                    emitted = True
            if not emitted:
                events.append({"timestamp": ts, "severity": "INFO", "title": "Сканирование завершено", "detail": "Значимых изменений не обнаружено.", "count": 0})
        previous = snap

    if scans:
        current_summary = report.get("risk_summary") or {}
        overall = str(current_summary.get("overall_risk") or "").upper()
        current_score = int(_num(current_summary.get("max_score")))
        scans[-1]["risk"] = overall or scans[-1]["risk"]
        if current_score:
            scans[-1]["score"] = current_score
        if overall == "HIGH":
            scans[-1]["severity"] = "HIGH"
        elif overall == "MEDIUM" and scans[-1]["severity"] == "INFO":
            scans[-1]["severity"] = "MEDIUM"

    return {"scans": scans, "events": list(reversed(events[-60:])), "chart": scans[-30:]}


def _history_chart_svg(rows: list[dict]) -> str:
    rows = [r for r in rows if _num(r.get("used_gb")) >= 0]
    if len(rows) < 2:
        return '<div class="history-empty">Недостаточно данных для графика. Нужно минимум 2 сканирования.</div>'
    width, height = 900, 210
    pad_x, pad_y = 34, 28
    vals = [_num(r.get("used_gb")) for r in rows]
    lo, hi = min(vals), max(vals)
    if abs(hi - lo) < 0.01:
        lo -= 1; hi += 1
    x_step = (width - pad_x * 2) / max(1, len(vals) - 1)
    def xy(i, value):
        return pad_x + i * x_step, height - pad_y - ((value - lo) / (hi - lo)) * (height - pad_y * 2)
    points = [xy(i, v) for i, v in enumerate(vals)]
    poly = " ".join(f"{x:.1f},{y:.1f}" for x, y in points)
    area = f"{pad_x},{height-pad_y} " + poly + f" {points[-1][0]:.1f},{height-pad_y}"
    labels = []
    step = max(1, len(rows) // 6)
    for i in range(0, len(rows), step):
        x, _ = points[i]
        labels.append(f'<text x="{x:.1f}" y="{height-6}" text-anchor="middle" class="hc-label">{_esc(str(rows[i].get("timestamp") or "")[:10])}</text>')
    labels.append(f'<text x="{width-pad_x}" y="18" text-anchor="end" class="hc-value">{hi:.1f} GB</text>')
    labels.append(f'<text x="{width-pad_x}" y="{height-30}" text-anchor="end" class="hc-value">{lo:.1f} GB</text>')
    dots = "".join(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3.5" class="hc-dot"><title>{_esc(rows[i].get("timestamp"))}: {vals[i]:.1f} GB</title></circle>' for i, (x, y) in enumerate(points))
    return f"""<svg class="history-chart" viewBox="0 0 {width} {height}" role="img" aria-label="Изменение занятого места на диске C">
      <line x1="{pad_x}" y1="{pad_y}" x2="{pad_x}" y2="{height-pad_y}" class="hc-grid"/>
      <line x1="{pad_x}" y1="{height-pad_y}" x2="{width-pad_x}" y2="{height-pad_y}" class="hc-grid"/>
      <polygon points="{area}" class="hc-area"/>
      <polyline points="{poly}" class="hc-line"/>
      {dots}
      {''.join(labels)}
    </svg>"""


# ---------------------------------------------------------------------------
# HTML builder
# ---------------------------------------------------------------------------

def build_dashboard_html(report: dict) -> str:
    computer = report.get("computer") or {}
    meta = report.get("meta") or {}
    scan = report.get("scan") or {}
    disks = report.get("disks") or {}
    changes = report.get("changes") or {}
    recommendations = report.get("recommendations") or []
    history = report.get("disk_history") or []
    history_data = _history_data(report)
    history_scans = history_data.get("scans") or []
    history_events = history_data.get("events") or []

    import platform as _platform
    raw_name = (
        computer.get("name")
        or computer.get("hostname")
        or computer.get("Name")
        or ""
    )
    if not str(raw_name).strip() or str(raw_name).strip().upper() in ("UNKNOWN", "NONE", "NULL"):
        raw_name = _platform.node() or "UNKNOWN"
    pc_name = _esc(str(raw_name).strip())
    pc_os = _esc(computer.get("os") or computer.get("caption") or "Windows")

    try:
        from core.monitor import monitor_enabled, monitor_interval_hours, next_run_eta
        if monitor_enabled():
            eta = next_run_eta() or f"каждые {monitor_interval_hours()} ч"
            next_scan_html = f"Monitor ON<br>{_esc(eta)}"
        else:
            next_scan_html = f"Monitor OFF<br>интервал {monitor_interval_hours()} ч"
    except Exception:
        next_scan_html = "Ручной запуск<br>через приложение"
    generated = _esc(meta.get("generated_at") or scan.get("timestamp") or "—")
    duration = meta.get("duration_sec") or scan.get("duration_sec")
    duration_str = f"{duration} сек" if duration is not None else "—"
    files_scanned = _fmt_int(meta.get("files_scanned") or scan.get("files_scanned") or 0)

    # Health
    score, health_label, health_cls, health_checks = _health_score(report)
    health_color = {"good": "#22C55E", "warn": "#F59E0B", "bad": "#E31B23"}[health_cls]
    health_ring = _health_svg_ring(score, "#E31B23" if health_cls != "good" else "#22C55E")
    if health_cls == "good":
        health_ring = _health_svg_ring(score, "#E31B23")  # keep red accent like screenshot
    health_checks_html = "".join(
        f'<div class="check-line">{_check_icon(k)} {_esc(t)}</div>'
        for k, t in health_checks
    )
    health_desc = {
        "good": "Система в целом<br>в хорошем состоянии",
        "warn": "Есть моменты,<br>требующие внимания",
        "bad": "Обнаружены<br>серьёзные проблемы",
    }[health_cls]

    # Risk
    risk_label, risk_title, risk_cls, risk_checks = _risk_level(report)
    risk_color = {"good": "#22C55E", "warn": "#F59E0B", "bad": "#E31B23"}[risk_cls]
    risk_ring = _risk_svg_ring(risk_label, risk_color)
    risk_checks_html = "".join(
        f'<div class="check-line">{_check_icon(k)} {_esc(t)}</div>'
        for k, t in risk_checks
    )
    risk_desc = (
        "Признаков угроз<br>не обнаружено"
        if risk_cls == "good"
        else "Обнаружены<br>потенциальные риски"
    )

    # Storage — all disks
    disk_blocks = []
    for letter in sorted(disks.keys()):
        info = disks[letter]
        if not isinstance(info, dict):
            continue
        total = _num(info.get("TotalGB"))
        free = _num(info.get("FreeGB"))
        used = _num(info.get("UsedGB"))
        pct = _num(info.get("UsedPct")) or (used / total * 100 if total else 0)
        color = "#E31B23" if pct >= 90 else ("#F59E0B" if pct >= 80 else "#22C55E")
        ring = _disk_svg_ring(pct, color)
        disk_blocks.append(f"""
        <div class="disk-block">
          {ring}
          <div class="disk-info">
            <div class="disk-letter">Диск { _esc(letter) }:</div>
            <div class="disk-stats">
              Всего: {_fmt_gb(total)}<br>
              Занято: {_fmt_gb(used)}<br>
              Свободно: {_fmt_gb(free)}
            </div>
          </div>
        </div>
        """)

    if not disk_blocks:
        disk_blocks.append('<div class="empty-state">Нет данных о дисках</div>')

    # Sparkline from C history
    pts = []
    for row in history:
        if isinstance(row, dict) and str(row.get("Disk", "C")).upper() == "C":
            pts.append(_num(row.get("UsedGB")))
    spark = _sparkline_svg(pts[-24:] if pts else [])

    # Changes columns
    new_unsigned = changes.get("new_unsigned_processes") or []
    new_autorun = changes.get("new_autorun") or []
    new_tasks = changes.get("new_scheduled_tasks") or []
    new_sus = changes.get("new_suspicious_files") or []
    new_services = changes.get("new_services") or []
    deltas = changes.get("folder_deltas") or []
    baseline = bool(changes.get("baseline"))
    diff_summary = str(changes.get("summary") or "")

    risk_summary = report.get("risk_summary") or {}
    top_findings = risk_summary.get("top_findings") or []
    counts = risk_summary.get("counts") or {}
    scan_mode = str((report.get("meta") or {}).get("mode") or "Full")

    def items_html(items: list, extractor, limit: int = 4) -> str:
        if not items:
            return '<div class="change-empty">Нет изменений</div>'
        lines = []
        for it in items[:limit]:
            text = extractor(it) if not isinstance(it, str) else it
            lines.append(f'<div class="change-item"><span class="dot warn">●</span> {_esc(text)}</div>')
        if len(items) > limit:
            lines.append(f'<div class="change-more">… и ещё {len(items) - limit}</div>')
        return "".join(lines)

    def path_name(it):
        if isinstance(it, dict):
            p = str(
                it.get("Path") or it.get("path")
                or it.get("Name") or it.get("name")
                or it.get("TaskName") or it.get("task_name")
                or "—"
            )
            return p.split("\\")[-1]
        return str(it)

    WHY_RU = {
        "unsigned": "нет подписи",
        "unknown_publisher": "неизвестный издатель",
        "new_executable": "новый файл",
        "new_service": "новая служба",
        "suspicious_autorun": "автозагрузка",
        "suspicious_scheduled_task": "задача планировщика",
        "suspicious_parent": "подозрительный parent",
        "parent_from_temp": "parent из Temp",
        "temp_process": "запуск из Temp",
        "encoded_command": "кодированная команда",
        "user_temp": "папка Temp",
        "double_extension": "двойное расширение",
        "suspicious_name": "подозрительное имя",
        "service_unknown_path": "путь вне system/PF",
        "known_system_path": "системный путь",
        "valid_microsoft_signature": "подпись Microsoft",
        "valid_signature": "есть подпись",
        "known_publisher": "известный издатель",
        "dev_tool_path": "dev-инструмент",
        "script_context": "скрипт расширения",
        "vt_malicious": "VirusTotal positive",
        "known_malicious_hash": "известный malware hash",
    }
    KIND_RU = {
        "file": "файл",
        "process": "процесс",
        "service": "служба",
        "autorun": "автозагрузка",
        "scheduled_task": "задача",
    }

    def _why_ru(items) -> str:
        out = []
        for w in items[:4]:
            key = str(w).strip()
            out.append(WHY_RU.get(key, key.replace("_", " ")))
        return " · ".join(out) if out else "—"

    def processes_html(trees: list, limit: int = 12) -> str:
        if not trees:
            return '<div class="change-empty">Нет интересных process tree (unsigned / elevated score)</div>'
        blocks = []
        for i, t in enumerate(trees[:limit]):
            if not isinstance(t, dict):
                continue
            risk = str(t.get("risk") or "LOW").upper()
            cls = "bad" if risk == "HIGH" else ("warn" if risk == "MEDIUM" else "ok")
            name = _esc(str(t.get("name") or "—")[:48])
            score = int(t.get("score") or 0)
            path = _esc(str(t.get("path") or ""))
            tree = t.get("tree") or []
            tree_html = '<div class="proc-tree">'
            for ti, node in enumerate(tree if isinstance(tree, list) else []):
                if not isinstance(node, dict):
                    continue
                nname = _esc(str(node.get("name") or (node.get("path") or "").split("\\")[-1] or "?"))
                npath = _esc(str(node.get("path") or ""))
                nsig = _esc(str(node.get("signature") or "—"))
                indent = 14 * ti
                branch = "└── " if ti else ""
                tree_html += (
                    f'<div class="pt-node" style="padding-left:{indent}px" title="{npath}">'
                    f'<span class="pt-br">{branch}</span>'
                    f'<span class="pt-name">{nname}</span>'
                    f'<span class="pt-sig">{nsig}</span></div>'
                )
            tree_html += "</div>"
            blocks.append(
                f'<div class="proc-card">'
                f'<div class="proc-card-head">'
                f'<span class="finding-risk {cls}">{risk}</span>'
                f'<span class="finding-score">{score}</span>'
                f'<span class="finding-name" title="{path}">{name}</span>'
                f'</div>'
                f'{tree_html}'
                f'</div>'
            )
        return "".join(blocks)

    def findings_html(findings: list, limit: int = 8) -> str:

        from core.risk_engine import format_explain

        interesting = [
            f for f in findings
            if isinstance(f, dict) and str(f.get("risk", "")).upper() in ("HIGH", "MEDIUM")
        ]
        if not interesting:
            return '<div class="change-empty">Нет объектов MEDIUM/HIGH</div>'
        rows = []
        for i, f in enumerate(interesting[:limit]):
            risk = str(f.get("risk") or "LOW").upper()
            cls = "bad" if risk == "HIGH" else ("warn" if risk == "MEDIUM" else "ok")
            name = _esc(str(f.get("name") or "—")[:48])
            kind_raw = str(f.get("kind") or "file").lower()
            kind = _esc(KIND_RU.get(kind_raw, kind_raw))
            score = int(f.get("score") or 0)
            conf = _esc(str(f.get("confidence") or ""))
            path = _esc(str(f.get("path") or ""))
            exp = format_explain(f)
            breakdown = exp.get("breakdown") or []
            why = exp.get("why_flagged") or []
            why_s = _esc(_why_ru(why) if why else "—")
            lines_html = ""
            for b in breakdown:
                w = int(b.get("weight") or 0)
                wcls = "pos" if w > 0 else "neg"
                lines_html += (
                    f'<div class="explain-line {wcls}">'
                    f'<span class="w">{_esc(b.get("text","").split("  ")[0] if b.get("text") else w)}</span>'
                    f'<span class="lbl">{_esc(b.get("label") or "")}'
                    f'{(" ("+_esc(b.get("detail"))+")") if b.get("detail") else ""}</span>'
                    f'</div>'
                )
            if not lines_html:
                lines_html = '<div class="explain-line">Нет разбивки evidence</div>'
            fid = f"ex{i}"
            tree = f.get("process_tree") or []
            tree_html = ""
            if tree and isinstance(tree, list):
                tree_html = '<div class="explain-head">PROCESS TREE</div><div class="proc-tree">'
                for ti, node in enumerate(tree):
                    if not isinstance(node, dict):
                        continue
                    nname = _esc(str(node.get("name") or (node.get("path") or "").split("\\")[-1] or "?"))
                    npath = _esc(str(node.get("path") or ""))
                    nsig = _esc(str(node.get("signature") or "—"))
                    indent = 14 * ti
                    branch = "└── " if ti else ""
                    tree_html += (
                        f'<div class="pt-node" style="padding-left:{indent}px" title="{npath}">'
                        f'<span class="pt-br">{branch}</span>'
                        f'<span class="pt-name">{nname}</span>'
                        f'<span class="pt-sig">{nsig}</span></div>'
                    )
                tree_html += "</div>"
            rows.append(
                f'<div class="finding-block">'
                f'<div class="finding-row" onclick="document.getElementById(\'{fid}\').classList.toggle(\'open\')">'
                f'<span class="finding-risk {cls}">{risk}</span>'
                f'<span class="finding-score">{score}</span>'
                f'<span class="finding-kind">{kind}</span>'
                f'<span class="finding-name" title="{path}">{name}</span>'
                f'<span class="finding-why" title="{why_s}">{why_s}</span>'
                f'</div>'
                f'<div class="explain-panel" id="{fid}">'
                f'<div class="explain-head">WHY IS THIS SUSPICIOUS? · score {score} · conf {conf}</div>'
                f'<div class="explain-path">{path}</div>'
                f'{tree_html}'
                f'{lines_html}'
                f'<div class="explain-foot">{_esc(exp.get("conclusion") or "")}</div>'
                f'</div>'
                f'</div>'
            )
        if len(interesting) > limit:
            rows.append(f'<div class="change-more">… и ещё {len(interesting) - limit}</div>')
        return "".join(rows)

    total_delta = sum(_num(d.get("DeltaGB")) for d in deltas if isinstance(d, dict))
    delta_sign = "+" if total_delta >= 0 else ""
    delta_count = f"{delta_sign}{total_delta:.1f} GB" if deltas else "0"

    delta_lines = []
    for d in sorted(deltas, key=lambda x: abs(_num(x.get("DeltaGB"))), reverse=True)[:4]:
        if not isinstance(d, dict):
            continue
        path = str(d.get("Path", "")).split("\\")[-1]
        delta = _num(d.get("DeltaGB"))
        sign = "+" if delta >= 0 else ""
        delta_lines.append(
            f'<div class="change-item">{_esc(path)} <span class="delta">{sign}{delta:.1f} GB</span></div>'
        )
    delta_html = "".join(delta_lines) if delta_lines else '<div class="change-empty">Нет изменений</div>'

    # AI section
    high_n = int(counts.get("HIGH") or 0)
    med_n = int(counts.get("MEDIUM") or 0)
    summary_ru = diff_summary
    if "No significant changes" in summary_ru:
        summary_ru = "Значимых изменений с прошлого скана нет."
    elif "Baseline snapshot" in summary_ru:
        summary_ru = "Базовый снимок — сравнивать пока не с чем."

    ai = report.get("ai") or {}
    if not isinstance(ai, dict) or not ai.get("body"):
        if score >= 80 and risk_cls == "good" and high_n == 0 and med_n == 0:
            ai = {
                "title": "Система выглядит здоровой",
                "body": "Объектов MEDIUM/HIGH не найдено. " + (summary_ru or "Изменений нет."),
                "provider": "rules",
                "model": "local",
            }
        elif risk_cls == "bad" or high_n:
            ai = {
                "title": "Обнаружены потенциальные риски",
                "body": f"Найдено HIGH: {high_n}, MEDIUM: {med_n}. Проверьте блок «Требуют внимания».",
                "provider": "rules",
                "model": "local",
            }
        else:
            ai = {
                "title": "Требуется внимание",
                "body": f"Объектов среднего риска: {med_n}. Критических угроз нет — просмотрите findings.",
                "provider": "rules",
                "model": "local",
            }

    ai_title = str(ai.get("title") or "AI анализ")
    ai_body = str(ai.get("body") or "")
    overall_ai = str(ai.get("overall_risk") or (report.get("risk_summary") or {}).get("overall_risk") or "").upper()
    if overall_ai == "HIGH" or high_n:
        ai_title_cls = "warn"
    elif overall_ai == "MEDIUM" or med_n:
        ai_title_cls = "warn"
    else:
        ai_title_cls = "good"
    ai_provider = _esc(str(ai.get("provider") or "rules"))
    ai_model = _esc(str(ai.get("model") or "local"))

    recs_html = "".join(f"<li>{_esc(r)}</li>" for r in (recommendations or ["Существенных проблем не найдено"])[:5])



    # --- Security Status (main banner) ---
    overall = str((report.get("risk_summary") or {}).get("overall_risk") or "LOW").upper()
    conf = str((report.get("risk_summary") or {}).get("overall_confidence") or "—").upper()
    high_n_ss = int((report.get("risk_summary") or {}).get("counts", {}).get("HIGH") or 0)
    med_n_ss = int((report.get("risk_summary") or {}).get("counts", {}).get("MEDIUM") or 0)
    if overall == "HIGH" or high_n_ss > 0:
        ss_cls = "bad"
        ss_title = "🔴 ACTION REQUIRED"
        ss_sub = f"Обнаружены объекты высокого риска: HIGH {high_n_ss} · MEDIUM {med_n_ss}"
        ss_btn = "СМОТРЕТЬ FINDINGS"
        ss_href = "#findings"
    elif overall == "MEDIUM" or med_n_ss > 0:
        ss_cls = "warn"
        ss_title = "🟠 ATTENTION"
        ss_sub = f"Есть объекты среднего риска: MEDIUM {med_n_ss} · HIGH {high_n_ss}"
        ss_btn = "СМОТРЕТЬ FINDINGS"
        ss_href = "#findings"
    else:
        ss_cls = "ok"
        ss_title = "🟢 PROTECTED"
        ss_sub = "Критических угроз не обнаружено. Система под наблюдением."
        ss_btn = "ИСТОРИЯ"
        ss_href = "#history-full"
    ss_meta = (
        f"Risk: <b>{_esc(overall)}</b> · Confidence: <b>{_esc(conf)}</b>"
        f" · Скан: <b>{generated}</b>"
    )

    # Timeline — current scan stays compact on the dashboard; full history is below.
    timeline_items = history_events[:5]

    def _tl_class(severity: str) -> str:
        sev = str(severity or "INFO").upper()
        return "bad" if sev == "HIGH" else ("warn" if sev == "MEDIUM" else "info")

    timeline_html = ""
    for event in timeline_items:
        kind = _tl_class(event.get("severity"))
        badge = _esc(event.get("severity") or "INFO")
        timeline_html += f"""
        <div class="tl-item">
          <div class="tl-dot {kind}"></div>
          <div class="tl-body">
            <div class="tl-time">{_esc(event.get("timestamp") or "—")}</div>
            <div class="tl-title">{_esc(event.get("title") or "Событие")}</div>
            <div class="tl-sub">{_esc(event.get("detail") or "")}</div>
          </div>
          <div class="tl-badge {kind}">{badge}</div>
        </div>
        """
    if not timeline_html:
        timeline_html = '<div class="history-empty">История пока пуста.</div>'

    history_rows = ""
    for row in history_scans[-12:][::-1]:
        risk = str(row.get("risk") or "LOW").upper()
        if risk not in ("HIGH", "MEDIUM", "LOW"):
            risk = "LOW"
        cls = _tl_class("HIGH" if risk == "HIGH" else ("MEDIUM" if risk == "MEDIUM" else "INFO"))
        if risk == "LOW":
            cls = "info"
        changes_count = int(row.get("added") or 0)
        removed_count = int(row.get("removed") or 0)
        if row.get("baseline"):
            change_text = "Базовый снимок"
        elif changes_count or removed_count:
            change_text = f"+{changes_count} / −{removed_count}"
        else:
            change_text = "Без изменений"
        score_s = f" · {row.get('score')}" if row.get("score") else ""
        history_rows += f"""
        <div class="history-row">
          <div class="history-date">{_esc(row.get("timestamp") or "—")}</div>
          <div><span class="history-badge {cls}">{_esc(risk)}</span></div>
          <div class="history-risk">{_esc(risk)}{score_s}</div>
          <div class="history-change">{_esc(change_text)}</div>
          <div class="history-disk">{_num(row.get("used_gb")):.1f} GB <span>{_num(row.get("used_pct")):.0f}%</span></div>
        </div>
        """
    history_chart = _history_chart_svg(history_data.get("chart") or [])

    embedded = json.dumps(report, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")

    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Miharu — {pc_name}</title>
<link rel="icon" type="image/png" href="data:image/png;base64,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"/>
<style>
:root {{
  --bg: #0B0B0D;
  --bg-sidebar: #0E0E10;
  --bg-card: #121214;
  --bg-card2: #161618;
  --border: #1E1E22;
  --border-soft: #2A2A30;
  --text: #E8E8EC;
  --muted: #8A8A92;
  --dim: #5C5C64;
  --red: #E31B23;
  --green: #22C55E;
  --orange: #F59E0B;
  --blue: #3B82F6;
}}

* {{ box-sizing: border-box; margin: 0; padding: 0; }}

body {{
  background: var(--bg);
  color: var(--text);
  font-family: "Segoe UI", Inter, system-ui, -apple-system, sans-serif;
  font-size: 13px;
  line-height: 1.45;
  min-height: 100vh;
}}

.app {{
  display: grid;
  grid-template-columns: 220px 1fr;
  min-height: 100vh;
}}

/* ---- Sidebar ---- */
.sidebar {{
  background: var(--bg-sidebar);
  border-right: 1px solid var(--border);
  padding: 20px 0;
  display: flex;
  flex-direction: column;
  position: sticky;
  top: 0;
  height: 100vh;
}}

.brand {{
  padding: 0 18px 20px;
}}
.brand-logo {{
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 4px;
}}
.brand-img {{
  width: 40px;
  height: 40px;
  border-radius: 10px;
  display: block;
  object-fit: cover;
  box-shadow: 0 0 0 1px rgba(227,27,35,0.25);
}}
.brand-eye {{
  width: 36px; height: 36px;
  border-radius: 50%;
  background: radial-gradient(circle at 40% 40%, #ff4444, #8b0000 70%, #1a0000);
  border: 2px solid var(--red);
  box-shadow: 0 0 16px rgba(227,27,35,0.4);
  display: grid; place-items: center;
  font-size: 14px; color: #fff; font-weight: 700;
}}
.brand-jp {{
  color: var(--red);
  font-size: 18px;
  font-weight: 700;
  letter-spacing: 3px;
}}
.brand-tag {{
  color: var(--red);
  font-size: 10px;
  letter-spacing: 3px;
  margin-top: 2px;
}}
.brand-name {{
  color: var(--text);
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 2px;
  margin-top: 2px;
}}

.nav {{
  display: flex;
  flex-direction: column;
  gap: 2px;
  flex: 1;
  padding: 0 0 12px;
}}
.nav a {{
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 18px;
  color: var(--muted);
  text-decoration: none;
  font-size: 13px;
  border-left: 3px solid transparent;
  transition: all .15s;
}}
.nav a:hover {{ background: rgba(255,255,255,.03); color: var(--text); }}
.nav a.active {{
  background: rgba(227,27,35,.12);
  color: var(--text);
  border-left-color: var(--red);
  font-weight: 600;
}}
.nav .ico {{ width: 18px; text-align: center; opacity: .8; }}

.sidebar-foot {{
  padding: 12px 18px;
  border-top: 1px solid var(--border);
  color: var(--dim);
  font-size: 11px;
}}
.sidebar-foot .label {{ letter-spacing: 1px; margin-bottom: 4px; }}

/* ---- Main ---- */
.main {{
  display: flex;
  flex-direction: column;
  min-width: 0;
}}

.header {{
  display: flex;
  align-items: center;
  gap: 24px;
  padding: 14px 28px;
  border-bottom: 1px solid var(--border);
  background: var(--bg);
  position: sticky;
  top: 0;
  z-index: 10;
}}
.header-pc {{
  display: flex;
  flex-direction: column;
  gap: 2px;
}}
.header-pc .name {{ font-size: 14px; font-weight: 600; }}
.header-pc .os {{ font-size: 11px; color: var(--muted); }}

.header-meta {{
  display: flex;
  gap: 28px;
  margin-left: auto;
}}
.meta-item .lbl {{
  font-size: 10px;
  color: var(--dim);
  letter-spacing: .5px;
  text-transform: uppercase;
}}
.meta-item .val {{
  font-size: 13px;
  font-weight: 600;
  margin-top: 2px;
}}

.content {{
  padding: 20px 28px 32px;
  display: flex;
  flex-direction: column;
  gap: 16px;
}}

/* ---- Cards ---- */
.card {{
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 18px 20px;
}}

.card-title {{
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 1px;
  color: var(--muted);
  margin-bottom: 14px;
  display: flex;
  align-items: center;
  gap: 6px;
}}

.security-status {{
  margin: 0 24px 16px;
  padding: 18px 22px;
  border-radius: 12px;
  border: 1px solid var(--border);
  background: var(--bg-card);
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 20px;
}}
.security-status.ok {{
  border-color: rgba(34,197,94,0.35);
  background: linear-gradient(90deg, rgba(34,197,94,0.08), var(--bg-card) 55%);
}}
.security-status.warn {{
  border-color: rgba(245,158,11,0.4);
  background: linear-gradient(90deg, rgba(245,158,11,0.1), var(--bg-card) 55%);
}}
.security-status.bad {{
  border-color: rgba(227,27,35,0.45);
  background: linear-gradient(90deg, rgba(227,27,35,0.12), var(--bg-card) 55%);
}}
.ss-left {{ display: flex; flex-direction: column; gap: 4px; min-width: 0; }}
.ss-label {{
  font-size: 11px;
  letter-spacing: 1.5px;
  color: var(--muted);
  text-transform: uppercase;
}}
.ss-title {{
  font-size: 22px;
  font-weight: 800;
  letter-spacing: 0.5px;
}}
.security-status.ok .ss-title {{ color: var(--green); }}
.security-status.warn .ss-title {{ color: var(--orange); }}
.security-status.bad .ss-title {{ color: var(--red); }}
.ss-meta {{
  font-size: 12px;
  color: var(--muted);
  margin-top: 4px;
  line-height: 1.5;
}}
.ss-meta b {{ color: var(--text); font-weight: 600; }}
.ss-actions {{ display: flex; gap: 10px; flex-shrink: 0; }}
.ss-actions a {{
  text-decoration: none;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.8px;
  padding: 8px 14px;
  border-radius: 8px;
  border: 1px solid var(--border-soft);
  color: var(--text);
}}
.ss-actions a.primary {{
  background: rgba(227,27,35,0.15);
  border-color: rgba(227,27,35,0.4);
  color: #ff6b6b;
}}
.security-status.ok .ss-actions a.primary {{
  background: rgba(34,197,94,0.12);
  border-color: rgba(34,197,94,0.35);
  color: var(--green);
}}
.security-status.warn .ss-actions a.primary {{
  background: rgba(245,158,11,0.12);
  border-color: rgba(245,158,11,0.4);
  color: var(--orange);
}}
.top-row {{
  display: grid;
  grid-template-columns: 1fr 1fr 1fr;
  gap: 16px;
}}

.gauge-row {{
  display: flex;
  gap: 16px;
  align-items: flex-start;
}}
.gauge-info {{ flex: 1; }}
.gauge-status {{
  font-size: 18px;
  font-weight: 700;
  margin-bottom: 4px;
}}
.gauge-status.good {{ color: var(--green); }}
.gauge-status.warn {{ color: var(--orange); }}
.gauge-status.bad {{ color: var(--red); }}

.gauge-desc {{
  color: var(--muted);
  font-size: 12px;
  margin-bottom: 12px;
  line-height: 1.4;
}}

.check-line {{
  font-size: 12px;
  color: var(--muted);
  margin-bottom: 4px;
  display: flex;
  align-items: center;
  gap: 6px;
}}
.dot.ok {{ color: var(--green); }}
.dot.warn {{ color: var(--orange); }}
.dot.bad {{ color: var(--red); }}

.card-more {{
  margin-top: 12px;
  text-align: right;
  font-size: 11px;
  color: var(--dim);
  text-decoration: none;
  display: block;
}}
a.card-more:hover {{ color: var(--text); }}

/* Storage */
.disks-row {{
  display: flex;
  flex-wrap: wrap;
  gap: 16px;
  margin-bottom: 10px;
}}
.disk-block {{
  display: flex;
  gap: 12px;
  align-items: center;
  flex: 1;
  min-width: 180px;
}}
.disk-letter {{
  font-size: 13px;
  font-weight: 600;
  margin-bottom: 4px;
}}
.disk-stats {{
  font-size: 12px;
  color: var(--muted);
  line-height: 1.5;
}}
.empty-spark {{
  color: var(--dim);
  font-size: 11px;
  padding: 12px 0;
}}

/* Changes */
.changes-header {{
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 14px;
}}
.changes-header .card-title {{ margin-bottom: 0; }}

.changes-grid {{
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 0;
}}
.change-col {{
  padding: 12px 14px;
  border-right: 1px solid var(--border);
  border-bottom: 1px solid var(--border);
}}
.change-col:nth-child(3n) {{ border-right: none; }}
.change-col:nth-last-child(-n+3) {{ border-bottom: none; }}
.change-col:nth-child(3n+1) {{ padding-left: 0; }}
.change-col:nth-child(3n) {{ padding-right: 0; }}

.change-head {{
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  margin-bottom: 10px;
}}
.change-head .lbl {{
  font-size: 10px;
  color: var(--dim);
  letter-spacing: .5px;
}}
.change-head .cnt {{
  font-size: 16px;
  font-weight: 700;
}}
.change-item {{
  font-size: 12px;
  color: var(--muted);
  margin-bottom: 6px;
  display: flex;
  gap: 6px;
  align-items: flex-start;
}}

.findings-meta {{
  color: var(--muted);
  font-size: 11px;
  letter-spacing: 0.5px;
}}
.findings-head {{
  display: grid;
  grid-template-columns: 64px 52px 72px 1.2fr 1.6fr;
  gap: 8px;
  padding: 8px 4px;
  color: var(--dim);
  font-size: 10px;
  letter-spacing: 0.8px;
  border-bottom: 1px solid var(--border);
  margin-bottom: 6px;
}}
.findings-list {{ display: flex; flex-direction: column; gap: 4px; }}
.finding-row {{
  display: grid;
  grid-template-columns: 64px 52px 72px 1.2fr 1.6fr;
  gap: 8px;
  align-items: center;
  padding: 8px 4px;
  border-radius: 6px;
  background: rgba(255,255,255,0.02);
  font-size: 12px;
}}
.finding-risk {{
  font-weight: 700;
  font-size: 11px;
  letter-spacing: 0.5px;
}}
.finding-risk.bad {{ color: var(--red); }}
.finding-risk.warn {{ color: var(--orange); }}
.finding-risk.ok {{ color: var(--green); }}
.finding-score {{ color: var(--text); font-weight: 600; }}
.finding-kind {{ color: var(--muted); font-size: 11px; text-transform: uppercase; }}
.finding-name {{ color: var(--text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
.finding-why {{ color: var(--muted); font-size: 11px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
.finding-block {{ border-bottom: 1px solid var(--border); }}
.finding-row {{ cursor: pointer; }}
.finding-row:hover {{ background: rgba(255,255,255,0.03); }}
.explain-panel {{
  display: none;
  padding: 10px 14px 14px 14px;
  background: #0c0c0e;
  border-left: 2px solid var(--border-soft);
  margin: 0 0 8px 0;
}}
.explain-panel.open {{ display: block; }}
.explain-head {{
  font-size: 11px;
  letter-spacing: 1px;
  color: var(--muted);
  margin-bottom: 6px;
  text-transform: uppercase;
}}
.explain-path {{
  font-size: 11px;
  color: var(--dim);
  margin-bottom: 10px;
  word-break: break-all;
}}
.explain-line {{
  display: flex;
  gap: 12px;
  font-size: 12px;
  padding: 3px 0;
  font-family: ui-monospace, Consolas, monospace;
}}
.explain-line .w {{ width: 42px; flex-shrink: 0; text-align: right; color: var(--orange); }}
.explain-line.pos .w {{ color: var(--orange); }}
.explain-line.neg .w {{ color: var(--green); }}
.explain-line .lbl {{ color: var(--text); }}
.proc-grid {{
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
}}
@media (max-width: 1100px) {{
  .proc-grid {{ grid-template-columns: 1fr; }}
}}
.proc-card {{
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 12px 14px;
  background: #0c0c0e;
}}
.proc-card-head {{
  display: flex;
  gap: 10px;
  align-items: center;
  margin-bottom: 8px;
  font-size: 12px;
}}
.proc-tree {{
  margin: 8px 0 12px;
  font-family: ui-monospace, Consolas, monospace;
  font-size: 12px;
}}
.pt-node {{ padding: 2px 0; color: var(--text); }}
.pt-br {{ color: var(--dim); }}
.pt-name {{ color: var(--text); }}
.pt-sig {{ color: var(--dim); margin-left: 10px; font-size: 10px; text-transform: uppercase; }}
.explain-foot {{
  margin-top: 10px;
  font-size: 12px;
  color: var(--muted);
}}
.diff-summary {{
  margin-top: 12px;
  color: var(--dim);
  font-size: 11px;
  letter-spacing: 0.3px;
}}
.mode-badge {{
  display: inline-block;
  margin-left: 10px;
  padding: 2px 8px;
  border: 1px solid var(--border);
  border-radius: 4px;
  font-size: 10px;
  color: var(--muted);
  letter-spacing: 1px;
}}
.change-empty {{
  font-size: 12px;
  color: var(--dim);
}}
.change-more {{
  font-size: 11px;
  color: var(--dim);
  margin-top: 4px;
}}
.delta {{
  color: var(--orange);
  font-weight: 600;
  white-space: nowrap;
}}

/* Bottom row */
.bottom-row {{
  display: grid;
  grid-template-columns: 1.4fr 1fr;
  gap: 16px;
}}

.ai-title {{
  font-size: 15px;
  font-weight: 700;
  margin-bottom: 8px;
}}
.ai-title.good {{ color: var(--green); }}
.ai-title.warn {{ color: var(--orange); }}
.ai-body {{
  color: var(--muted);
  font-size: 12px;
  line-height: 1.55;
  margin-bottom: 16px;
}}
.ai-cols {{
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}}
.ai-cols .lbl {{
  font-size: 10px;
  color: var(--dim);
  letter-spacing: .5px;
  margin-bottom: 6px;
}}
.ai-cols ul {{
  list-style: none;
  font-size: 12px;
  color: var(--muted);
}}
.ai-cols li {{
  margin-bottom: 4px;
  padding-left: 12px;
  position: relative;
}}
.ai-cols li::before {{
  content: "•";
  position: absolute;
  left: 0;
  color: var(--dim);
}}
.ai-meta {{
  margin-top: 16px;
  font-size: 10px;
  color: var(--dim);
}}

/* Full History */
.history-page {{ margin:0 24px 24px; padding:22px; border:1px solid var(--border); border-radius:10px; background:var(--bg-card); scroll-margin-top:78px; }}
.history-page-head {{ display:flex; justify-content:space-between; align-items:center; gap:20px; margin-bottom:16px; }}
.history-subtitle {{ color:var(--muted); font-size:12px; margin-top:5px; }}
.history-stat {{ min-width:82px; text-align:center; border:1px solid var(--border); border-radius:8px; padding:9px 12px; }}
.history-stat strong {{ display:block; font-size:20px; }} .history-stat span {{ font-size:9px; color:var(--dim); text-transform:uppercase; letter-spacing:.6px; }}
.history-grid {{ display:grid; grid-template-columns:1.5fr 1fr; gap:12px; }}
.history-chart-card, .history-events-card, .history-table-card {{ min-width:0; }}
.history-chart {{ width:100%; height:210px; display:block; margin-top:8px; }}
.hc-grid {{ stroke:var(--border-soft); stroke-width:1; }} .hc-area {{ fill:rgba(34,197,94,.06); }}
.hc-line {{ fill:none; stroke:var(--green); stroke-width:2.2; vector-effect:non-scaling-stroke; }} .hc-dot {{ fill:var(--green); stroke:var(--bg-card); stroke-width:2; }}
.hc-label, .hc-value {{ fill:var(--dim); font-size:9px; font-family:inherit; }}
.chart-legend {{ font-size:10px; color:var(--muted); margin:2px 0 0 34px; }} .legend-dot {{ display:inline-block; width:7px; height:7px; border-radius:50%; background:var(--green); margin-right:5px; }}
.history-events {{ max-height:245px; overflow:auto; }} .history-event {{ display:flex; align-items:center; gap:9px; padding:10px 0; border-bottom:1px solid var(--border); }}
.history-event:last-child {{ border-bottom:0; }} .history-event > div {{ min-width:0; flex:1; }} .history-event b {{ display:block; font-size:11px; }}
.history-event small {{ display:block; color:var(--muted); font-size:9px; margin-top:3px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }}
.history-event-dot {{ width:8px; height:8px; border-radius:50%; flex:0 0 auto; }} .history-event-dot.info {{ background:var(--green); }} .history-event-dot.warn {{ background:var(--orange); }} .history-event-dot.bad {{ background:var(--red); }}
.history-table-card {{ margin-top:12px; }} .history-table-head, .history-row {{ display:grid; grid-template-columns:1.45fr .75fr .8fr 1fr .8fr; gap:12px; align-items:center; }}
.history-table-head {{ padding:8px 12px; color:var(--dim); font-size:9px; border-bottom:1px solid var(--border); }} .history-row {{ padding:11px 12px; border-bottom:1px solid var(--border); font-size:11px; }}
.history-row:last-child {{ border-bottom:0; }} .history-date {{ color:var(--muted); }} .history-risk {{ font-weight:700; }} .history-change {{ color:var(--muted); }}
.history-disk {{ text-align:right; font-weight:600; }} .history-disk span {{ color:var(--dim); font-weight:400; }}
.history-badge {{ display:inline-block; padding:3px 7px; border-radius:4px; font-size:8px; font-weight:700; letter-spacing:.5px; }}
.history-badge.info {{ color:var(--green); background:rgba(34,197,94,.10); }} .history-badge.warn {{ color:var(--orange); background:rgba(245,158,11,.10); }} .history-badge.bad {{ color:var(--red); background:rgba(227,27,35,.10); }}
.history-empty {{ padding:20px; color:var(--dim); font-size:11px; text-align:center; }}

/* Timeline */
.tl-item {{
  display: flex;
  gap: 12px;
  align-items: flex-start;
  padding: 10px 0;
  border-bottom: 1px solid var(--border);
}}
.tl-item:last-child {{ border-bottom: none; }}
.tl-dot {{
  width: 12px; height: 12px;
  border-radius: 50%;
  margin-top: 4px;
  flex-shrink: 0;
  border: 2px solid;
}}
.tl-dot.info {{ background: var(--green); border-color: var(--green); }}
.tl-dot.warn {{ background: var(--orange); border-color: var(--orange); }}
.tl-dot.low {{ background: var(--blue); border-color: var(--blue); }}
.tl-body {{ flex: 1; min-width: 0; }}
.tl-time {{ font-size: 11px; color: var(--dim); }}
.tl-title {{ font-size: 13px; font-weight: 600; margin-top: 2px; }}
.tl-sub {{ font-size: 12px; color: var(--muted); margin-top: 2px; }}
.tl-badge {{
  font-size: 10px;
  font-weight: 700;
  letter-spacing: .5px;
  padding: 3px 8px;
  border-radius: 4px;
  align-self: center;
}}
.tl-badge.info {{ color: var(--green); background: rgba(34,197,94,.12); }}
.tl-badge.warn {{ color: var(--orange); background: rgba(245,158,11,.12); }}
.tl-badge.low {{ color: var(--blue); background: rgba(59,130,246,.12); }}

.tl-link {{
  text-align: right;
  margin-top: 10px;
  font-size: 11px;
  color: var(--dim);
}}

/* Footer bar */
.footer {{
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 28px;
  border-top: 1px solid var(--border);
  background: var(--bg-sidebar);
  font-size: 11px;
  color: var(--muted);
}}
.footer .dot-status {{ color: var(--green); font-size: 9px; }}
.footer .spacer {{ flex: 1; }}
.footer a {{
  color: var(--muted);
  text-decoration: none;
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 5px 12px;
}}
.footer a:hover {{ color: var(--text); border-color: var(--border-soft); }}

@media (max-width: 1100px) {{
  .top-row {{ grid-template-columns: 1fr; }}
  .changes-grid {{ grid-template-columns: 1fr 1fr; }}
  .change-col {{ border-right: 1px solid var(--border); border-bottom: 1px solid var(--border); padding: 12px; }}
  .change-col:nth-child(2n) {{ border-right: none; }}
  .change-col:nth-child(3n) {{ border-right: 1px solid var(--border); }}
  .change-col:nth-last-child(-n+2) {{ border-bottom: none; }}
  .bottom-row {{ grid-template-columns: 1fr; }}
}}
</style>
</head>
<body>
<div class="app">

  <!-- SIDEBAR -->
  <aside class="sidebar">
    <div class="brand">
      <div class="brand-logo">
        <img class="brand-img" src="data:image/png;base64,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" alt="logo" width="40" height="40"/>
      </div>
      <div class="brand-name">MIHARU</div>
      <div class="brand-tag">見張る</div>
    </div>

    <nav class="nav">
      <a href="#dashboard" class="active"><span class="ico">▦</span> DASHBOARD</a>
      <a href="#security"><span class="ico">🛡</span> SECURITY</a>
      <a href="#storage"><span class="ico">▣</span> STORAGE</a>
      <a href="#changes"><span class="ico">↻</span> CHANGES</a>
      <a href="#findings"><span class="ico">◎</span> FINDINGS</a>
      <a href="#processes"><span class="ico">⌘</span> PROCESSES</a>
      <a href="#history-full"><span class="ico">◷</span> HISTORY</a>
    </nav>

    <div class="sidebar-foot">
      <div class="label">MONITOR</div>
      <div>{next_scan_html}</div>
      <div style="margin-top:10px">v1.1.0</div>
    </div>
  </aside>

  <!-- MAIN -->
  <div class="main">
    <header class="header">
      <div class="header-pc">
        <div class="name">🖥  {pc_name}</div>
        <div class="os">{pc_os}</div>
      </div>
      <div class="header-meta">
        <div class="meta-item">
          <div class="lbl">Последнее сканирование</div>
          <div class="val">{generated}</div>
        </div>
        <div class="meta-item">
          <div class="lbl">Длительность</div>
          <div class="val">{_esc(duration_str)}</div>
        </div>
        <div class="meta-item">
          <div class="lbl">Файлов проверено</div>
          <div class="val">{files_scanned}</div>
        </div>
        <div class="meta-item">
          <div class="lbl">Режим</div>
          <div class="val"><span class="mode-badge">{_esc(scan_mode)}</span></div>
        </div>
      </div>
    </header>

    <div class="content" id="dashboard">

      <div class="security-status {ss_cls}" id="security-status">
        <div class="ss-left">
          <div class="ss-label">SYSTEM SECURITY STATUS</div>
          <div class="ss-title">{ss_title}</div>
          <div class="ss-meta">{ss_sub}<br>{ss_meta}</div>
        </div>
        <div class="ss-actions">
          <a class="primary" href="{ss_href}">{ss_btn}</a>
        </div>
      </div>

      <!-- TOP 3 CARDS -->
      <div class="top-row">
        <!-- Health -->
        <div class="card">
          <div class="card-title">⚡ SYSTEM HEALTH</div>
          <div class="gauge-row">
            {health_ring}
            <div class="gauge-info">
              <div class="gauge-status {health_cls}">{health_label}</div>
              <div class="gauge-desc">{health_desc}</div>
              {health_checks_html}
            </div>
          </div>
          <a class="card-more" href="#findings">К FINDINGS ›</a>
        </div>

        <!-- Risk -->
        <div class="card" id="security">
          <div class="card-title">🛡 SECURITY RISK</div>
          <div class="gauge-row">
            {risk_ring}
            <div class="gauge-info">
              <div class="gauge-status {risk_cls}">{risk_title}</div>
              <div class="gauge-desc">{risk_desc}</div>
              {risk_checks_html}
            </div>
          </div>
          <a class="card-more" href="#findings">К FINDINGS ›</a>
        </div>

        <!-- Storage -->
        <div class="card" id="storage">
          <div class="card-title">▣ STORAGE</div>
          <div class="disks-row">
            {"".join(disk_blocks)}
          </div>
          {spark}
          <a class="card-more" href="#history-full">К HISTORY ›</a>
        </div>
      </div>

      <!-- CHANGES -->
      <div class="card" id="changes">
        <div class="changes-header">
          <div class="card-title">▦ ИЗМЕНЕНИЯ С ПОСЛЕДНЕГО СКАНИРОВАНИЯ</div>
          <a class="card-more" style="margin:0" href="#findings">К FINDINGS ›</a>
        </div>
        <div class="changes-grid">
          <div class="change-col">
            <div class="change-head">
              <span class="lbl">НОВЫЕ ПРОЦЕССЫ</span>
              <span class="cnt">{len(new_unsigned)}</span>
            </div>
            {items_html(new_unsigned, path_name)}
          </div>
          <div class="change-col">
            <div class="change-head">
              <span class="lbl">НОВЫЕ АВТОЗАГРУЗКИ</span>
              <span class="cnt">{len(new_autorun)}</span>
            </div>
            {items_html(new_autorun, path_name)}
          </div>
          <div class="change-col">
            <div class="change-head">
              <span class="lbl">НОВЫЕ СЛУЖБЫ</span>
              <span class="cnt">{len(new_services)}</span>
            </div>
            {items_html(new_services, path_name)}
          </div>
          <div class="change-col">
            <div class="change-head">
              <span class="lbl">НОВЫЕ ЗАДАЧИ</span>
              <span class="cnt">{len(new_tasks)}</span>
            </div>
            {items_html(new_tasks, path_name)}
          </div>
          <div class="change-col">
            <div class="change-head">
              <span class="lbl">НОВЫЕ ФАЙЛЫ</span>
              <span class="cnt">{len(new_sus)}</span>
            </div>
            {items_html(new_sus, path_name)}
          </div>
          <div class="change-col">
            <div class="change-head">
              <span class="lbl">ИЗМЕНЕНИЯ ДИСКА</span>
              <span class="cnt">{delta_count}</span>
            </div>
            {delta_html}
          </div>
        </div>
        <div class="diff-summary">{_esc(summary_ru) if summary_ru else ""}</div>
      </div>

      <!-- PROCESSES -->
      <div class="card" id="processes">
        <div class="card-head">
          <div class="card-title">⌘ PROCESS TREES</div>
          <div class="findings-meta">unsigned / elevated · parent chain</div>
        </div>
        <div class="proc-grid">
          {processes_html((report.get("process_trees") or []), limit=12)}
        </div>
      </div>

      <!-- FINDINGS -->
      <div class="card" id="findings">
        <div class="changes-header">
          <div class="card-title">◎ ТРЕБУЮТ ВНИМАНИЯ</div>
          <div class="findings-meta">
            HIGH {int(counts.get("HIGH") or 0)} · MEDIUM {int(counts.get("MEDIUM") or 0)} · LOW {int(counts.get("LOW") or 0)}
          </div>
        </div>
        <div class="findings-head">
          <span>RISK</span><span>SCORE</span><span>TYPE</span><span>NAME</span><span>WHY (клик = explain)</span>
        </div>
        <div class="findings-list">
          {findings_html(top_findings)}
        </div>
      </div>

      <!-- BOTTOM: AI + Timeline -->
      <div class="bottom-row">
        <div class="card">
          <div class="card-title">◈ AI АНАЛИЗ</div>
          <div class="ai-title {ai_title_cls}">{ai_title}</div>
          <div class="ai-body">{_esc(ai_body)}</div>
          <div class="ai-cols">
            <div>
              <div class="lbl">РЕКОМЕНДАЦИИ</div>
              <ul>{recs_html}</ul>
            </div>
            <div>
              <div class="lbl">ЛЕГИТИМНЫЕ ЭЛЕМЕНТЫ</div>
              <ul>
                <li>Microsoft VS Code</li>
                <li>Docker Desktop</li>
                <li>Python</li>
                <li>Ollama</li>
              </ul>
            </div>
          </div>
          <div class="ai-meta">ПРОВАЙДЕР: {ai_provider}  ·  МОДЕЛЬ: {ai_model}  ·  источник: Risk Engine</div>
        </div>

        <div class="card" id="history">
          <div class="card-title">◇ ХРОНОЛОГИЯ СОБЫТИЙ</div>
          {timeline_html}
          <a class="tl-link" href="#history-full">ПЕРЕЙТИ В ИСТОРИЮ ›</a>
        </div>
      </div>

    </div>

    <!-- HISTORY / TIMELINE -->
    <section class="history-page" id="history-full">
      <div class="history-page-head">
        <div>
          <div class="card-title">◷ ИСТОРИЯ И TIMELINE</div>
          <div class="history-subtitle">Последние сканирования, изменения и динамика диска C</div>
        </div>
        <div class="history-stat"><strong>{len(history_scans)}</strong><span>сканов</span></div>
      </div>

      <div class="history-grid">
        <div class="card history-chart-card">
          <div class="card-title">ДИНАМИКА ХРАНИЛИЩА</div>
          {history_chart}
          <div class="chart-legend"><span class="legend-dot"></span> Занято на диске C</div>
        </div>
        <div class="card history-events-card">
          <div class="card-title">СОБЫТИЯ</div>
          <div class="history-events">
            {''.join(f'''<div class="history-event"><span class="history-event-dot {_tl_class(e.get("severity"))}"></span><div><b>{_esc(e.get("title") or "Событие")}</b><small>{_esc(e.get("timestamp") or "—")} · {_esc(e.get("detail") or "")}</small></div><span class="history-badge {_tl_class(e.get("severity"))}">{_esc(e.get("severity") or "INFO")}</span></div>''' for e in history_events[:12]) or '<div class="history-empty">Событий пока нет.</div>'}
          </div>
        </div>
      </div>

      <div class="card history-table-card">
        <div class="changes-header">
          <div class="card-title">СКАНИРОВАНИЯ</div>
          <div class="card-more" style="margin:0">ПОСЛЕДНИЕ 12</div>
        </div>
        <div class="history-table-head"><span>ВРЕМЯ</span><span>RISK</span><span>SCORE</span><span>ИЗМЕНЕНИЯ</span><span>ДИСК C</span></div>
        {history_rows or '<div class="history-empty">История пока пуста.</div>'}
      </div>
    </section>

    <footer class="footer">
      <span class="dot-status">●</span>
      <span>СТАТУС: ГОТОВ</span>
      <span class="spacer"></span>
      <a href="#" onclick="downloadJson();return false">ЭКСПОРТ ОТЧЁТА</a>
    </footer>
  </div>
</div>

<script>
const REPORT = {embedded};

function downloadJson() {{
  const blob = new Blob([JSON.stringify(REPORT, null, 2)], {{type: "application/json"}});
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "report.json";
  a.click();
}}

const navLinks = document.querySelectorAll('.nav a');
const sections = Array.from(navLinks).map(a => document.getElementById(a.getAttribute('href').slice(1))).filter(Boolean);
window.addEventListener('scroll', () => {{
  const y = window.scrollY + 120;
  let active = sections[0];
  for (const section of sections) {{ if (section.offsetTop <= y) active = section; }}
  navLinks.forEach(a => a.classList.toggle('active', a.getAttribute('href') === '#' + active.id));
}}, {{passive:true}});
</script>
</body>
</html>
"""


def generate_dashboard(report: dict, json_path: Path) -> Path:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    if "risk_summary" not in report:
        report = enrich_report(report)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    dashboard_path = REPORT_DIR / f"Отчёт_{timestamp}.html"

    html_content = build_dashboard_html(report)
    dashboard_path.write_text(html_content, encoding="utf-8")

    latest_path = REPORT_DIR / "Отчёт_Последний.html"
    latest_path.write_text(html_content, encoding="utf-8")

    return dashboard_path


def format_report_preview(report: dict) -> str:
    """Компактный HTML-превью для встроенного просмотра в GUI."""
    computer = report.get("computer") or {}
    disks = report.get("disks") or {}
    meta = report.get("meta") or {}

    blocks = [
        f"""
        <div style="padding:18px;border:1px solid #1E1E22;background:#121214;
                    border-radius:10px;margin-bottom:10px;">
            <div style="font-size:16px;font-weight:600;color:#E8E8EC;letter-spacing:0.3px;">
                Miharu Report
            </div>
            <div style="color:#8A8A92;margin-top:5px;font-size:11px;">
                {_esc(computer.get("name", "?"))}
                · {_esc(computer.get("user", "?"))}
                · {_esc(meta.get("generated_at", "?"))}
            </div>
        </div>
        """
    ]

    for letter, info in disks.items():
        if not isinstance(info, dict):
            continue
        blocks.append(
            f"""
            <div style="padding:12px;border:1px solid #1E1E22;background:#0E0E10;
                        border-radius:8px;margin-bottom:6px;">
                <b style="color:#E8E8EC;font-size:12px;">DISK {_esc(letter)}</b><br>
                <span style="color:#8A8A92;font-size:11px;">
                    TOTAL: {_esc(info.get("TotalGB", "?"))} GB ·
                    USED: {_esc(info.get("UsedGB", "?"))} GB ·
                    FREE: {_esc(info.get("FreeGB", "?"))} GB ·
                    USED: {_esc(info.get("UsedPct", "?"))}%
                </span>
            </div>
            """
        )

    blocks.append(
        """
        <div style="padding:10px;color:#5C5C64;font-size:10px;
                    border-top:1px solid #1E1E22;margin-top:8px;">
            Полный интерактивный дашборд сохранён в HTML.
            Нажмите «ОТКРЫТЬ DASHBOARD».
        </div>
        """
    )
    return "".join(blocks)