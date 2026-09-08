"""Export shareable Miharu reports (HTML + TXT)."""
from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from config import REPORT_DIR, ensure_app_dirs


def _esc(v: Any) -> str:
    return html.escape("" if v is None else str(v))


def _s(v: Any) -> str:
    return str(v or "").strip()


def _host(report: dict) -> str:
    c = report.get("computer") or {}
    if isinstance(c, dict):
        return _s(c.get("name") or c.get("hostname") or c.get("ComputerName")) or "PC"
    return "PC"


def _meta(report: dict) -> dict:
    m = report.get("meta") or {}
    return m if isinstance(m, dict) else {}


def _risk(report: dict) -> dict:
    r = report.get("risk_summary") or {}
    return r if isinstance(r, dict) else {}


def _counts(report: dict) -> dict:
    c = _risk(report).get("counts") or {}
    return c if isinstance(c, dict) else {}


def _changes_summary(report: dict) -> str:
    ch = report.get("changes") or {}
    if isinstance(ch, dict):
        s = _s(ch.get("summary"))
        if s:
            low = s.lower()
            if "no significant changes" in low:
                return "Значимых изменений с прошлого скана нет."
            if "baseline" in low:
                return "Базовый снимок — сравнивать пока не с чем."
            return s
    return "—"


def _top_findings(report: dict, limit: int = 15) -> list[dict]:
    """Only MEDIUM/HIGH — never pad export with LOW noise."""
    tops = _risk(report).get("top_findings") or []
    if not isinstance(tops, list):
        return []
    out = []
    for f in tops:
        if not isinstance(f, dict):
            continue
        risk = _s(f.get("risk")).upper()
        if risk in ("HIGH", "MEDIUM"):
            out.append(f)
        if len(out) >= limit:
            break
    return out


def _ai_body(report: dict) -> str:
    ai = report.get("ai") or {}
    if not isinstance(ai, dict):
        return ""
    title = _s(ai.get("title"))
    body = _s(ai.get("body"))
    if title and body:
        return f"{title}\n{body}"
    return body or title


def _disks_lines(report: dict) -> list[str]:
    disks = report.get("disks") or {}
    lines = []
    if not isinstance(disks, dict):
        return lines
    for letter, info in sorted(disks.items()):
        if not isinstance(info, dict):
            continue
        lab = str(letter).rstrip(":")
        lines.append(
            f"{lab}: total={info.get('TotalGB', '?')} GB  "
            f"used={info.get('UsedGB', '?')} GB  "
            f"free={info.get('FreeGB', '?')} GB  "
            f"({info.get('UsedPct', '?')}%)"
        )
    return lines


def build_text_report(report: dict) -> str:
    host = _host(report)
    meta = _meta(report)
    risk = _risk(report)
    counts = _counts(report)
    overall = _s(risk.get("overall_risk") or "LOW").upper()
    conf = _s(risk.get("overall_confidence") or "—").upper()
    when = _s(meta.get("generated_at") or datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    mode = _s(meta.get("mode") or meta.get("scan_mode") or "—")
    files = meta.get("files_scanned") or meta.get("files") or "—"
    dur = meta.get("duration_sec") or meta.get("duration") or "—"

    lines = [
        "MIHARU — ОТЧЁТ",
        "=" * 40,
        f"Хост:        {host}",
        f"Время:       {when}",
        f"Режим:       {mode}",
        f"Риск:        {overall} (confidence {conf})",
        f"Объекты:     HIGH {counts.get('HIGH', 0)} · MED {counts.get('MEDIUM', 0)} · LOW {counts.get('LOW', 0)} · total {counts.get('total', 0)}",
        f"Файлов:      {files}",
        f"Длительность:{dur} с",
        "",
        "ДИСКИ",
        "-" * 40,
    ]
    disks = _disks_lines(report)
    lines.extend(disks if disks else ["—"])
    lines += [
        "",
        "ИЗМЕНЕНИЯ",
        "-" * 40,
        _changes_summary(report),
        "",
        "FINDINGS (MEDIUM/HIGH)",
        "-" * 40,
    ]
    findings = _top_findings(report)
    if not findings:
        lines.append("Нет объектов MEDIUM/HIGH.")
    else:
        for f in findings:
            name = _s(f.get("name") or f.get("path") or "?")
            path = _s(f.get("path"))
            rk = _s(f.get("risk")).upper()
            sc = f.get("score", 0)
            kind = _s(f.get("kind") or "object")
            why = f.get("why_flagged") or []
            why_s = ", ".join(str(x) for x in why[:5]) if isinstance(why, list) else _s(why)
            lines.append(f"[{rk}] score={sc}  {kind}  {name}")
            if path:
                lines.append(f"  path: {path}")
            if why_s:
                lines.append(f"  why:  {why_s}")
            lines.append("")

    ai = _ai_body(report)
    if ai:
        lines += ["AI / ПОЯСНЕНИЕ", "-" * 40, ai, ""]

    lines += [
        "=" * 40,
        "Miharu — See what changed. Understand what matters.",
        "Отчёт сформирован локально. Секреты и полные JSON не включены.",
    ]
    return "\n".join(lines)


def build_export_html(report: dict) -> str:
    host = _host(report)
    meta = _meta(report)
    risk = _risk(report)
    counts = _counts(report)
    overall = _s(risk.get("overall_risk") or "LOW").upper()
    conf = _s(risk.get("overall_confidence") or "—").upper()
    when = _s(meta.get("generated_at") or datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    mode = _s(meta.get("mode") or meta.get("scan_mode") or "—")
    files = meta.get("files_scanned") or meta.get("files") or "—"
    dur = meta.get("duration_sec") or meta.get("duration") or "—"

    risk_cls = "ok" if overall == "LOW" else ("warn" if overall == "MEDIUM" else "bad")
    status = (
        "PROTECTED" if overall == "LOW"
        else ("ATTENTION" if overall == "MEDIUM" else "ACTION REQUIRED")
    )

    disk_rows = []
    for letter, info in sorted((report.get("disks") or {}).items()):
        if not isinstance(info, dict):
            continue
        disk_rows.append(
            f"<tr><td><b>{_esc(letter)}</b></td>"
            f"<td>{_esc(info.get('TotalGB', '—'))} GB</td>"
            f"<td>{_esc(info.get('UsedGB', '—'))} GB</td>"
            f"<td>{_esc(info.get('FreeGB', '—'))} GB</td>"
            f"<td>{_esc(info.get('UsedPct', '—'))}%</td></tr>"
        )
    disks_html = (
        "".join(disk_rows)
        if disk_rows
        else "<tr><td colspan='5'>Нет данных</td></tr>"
    )

    finding_blocks = []
    for f in _top_findings(report):
        rk = _s(f.get("risk")).upper()
        cls = "bad" if rk == "HIGH" else ("warn" if rk == "MEDIUM" else "ok")
        name = _esc(f.get("name") or "—")
        path = _esc(f.get("path") or "")
        score = _esc(f.get("score") or 0)
        kind = _esc(f.get("kind") or "object")
        why = f.get("why_flagged") or []
        if isinstance(why, list):
            why_s = _esc(", ".join(str(x) for x in why[:6]))
        else:
            why_s = _esc(why)
        finding_blocks.append(
            f'<div class="finding {cls}">'
            f'<div class="f-head"><span class="badge {cls}">{_esc(rk)}</span> '
            f'<span class="score">score {score}</span> '
            f'<span class="kind">{kind}</span> '
            f'<span class="name">{name}</span></div>'
            f'<div class="path">{path}</div>'
            f'<div class="why">{why_s or "—"}</div>'
            f"</div>"
        )
    findings_html = (
        "".join(finding_blocks)
        if finding_blocks
        else '<div class="empty">Нет объектов MEDIUM/HIGH</div>'
    )

    ai = _ai_body(report)
    ai_html = f"<pre class='ai'>{_esc(ai)}</pre>" if ai else "<div class='empty'>Нет AI-пояснения</div>"
    changes = _esc(_changes_summary(report))

    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Miharu Export — {_esc(host)} — {_esc(when)}</title>
<style>
  :root {{
    --bg:#0b0b0d; --card:#121214; --border:#1e1e22;
    --text:#e8e8ec; --muted:#8a8a92; --dim:#5c5c64;
    --green:#22c55e; --orange:#f59e0b; --red:#e31b23;
  }}
  * {{ box-sizing:border-box; }}
  body {{
    margin:0; font-family: "Segoe UI", system-ui, sans-serif;
    background:var(--bg); color:var(--text); line-height:1.45;
  }}
  .wrap {{ max-width:920px; margin:0 auto; padding:28px 20px 60px; }}
  h1 {{ font-size:22px; margin:0 0 4px; letter-spacing:.5px; }}
  .sub {{ color:var(--muted); font-size:13px; margin-bottom:22px; }}
  .status {{
    border:1px solid var(--border); border-radius:12px; padding:16px 18px;
    margin-bottom:18px; background:var(--card);
  }}
  .status.ok {{ border-color:rgba(34,197,94,.35); }}
  .status.warn {{ border-color:rgba(245,158,11,.4); }}
  .status.bad {{ border-color:rgba(227,27,35,.45); }}
  .status .label {{ font-size:11px; letter-spacing:1.5px; color:var(--muted); text-transform:uppercase; }}
  .status .title {{ font-size:20px; font-weight:800; margin-top:4px; }}
  .status.ok .title {{ color:var(--green); }}
  .status.warn .title {{ color:var(--orange); }}
  .status.bad .title {{ color:var(--red); }}
  .grid {{ display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-bottom:18px; }}
  @media (max-width:700px) {{ .grid {{ grid-template-columns:1fr; }} }}
  .card {{
    background:var(--card); border:1px solid var(--border); border-radius:12px;
    padding:14px 16px;
  }}
  .card h2 {{
    margin:0 0 10px; font-size:11px; letter-spacing:1.2px;
    color:var(--muted); text-transform:uppercase; font-weight:600;
  }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th, td {{ text-align:left; padding:6px 4px; border-bottom:1px solid var(--border); }}
  th {{ color:var(--dim); font-weight:600; font-size:11px; }}
  .finding {{
    border:1px solid var(--border); border-radius:10px; padding:12px 14px;
    margin-bottom:8px; background:#0e0e10;
  }}
  .finding.bad {{ border-left:3px solid var(--red); }}
  .finding.warn {{ border-left:3px solid var(--orange); }}
  .badge {{
    font-size:11px; font-weight:700; padding:2px 8px; border-radius:4px;
  }}
  .badge.bad {{ color:var(--red); background:rgba(227,27,35,.12); }}
  .badge.warn {{ color:var(--orange); background:rgba(245,158,11,.12); }}
  .badge.ok {{ color:var(--green); background:rgba(34,197,94,.12); }}
  .score,.kind {{ color:var(--muted); font-size:12px; margin-left:8px; }}
  .name {{ font-weight:600; margin-left:8px; }}
  .path {{ color:var(--dim); font-size:12px; margin-top:6px; word-break:break-all; }}
  .why {{ color:var(--muted); font-size:12px; margin-top:4px; }}
  .empty {{ color:var(--dim); font-size:13px; }}
  pre.ai {{
    white-space:pre-wrap; font-family:inherit; font-size:13px;
    color:var(--text); margin:0;
  }}
  .foot {{
    margin-top:28px; padding-top:14px; border-top:1px solid var(--border);
    color:var(--dim); font-size:11px;
  }}
  @media print {{
    body {{ background:#fff; color:#111; }}
    .card,.status,.finding {{ break-inside:avoid; }}
  }}
</style>
</head>
<body>
<div class="wrap">
  <h1>MIHARU — ОТЧЁТ</h1>
  <div class="sub">{_esc(host)} · {_esc(when)} · режим {_esc(mode)}</div>

  <div class="status {risk_cls}">
    <div class="label">System Security Status</div>
    <div class="title">{status}</div>
    <div class="sub" style="margin:8px 0 0">
      Risk <b>{_esc(overall)}</b> · Confidence <b>{_esc(conf)}</b> ·
      HIGH {_esc(counts.get('HIGH', 0))} · MED {_esc(counts.get('MEDIUM', 0))} · LOW {_esc(counts.get('LOW', 0))}
      · файлов {_esc(files)} · {_esc(dur)} с
    </div>
  </div>

  <div class="grid">
    <div class="card">
      <h2>Диски</h2>
      <table>
        <tr><th>Диск</th><th>Всего</th><th>Занято</th><th>Свободно</th><th>%</th></tr>
        {disks_html}
      </table>
    </div>
    <div class="card">
      <h2>Изменения с прошлого скана</h2>
      <div>{changes}</div>
    </div>
  </div>

  <div class="card" style="margin-bottom:18px">
    <h2>Findings (MEDIUM / HIGH)</h2>
    {findings_html}
  </div>

  <div class="card">
    <h2>Пояснение</h2>
    {ai_html}
  </div>

  <div class="foot">
    Miharu — See what changed. Understand what matters.<br>
    Локальный отчёт для передачи. Не содержит bot token и полных сырых dumps.
  </div>
</div>
</body>
</html>
"""


def export_report(report: dict, *, stem: str | None = None) -> dict[str, Path]:
    """Write HTML + TXT export into Reports/. Returns paths."""
    ensure_app_dirs()
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    host = _host(report).replace(" ", "_")[:32]
    base = stem or f"Miharu_Export_{host}_{ts}"

    html_path = REPORT_DIR / f"{base}.html"
    txt_path = REPORT_DIR / f"{base}.txt"

    html_path.write_text(build_export_html(report), encoding="utf-8")
    txt_path.write_text(build_text_report(report), encoding="utf-8")

    # latest aliases
    (REPORT_DIR / "Miharu_Export_Latest.html").write_text(
        html_path.read_text(encoding="utf-8"), encoding="utf-8"
    )
    (REPORT_DIR / "Miharu_Export_Latest.txt").write_text(
        txt_path.read_text(encoding="utf-8"), encoding="utf-8"
    )
    return {"html": html_path, "txt": txt_path}