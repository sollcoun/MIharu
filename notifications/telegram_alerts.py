"""Telegram notification provider with per-installation deduplication.

Direct Telegram credentials are supported for development/self-hosted use.
For a multi-user release the preferred mode is a central backend provider;
the client never needs the shared bot token in that mode.
"""
from __future__ import annotations

import hashlib
import html
import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

from config import (
    DEFAULT_TELEGRAM_BOT_TOKEN,
    TELEGRAM_STATE_PATH,
    ensure_app_dirs,
    load_settings,
    save_settings,
)
from .notifications import NotificationManager, NotificationResult

TELEGRAM_API = "https://api.telegram.org/bot{token}/{method}"
MAX_MESSAGE_LENGTH = 3900


class TelegramAlertError(RuntimeError):
    pass


def _env(name: str) -> str:
    return os.environ.get(name, "").strip()


def telegram_token() -> str:
    """Permanent bot token: env → settings.json → product_defaults → empty."""
    token = _env("TELEGRAM_BOT_TOKEN") or _env("TELEGRAM_TOKEN")
    if token:
        return token
    token = str(load_settings().get("telegram_bot_token") or "").strip()
    if token:
        return token
    try:
        from config import load_product_defaults
        token = str(load_product_defaults().get("telegram_bot_token") or "").strip()
        if token:
            return token
    except Exception:
        pass
    return (DEFAULT_TELEGRAM_BOT_TOKEN or "").strip()


def telegram_chat_id() -> str:
    """Per-user chat id: env → settings.json (auto-linked)."""
    chat_id = _env("TELEGRAM_CHAT_ID") or _env("TELEGRAM_CHAT")
    if chat_id:
        return chat_id
    return str(load_settings().get("telegram_chat_id") or "").strip()


def is_configured() -> bool:
    return bool(telegram_token() and telegram_chat_id())


def set_bot_token(token: str) -> None:
    """Save bot token once into settings (permanent for this install)."""
    token = (token or "").strip()
    if not token:
        raise TelegramAlertError("Пустой token")
    save_settings({"telegram_bot_token": token})


def set_chat_id(chat_id: str | int) -> None:
    """Persist chat_id and enable direct notifications."""
    chat_id = str(chat_id or "").strip()
    if not chat_id:
        raise TelegramAlertError("Пустой chat_id")
    save_settings({
        "telegram_chat_id": chat_id,
        "notification_mode": "direct",
    })


def _api(method: str, params: dict | None = None, *, token: str | None = None, timeout: int = 20) -> dict:
    token = (token or telegram_token()).strip()
    if not token:
        raise TelegramAlertError("Telegram bot token не задан")
    url = TELEGRAM_API.format(token=urllib.parse.quote(token, safe=""), method=method)
    data = None
    if params:
        data = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None}).encode("utf-8")
    request = urllib.request.Request(url, data=data, method="POST" if data else "GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:400]
        raise TelegramAlertError(f"Telegram HTTP {exc.code}: {detail}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise TelegramAlertError(f"Telegram connection error: {exc}") from exc
    except ValueError as exc:
        raise TelegramAlertError("Telegram вернул некорректный JSON") from exc
    if not payload.get("ok"):
        raise TelegramAlertError(str(payload.get("description") or "Telegram API error"))
    return payload.get("result")


def get_bot_username(token: str | None = None) -> str:
    me = _api("getMe", token=token)
    return str((me or {}).get("username") or "").strip()


def deep_link(token: str | None = None, start_payload: str | None = None) -> str:
    """https://t.me/<bot>?start=<payload> for one-tap link."""
    username = get_bot_username(token=token)
    if not username:
        raise TelegramAlertError("Не удалось получить username бота")
    if start_payload:
        return f"https://t.me/{username}?start={urllib.parse.quote(str(start_payload), safe='')}"
    return f"https://t.me/{username}"


def link_chat_id(
    *,
    timeout_sec: int = 120,
    start_payload: str | None = None,
    on_status: Callable[[str], None] | None = None,
) -> str:
    """Wait for user /start and save chat_id automatically.

    Flow:
      1. App shows deep_link()
      2. User opens bot and presses Start
      3. This function polls getUpdates and stores chat.id
    """
    token = telegram_token()
    if not token:
        raise TelegramAlertError("Сначала задайте bot token")

    def status(msg: str) -> None:
        if on_status:
            on_status(msg)

    # Drop pending updates so we only see fresh /start
    try:
        _api("getUpdates", {"offset": -1, "limit": 1, "timeout": 0}, token=token, timeout=10)
    except TelegramAlertError:
        pass

    deadline = time.time() + max(15, int(timeout_sec))
    offset = 0
    payload_l = (start_payload or "").strip().lower()
    status("Жду /start в Telegram…")

    while time.time() < deadline:
        updates = _api(
            "getUpdates",
            {"offset": offset, "timeout": 25, "limit": 20},
            token=token,
            timeout=35,
        ) or []
        for upd in updates:
            if not isinstance(upd, dict):
                continue
            uid = int(upd.get("update_id") or 0)
            if uid:
                offset = max(offset, uid + 1)
            msg = upd.get("message") or upd.get("channel_post") or {}
            if not isinstance(msg, dict):
                continue
            text = str(msg.get("text") or "").strip()
            chat = msg.get("chat") or {}
            chat_id = chat.get("id")
            if chat_id is None:
                continue
            if text.startswith("/start"):
                parts = text.split(maxsplit=1)
                arg = parts[1].strip().lower() if len(parts) > 1 else ""
                if payload_l and arg and arg != payload_l:
                    continue
                set_chat_id(chat_id)
                status(f"Привязан chat_id={chat_id}")
                return str(chat_id)
        status("Всё ещё жду /start…")

    raise TelegramAlertError("Таймаут: откройте бота и нажмите Start")


def link_chat_id_async(
    *,
    timeout_sec: int = 120,
    start_payload: str | None = None,
    on_status: Callable[[str], None] | None = None,
    on_done: Callable[[bool, str], None] | None = None,
) -> None:
    def worker() -> None:
        try:
            cid = link_chat_id(
                timeout_sec=timeout_sec,
                start_payload=start_payload,
                on_status=on_status,
            )
            if on_done:
                on_done(True, f"Telegram привязан (chat_id={cid})")
        except Exception as exc:
            if on_done:
                on_done(False, str(exc))

    threading.Thread(target=worker, name="telegram-link", daemon=True).start()


def _load_state() -> dict[str, Any]:
    try:
        if TELEGRAM_STATE_PATH.exists():
            data = json.loads(TELEGRAM_STATE_PATH.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                active = data.get("active")
                if isinstance(active, dict):
                    return {"version": 2, "active": active}
    except (OSError, ValueError, TypeError):
        pass
    return {"version": 2, "active": {}}


def _save_state(state: dict[str, Any]) -> None:
    try:
        ensure_app_dirs()
        tmp = TELEGRAM_STATE_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(TELEGRAM_STATE_PATH)
    except OSError:
        pass


def _s(value: Any) -> str:
    return str(value or "").strip()


def _risk(value: Any) -> str:
    return _s(value).upper()


def _identity(kind: str, item: dict[str, Any]) -> str:
    if kind == "autorun":
        raw = f"{item.get('Key') or item.get('key') or ''}|{item.get('Name') or item.get('name') or ''}"
    elif kind == "task":
        raw = f"{item.get('TaskPath') or item.get('task_path') or ''}|{item.get('TaskName') or item.get('task_name') or item.get('Name') or ''}"
    elif kind == "service":
        raw = _s(item.get("Name") or item.get("name") or item.get("ServiceName"))
    else:
        raw = _s(item.get("path") or item.get("Path") or item.get("name") or item.get("Name"))
    return raw.strip().lower().replace("/", "\\")


def _fingerprint(prefix: str, identity: str) -> str:
    digest = hashlib.sha256(identity.encode("utf-8", errors="replace")).hexdigest()[:24]
    return f"{prefix}:{digest}"


def _high_findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()
    for key in ("scored_files", "scored_processes", "scored_autoruns", "scored_tasks", "scored_services"):
        for item in report.get(key) or []:
            if not isinstance(item, dict) or _risk(item.get("risk")) != "HIGH":
                continue
            kind = _s(item.get("kind") or key.removeprefix("scored_")).lower()
            identity = _identity(kind, item)
            if not identity:
                continue
            fp = _fingerprint("high", f"{kind}|{identity}")
            if fp in seen:
                continue
            seen.add(fp)
            copy = dict(item)
            copy["_kind"] = kind
            copy["_fingerprint"] = fp
            candidates.append(copy)
    candidates.sort(key=lambda x: int(x.get("score") or 0), reverse=True)
    return candidates


def _is_noise_persistence(kind: str, item: dict[str, Any]) -> bool:
    """Skip Windows noise that is not actionable persistence."""
    path = _s(
        item.get("path")
        or item.get("Path")
        or item.get("Value")
        or item.get("value")
        or item.get("Name")
        or item.get("name")
        or ""
    ).lower().replace("/", "\\")
    name = path.rsplit("\\", 1)[-1]
    if name == "desktop.ini" or path.endswith("\\desktop.ini"):
        return True
    if kind == "startup":
        # only real launchers
        if not any(name.endswith(ext) for ext in (
            ".lnk", ".exe", ".bat", ".cmd", ".vbs", ".ps1", ".js", ".msc", ".scr",
        )):
            return True
    if kind == "service":
        # first-collect mass noise already handled in diff; still skip empty names
        if not _s(item.get("Name") or item.get("name")):
            return True
    return False


def _new_persistence(report: dict[str, Any]) -> list[dict[str, Any]]:
    changes = report.get("changes") or {}
    result: list[dict[str, Any]] = []
    mapping = (
        ("new_autorun", "autorun", "автозагрузка"),
        ("new_scheduled_tasks", "task", "задача планировщика"),
        ("new_services", "service", "служба"),
        ("new_startup", "startup", "Startup"),
    )
    seen: set[str] = set()
    for change_key, kind, label in mapping:
        for item in changes.get(change_key) or []:
            if isinstance(item, str):
                item = {"Name": item, "path": item}
            if not isinstance(item, dict):
                continue
            if _is_noise_persistence(kind, item):
                continue
            identity = _identity(kind, item)
            if not identity:
                continue
            fp = _fingerprint("persist", f"{kind}|{identity}")
            if fp in seen:
                continue
            seen.add(fp)
            result.append({"kind": kind, "label": label, "item": item, "fingerprint": fp})
    return result


def _fmt_why(item: dict[str, Any]) -> str:
    why = item.get("why_flagged") or []
    if isinstance(why, list):
        values = [str(x).strip() for x in why if str(x).strip()]
        if values:
            return ", ".join(values[:3])
    evidence = item.get("evidence") or []
    values = []
    if isinstance(evidence, list):
        for e in evidence:
            if isinstance(e, dict) and int(e.get("weight") or 0) > 0:
                values.append(_s(e.get("type")).replace("_", " "))
    return ", ".join(values[:3]) or "обнаружены признаки, требующие проверки"


def _vt_text(item: dict[str, Any]) -> str:
    total = item.get("vt_total")
    if total is None:
        return ""
    try:
        detections = int(item.get("vt_malicious") or 0) + int(item.get("vt_suspicious") or 0)
        return f"\nVirusTotal: <b>{detections}/{int(total)}</b>"
    except (TypeError, ValueError):
        return ""


def _high_block(item: dict[str, Any]) -> str:
    try:
        from core.risk_engine import format_explain
        exp = format_explain(item)
    except Exception:
        exp = {
            "score": item.get("score"),
            "risk": item.get("risk"),
            "confidence": item.get("confidence"),
            "breakdown": [],
            "conclusion": "",
        }
    name = _s(item.get("name") or item.get("path") or "Неизвестный объект")
    path = _s(item.get("path"))
    score = _s(exp.get("score") if exp.get("score") is not None else item.get("score") or "0")
    kind = _s(item.get("kind") or item.get("_kind") or "object")
    conf = _s(exp.get("confidence") or item.get("confidence") or "")
    lines = [
        f"🔴 <b>HIGH · {html.escape(name)}</b>",
        f"Тип: {html.escape(kind)} · Score: <b>{html.escape(str(score))}</b>"
        + (f" · Conf: {html.escape(conf)}" if conf else ""),
    ]
    if path:
        lines.append(f"<code>{html.escape(path)}</code>")
    breakdown = exp.get("breakdown") or []
    tree_text = _s(item.get("process_tree_text") or "")
    if tree_text:
        lines.append("<b>PROCESS TREE</b>")
        for line in tree_text.splitlines()[:8]:
            lines.append(f"<code>{html.escape(line)}</code>")
    if breakdown:
        lines.append("<b>EXPLAIN</b>")
        for b in breakdown[:8]:
            if int(b.get("weight") or 0) <= 0:
                continue
            text = _s(b.get("text") or b.get("label") or "")
            if text:
                lines.append(html.escape(text))
    else:
        lines.append(f"WHY: {html.escape(_fmt_why(item))}")
    vt = _vt_text(item)
    if vt:
        lines.append(vt.strip())
    sha = _s(item.get("sha256") or item.get("SHA256") or (item.get("facts") or {}).get("sha256"))
    if sha:
        lines.append(f"SHA-256: <code>{html.escape(sha[:32])}…</code>")
    if exp.get("conclusion"):
        lines.append(f"<i>{html.escape(str(exp.get('conclusion')))}</i>")
    return "\n".join(lines)


def _persistence_block(event: dict[str, Any]) -> str:
    item = event["item"]
    label = event["label"]
    kind = event["kind"]
    name = _s(item.get("Name") or item.get("name") or item.get("TaskName") or item.get("task_name") or item.get("DisplayName") or item.get("Path") or item.get("path") or "Новый объект")
    path = _s(item.get("Value") or item.get("Path") or item.get("path") or item.get("TaskPath") or item.get("task_path"))
    return f"🟠 <b>NEW PERSISTENCE · {html.escape(label)}</b>\nОбъект: <b>{html.escape(name)}</b>\nТип: {html.escape(kind)}" + (f"\nЗначение/путь: <code>{html.escape(path)}</code>" if path else "")


def build_alert(report: dict[str, Any], high: list[dict[str, Any]], persistence: list[dict[str, Any]]) -> str:
    computer = report.get("computer") or {}
    meta = report.get("meta") or {}
    timestamp = _s(meta.get("generated_at") or (report.get("scan") or {}).get("timestamp"))
    host = _s(computer.get("name") or computer.get("hostname") or "")
    if not host:
        import platform as _plt
        host = _plt.node() or "Windows PC"
    overall = _risk((report.get("risk_summary") or {}).get("overall_risk")) or "UNKNOWN"
    risk_icon = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟢"}.get(overall, "⚪")

    status_map = {
        "HIGH": ("🔴", "ACTION REQUIRED"),
        "MEDIUM": ("🟠", "ATTENTION"),
        "LOW": ("🟢", "PROTECTED"),
    }
    a_icon, a_label = status_map.get(overall, ("🚨", "ALERT"))
    lines = [
        f"{a_icon} <b>Miharu · {a_label}</b>",
        "",
        f"<b>{html.escape(host)}</b>",
        f"Риск <b>{html.escape(overall)}</b> · требуется проверка",
    ]
    if timestamp:
        lines.append(f"<i>{html.escape(timestamp)}</i>")

    if high:
        lines.append("")
        lines.append(f"🔴 <b>HIGH · {len(high)}</b>")
        for x in high[:5]:
            lines.append(_high_block(x))

    if persistence:
        lines.append("")
        lines.append(f"🟠 <b>Новая persistence · {len(persistence)}</b>")
        for x in persistence[:6]:
            lines.append(_persistence_block(x))

    ai = report.get("ai") or {}
    if isinstance(ai, dict) and _s(ai.get("body")):
        lines.append("")
        lines.append("💬 <b>AI</b>")
        body = _s(ai.get("body"))
        if len(body) > 700:
            body = body[:700].rstrip() + "…"
        lines.append(html.escape(body))

    lines.append("")
    lines.append("<i>Подробности — Dashboard / экспорт отчёта.</i>")
    text = "\n".join(lines)
    if len(text) > MAX_MESSAGE_LENGTH:
        text = text[: MAX_MESSAGE_LENGTH - 60].rstrip() + "\n…\n<i>Подробности в Dashboard.</i>"
    return text



def send_message(text: str, *, token: str | None = None, chat_id: str | None = None, timeout: int = 12) -> None:
    token = (token or telegram_token()).strip()
    chat_id = (chat_id or telegram_chat_id()).strip()
    if not token or not chat_id:
        raise TelegramAlertError("Telegram не настроен")
    _api(
        "sendMessage",
        {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": "true",
        },
        token=token,
        timeout=timeout,
    )


class DirectTelegramProvider:
    """Development/self-hosted provider. Never used by default in a clean install."""
    name = "Telegram"

    def send(self, message: str) -> None:
        send_message(message)


def prepare_alert(report: dict[str, Any]) -> tuple[str | None, dict[str, Any]]:
    """Build alert text + dedup delta. Independent of Telegram credentials.

    Used by both backend and direct Telegram channels.
    """
    high = _high_findings(report)
    persistence = _new_persistence(report)
    triggers = high + [{"_fingerprint": x["fingerprint"]} for x in persistence]
    state = _load_state()
    active = state.get("active") or {}
    current = {
        x["_fingerprint"]: {"seen_at": time.time()}
        for x in triggers
        if x.get("_fingerprint")
    }
    new_high = [x for x in high if x["_fingerprint"] not in active]
    new_persistence = [x for x in persistence if x["fingerprint"] not in active]
    message = (
        build_alert(report, new_high, new_persistence)
        if (new_high or new_persistence)
        else None
    )
    return message, {
        "configured": True,
        "current": current,
        "new_high": len(new_high),
        "new_persistence": len(new_persistence),
    }


def build_summary(report: dict[str, Any]) -> str:
    """Compact card-style scan summary for Telegram."""
    computer = report.get("computer") or {}
    meta = report.get("meta") or {}
    scan = report.get("scan") or {}
    timestamp = _s(meta.get("generated_at") or scan.get("timestamp"))
    host = _s(computer.get("name") or computer.get("hostname") or "")
    if not host:
        import platform as _plt
        host = _plt.node() or "Windows PC"

    summary = report.get("risk_summary") or {}
    overall = _risk(summary.get("overall_risk")) or "UNKNOWN"
    conf = _s(summary.get("overall_confidence") or "").upper()
    counts = summary.get("counts") or {}
    n_high = int(counts.get("HIGH") or 0)
    n_med = int(counts.get("MEDIUM") or 0)
    n_low = int(counts.get("LOW") or 0)
    files = meta.get("files_scanned") or scan.get("files_scanned") or 0
    dur = meta.get("duration_sec") or scan.get("duration_sec")
    mode = _s(meta.get("mode") or scan.get("mode") or "")

    status = {
        "LOW": ("🟢", "PROTECTED"),
        "MEDIUM": ("🟠", "ATTENTION"),
        "HIGH": ("🔴", "ACTION REQUIRED"),
    }.get(overall, ("⚪", overall))
    icon, status_label = status

    # Disks
    disks = report.get("disks") or {}
    disk_bits = []
    if isinstance(disks, dict):
        for key, d in sorted(disks.items()):
            if not isinstance(d, dict):
                continue
            lab = str(key).rstrip(":").upper()
            pct = d.get("UsedPct")
            if pct is None:
                continue
            try:
                disk_bits.append(f"{lab}: {float(pct):.0f}%")
            except (TypeError, ValueError):
                pass
    disk_line = " · ".join(disk_bits[:4])

    # Changes
    changes = report.get("changes") or {}
    ch_parts = []
    mapping = (
        ("new_autorun", "autorun"),
        ("new_startup", "startup"),
        ("new_services", "службы"),
        ("new_scheduled_tasks", "задачи"),
        ("new_unsigned_processes", "процессы"),
        ("new_suspicious_files", "файлы"),
    )
    if isinstance(changes, dict):
        for key, label in mapping:
            n = len(changes.get(key) or [])
            if n:
                ch_parts.append(f"+{n} {label}")
        ch_summary = _s(changes.get("summary"))
    else:
        ch_summary = ""
    if ch_parts:
        ch_line = ", ".join(ch_parts)
    elif ch_summary and "no significant" in ch_summary.lower():
        ch_line = "без изменений"
    elif ch_summary:
        ch_line = ch_summary[:80]
    else:
        ch_line = "без изменений"

    # Header card
    lines = [
        f"{icon} <b>Miharu · {status_label}</b>",
        "",
        f"<b>{html.escape(host)}</b>",
        f"Риск <b>{html.escape(overall)}</b>"
        + (f" · conf {html.escape(conf)}" if conf else "")
        + (f" · H{n_high}/M{n_med}/L{n_low}" if (n_high or n_med) else ""),
    ]

    meta_bits = []
    if mode:
        meta_bits.append(html.escape(mode))
    try:
        if files:
            meta_bits.append(f"{int(files):,}".replace(",", " ") + " файлов")
    except (TypeError, ValueError):
        pass
    if dur is not None:
        try:
            meta_bits.append(f"{float(dur):.1f} с")
        except (TypeError, ValueError):
            meta_bits.append(f"{_s(dur)} с")
    if meta_bits:
        lines.append(" · ".join(meta_bits))
    if disk_line:
        lines.append(html.escape(disk_line))
    lines.append(f"Изменения: {html.escape(ch_line)}")
    if timestamp:
        lines.append(f"<i>{html.escape(timestamp)}</i>")

    # Outcome line
    lines.append("")
    if n_high > 0:
        lines.append("🔴 Есть <b>HIGH</b> — откройте Dashboard.")
    elif n_med > 0:
        lines.append("🟠 Есть <b>MEDIUM</b> — при необходимости проверьте findings.")
    else:
        lines.append("Критических угроз не найдено.")

    # Top HIGH only (compact)
    high = _high_findings(report)
    if high:
        lines.append("")
        lines.append("<b>Top HIGH</b>")
        for x in high[:3]:
            name = _s(x.get("name") or x.get("path") or "object")
            score = x.get("score")
            bit = f"· {score}" if score is not None else ""
            lines.append(f"• <code>{html.escape(name)}</code> {bit}".rstrip())

    # AI — title + short body
    ai = report.get("ai") or {}
    if isinstance(ai, dict):
        title = _s(ai.get("title"))
        body = _s(ai.get("body"))
        if title or body:
            lines.append("")
            if title:
                lines.append(f"<b>{html.escape(title)}</b>")
            if body:
                if len(body) > 280:
                    body = body[:280].rstrip() + "…"
                lines.append(html.escape(body))

    text = "\n".join(lines)
    if len(text) > MAX_MESSAGE_LENGTH:
        text = text[: MAX_MESSAGE_LENGTH - 40].rstrip() + "\n…"
    return text


def send_summary_async(report: dict[str, Any], on_done: Callable[[bool, str], None] | None = None) -> None:
    """Send a scan summary unconditionally (no deduplication)."""
    if not is_configured():
        if on_done:
            on_done(False, "Уведомления: канал не настроен")
        return
    message = build_summary(report)

    def worker() -> None:
        try:
            DirectTelegramProvider().send(message)
        except Exception as exc:
            if on_done:
                on_done(False, f"Telegram: {exc}")
            return
        if on_done:
            on_done(True, "Telegram: сводка отправлена")

    threading.Thread(target=worker, name="telegram-summary", daemon=True).start()


def finalize_alert(state_delta: dict[str, Any], success: bool) -> None:
    if not state_delta.get("configured"):
        return
    state = _load_state()
    active = state.setdefault("active", {})
    current = state_delta.get("current") or {}
    if success:
        active.update(current)
    else:
        for fp, value in current.items():
            if fp in active:
                active[fp] = value
    state["active"] = {fp: value for fp, value in active.items() if fp in current}
    _save_state(state)


def send_alert_async(report: dict[str, Any], on_done: Callable[[bool, str], None] | None = None) -> None:
    message, delta = prepare_alert(report)
    if not message:
        if on_done:
            on_done(False, "Уведомления: нет новых событий или канал не настроен")
        return

    def worker() -> None:
        try:
            DirectTelegramProvider().send(message)
        except Exception as exc:
            finalize_alert(delta, False)
            if on_done:
                on_done(False, f"Telegram: {exc}")
            return
        finalize_alert(delta, True)
        if on_done:
            on_done(True, f"Telegram: отправлено ({delta['new_high']} HIGH, {delta['new_persistence']} persistence)")

    threading.Thread(target=worker, name="telegram-alert", daemon=True).start()