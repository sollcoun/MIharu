from __future__ import annotations

import json
import re
import os
import time
import urllib.error
import urllib.request
from typing import Any

from config import load_settings

MISTRAL_URL = "https://api.mistral.ai/v1/chat/completions"
NVIDIA_URL = "https://integrate.api.nvidia.com/v1/chat/completions"
DEFAULT_MISTRAL_MODEL = "mistral-small-latest"
DEFAULT_NVIDIA_MODEL = "microsoft/phi-3-mini-128k-instruct"


def _env(name: str) -> str:
    return os.environ.get(name, "").strip()


def ai_provider() -> str:
    p = (_env("DISK_DIAGNOSTIC_AI_PROVIDER") or str(load_settings().get("ai_provider") or "")).strip().lower()
    if p in ("mistral", "nvidia", "auto", "off", "rules"):
        return p or "auto"
    return "auto"


def mistral_key() -> str:
    return _env("MISTRAL_API_KEY") or str(load_settings().get("mistral_api_key") or "").strip()


def nvidia_key() -> str:
    return (
        _env("NVIDIA_API_KEY")
        or _env("NGC_API_KEY")
        or str(load_settings().get("nvidia_api_key") or "").strip()
    )



def _nvidia_list_models(api_key: str, timeout: int = 20) -> list[str]:
    """Live catalog from integrate.api.nvidia.com (models change / EOL often)."""
    req = urllib.request.Request(
        "https://integrate.api.nvidia.com/v1/models",
        headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = json.loads(resp.read().decode("utf-8", errors="replace"))
    ids: list[str] = []
    for item in body.get("data") or []:
        if not isinstance(item, dict):
            continue
        mid = str(item.get("id") or "").strip()
        if mid:
            ids.append(mid)
    return ids


def _nvidia_pick_models(api_key: str, preferred: str) -> list[str]:
    """Prefer user model, then small instruct-like ids from live catalog."""
    ordered: list[str] = []
    if preferred:
        ordered.append(preferred)
    try:
        live = _nvidia_list_models(api_key)
    except Exception:
        live = []
    # Prefer smaller / instruct chat models when present
    prefer_sub = (
        "phi-3",
        "nemotron-nano",
        "nemotron-3-nano",
        "gemma-2-2b",
        "gemma-2-9b",
        "llama-3.2-3b",
        "llama-3.1-8b",
        "mistral-7b",
        "instruct",
    )
    scored: list[tuple[int, str]] = []
    for mid in live:
        low = mid.lower()
        # skip pure embedding / rerank / vision-only hints
        if any(x in low for x in ("embed", "rerank", "retrieve", "tts", "whisper", "guard")):
            continue
        score = 50
        for i, sub in enumerate(prefer_sub):
            if sub in low:
                score = i
                break
        if "instruct" in low or "chat" in low or "nemotron" in low:
            scored.append((score, mid))
        elif score < 50:
            scored.append((score, mid))
    scored.sort(key=lambda x: (x[0], len(x[1])))
    for _, mid in scored:
        if mid not in ordered:
            ordered.append(mid)
        if len(ordered) >= 8:
            break
    if not ordered:
        ordered = [preferred or DEFAULT_NVIDIA_MODEL]
    return ordered


def _system_prompt() -> str:
    return (
        "Ты — аналитик Miharu (Windows Security Monitor). Тебе дают ГОТОВЫЙ результат Risk Engine.\n"
        "Правила:\n"
        "1) НЕ меняй уровень риска (LOW/MEDIUM/HIGH) и score.\n"
        "2) НЕ выдумывай угрозы, файлы, процессы, которых нет во входных данных.\n"
        "3) Объясни простым русским: что произошло, почему Risk Engine так решил, что проверить.\n"
        "4) Если overall LOW и нет MEDIUM/HIGH — скажи, что система выглядит здоровой. "
        "НЕ перечисляй и НЕ обсуждай LOW-объекты, allowlisted и служебные пути "
        "(Windows Defender, WinSxS, DriverStore), если нет MEDIUM/HIGH.\n"
        "5) Коротко: 3–6 предложений. БЕЗ markdown: без **, без #, без `, без списков-маркеров. "
        "Только обычный текст."
    )


def strip_ai_markdown(text: str) -> str:
    """Remove common markdown so UI/Telegram show plain text."""
    s = str(text or "")
    s = re.sub(r"[*]{1,3}", "", s)
    s = re.sub(r"`+", "", s)
    s = re.sub(r"^#{1,6}\s*", "", s, flags=re.M)
    s = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", s)
    s = re.sub(r"[ \t]+\n", "\n", s)
    s = re.sub(r"\n{3,}", "\n\n", s)
    return s.strip()


def build_facts_payload(report: dict) -> dict[str, Any]:
    summary = report.get("risk_summary") or {}
    changes = report.get("changes") or {}
    computer = report.get("computer") or {}
    meta = report.get("meta") or {}
    top = summary.get("top_findings") or []
    findings = []
    for f in top[:8]:
        if not isinstance(f, dict):
            continue
        findings.append({
            "name": f.get("name"),
            "kind": f.get("kind"),
            "risk": f.get("risk"),
            "score": f.get("score"),
            "why": f.get("why_flagged") or [],
            "path": f.get("path"),
        })
    return {
        "host": computer.get("name"),
        "generated_at": meta.get("generated_at"),
        "mode": meta.get("mode"),
        "overall_risk": summary.get("overall_risk"),
        "overall_confidence": summary.get("overall_confidence"),
        "counts": summary.get("counts") or {},
        "changes_summary": changes.get("summary"),
        "new_autorun": len(changes.get("new_autorun") or []),
        "new_services": len(changes.get("new_services") or []),
        "new_tasks": len(changes.get("new_scheduled_tasks") or []),
        "new_startup": len(changes.get("new_startup") or []),
        "new_processes": len(changes.get("new_unsigned_processes") or []),
        "new_files": len(changes.get("new_suspicious_files") or []),
        "top_findings": findings,
        "recommendations": (report.get("recommendations") or [])[:5],
    }


def rules_explanation(report: dict) -> dict[str, Any]:
    """Local fallback — no network, no invented risk."""
    summary = report.get("risk_summary") or {}
    overall = str(summary.get("overall_risk") or "LOW").upper()
    counts = summary.get("counts") or {}
    changes = report.get("changes") or {}
    high = int(counts.get("HIGH") or 0)
    med = int(counts.get("MEDIUM") or 0)
    ch_sum = str(changes.get("summary") or "")
    if "No significant" in ch_sum:
        ch_sum = "Значимых изменений с прошлого скана нет."

    if overall == "HIGH" or high:
        title = "Обнаружены потенциальные риски"
        body = (
            f"Risk Engine оценил систему как HIGH (HIGH: {high}, MEDIUM: {med}). "
            "Проверьте объекты в блоке «Требуют внимания»: подпись, путь, автозагрузку и при необходимости VirusTotal. "
            f"{ch_sum}"
        )
    elif overall == "MEDIUM" or med:
        title = "Требуется внимание"
        body = (
            f"Есть объекты среднего риска (MEDIUM: {med}). Критический уровень Risk Engine не выставил. "
            "Имеет смысл просмотреть findings и новые элементы persistence. "
            f"{ch_sum}"
        )
    else:
        title = "Система выглядит здоровой"
        body = (
            "Risk Engine не нашёл объектов MEDIUM/HIGH. "
            + (ch_sum or "Изменений с прошлого скана нет.")
        )

    return {
        "title": title,
        "body": body,
        "provider": "rules",
        "model": "local",
        "overall_risk": overall,
        "source": "risk_engine",
    }


def _chat_completion(url: str, api_key: str, model: str, user_content: str, timeout: int = 45) -> str:
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": _system_prompt()},
            {"role": "user", "content": user_content},
        ],
        "temperature": 0.2,
        "max_tokens": 500,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
        },
        method="POST",
    )
    last_err: Exception | None = None
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = json.loads(resp.read().decode("utf-8", errors="replace"))
            break
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace")[:300]
            last_err = RuntimeError(f"HTTP {e.code} model={model}: {detail}")
            if e.code == 429 and attempt < 3:
                time.sleep(5 * (attempt + 1))  # 5s, 10s, 15s
                continue
            raise last_err from e
    else:
        raise last_err or RuntimeError("AI request failed")
    choices = body.get("choices") or []
    if not choices:
        raise RuntimeError("empty AI response")
    msg = (choices[0].get("message") or {}).get("content") or ""
    text = str(msg).strip()
    if not text:
        raise RuntimeError("empty AI content")
    return text


def _call_mistral(facts: dict) -> dict[str, Any]:
    key = mistral_key()
    if not key:
        raise RuntimeError("MISTRAL_API_KEY not set")
    model = (
        _env("MISTRAL_MODEL")
        or str(load_settings().get("mistral_model") or DEFAULT_MISTRAL_MODEL)
    ).strip()
    user = (
        "Ниже JSON с результатом Risk Engine. Объясни его. "
        "Не меняй overall_risk и score.\n\n"
        + json.dumps(facts, ensure_ascii=False, indent=2)
    )
    models_try = []
    for m in (model, "mistral-small-latest", "open-mistral-7b", "mistral-tiny"):
        if m and m not in models_try:
            models_try.append(m)
    text = ""
    err_last: Exception | None = None
    for m in models_try:
        try:
            text = _chat_completion(MISTRAL_URL, key, m, user)
            model = m
            break
        except Exception as exc:
            err_last = exc
    else:
        raise err_last or RuntimeError("Mistral failed")
    overall = str(facts.get("overall_risk") or "LOW").upper()
    title = {
        "HIGH": "Обнаружены потенциальные риски",
        "MEDIUM": "Требуется внимание",
        "LOW": "Система выглядит здоровой",
    }.get(overall, "Анализ Risk Engine")
    return {
        "title": title,
        "body": text,
        "provider": "mistral",
        "model": model,
        "overall_risk": overall,
        "source": "risk_engine",
    }


def _call_nvidia(facts: dict) -> dict[str, Any]:
    key = nvidia_key()
    if not key:
        raise RuntimeError("NVIDIA_API_KEY not set")
    preferred = (
        _env("NVIDIA_MODEL")
        or str(load_settings().get("nvidia_model") or "")
        or DEFAULT_NVIDIA_MODEL
    ).strip()
    # Live catalog — static ids go EOL on NVIDIA frequently
    candidates = _nvidia_pick_models(nvidia_key(), preferred)

    user = (
        "Ниже JSON с результатом Risk Engine. Объясни его. "
        "Не меняй overall_risk и score.\n\n"
        + json.dumps(facts, ensure_ascii=False, indent=2)
    )
    errors: list[str] = []
    text = ""
    model = candidates[0]
    for model in candidates:
        try:
            text = _chat_completion(NVIDIA_URL, key, model, user)
            break
        except Exception as exc:
            errors.append(f"{model}: {exc}")
    else:
        raise RuntimeError("NVIDIA all models failed: " + " | ".join(errors[:4]))

    overall = str(facts.get("overall_risk") or "LOW").upper()
    title = {
        "HIGH": "Обнаружены потенциальные риски",
        "MEDIUM": "Требуется внимание",
        "LOW": "Система выглядит здоровой",
    }.get(overall, "Анализ Risk Engine")
    return {
        "title": title,
        "body": text,
        "provider": "nvidia",
        "model": model,
        "overall_risk": overall,
        "source": "risk_engine",
    }



def generate_ai_explanation(report: dict) -> dict[str, Any]:
    """Explain Risk Engine result. Never overrides risk levels."""
    provider = ai_provider()
    if provider in ("off", "rules"):
        return rules_explanation(report)

    facts = build_facts_payload(report)
    errors: list[str] = []

    order: list[str]
    if provider == "mistral":
        order = ["mistral"]
    elif provider == "nvidia":
        order = ["nvidia"]
    else:
        # Mistral first (preferred), NVIDIA fallback
        order = []
        if mistral_key():
            order.append("mistral")
        if nvidia_key():
            order.append("nvidia")
        if not order:
            return rules_explanation(report)

    for name in order:
        try:
            if name == "mistral":
                out = _call_mistral(facts)
            else:
                out = _call_nvidia(facts)
            if isinstance(out, dict) and out.get("body"):
                out["body"] = strip_ai_markdown(str(out["body"]))
            if isinstance(out, dict) and out.get("title"):
                out["title"] = strip_ai_markdown(str(out["title"]))
            return out
        except Exception as exc:
            errors.append(f"{name}: {exc}")

    fallback = rules_explanation(report)
    fallback["errors"] = errors
    fallback["provider"] = "rules"
    fallback["model"] = "local-fallback"
    return fallback


def enrich_with_ai(report: dict) -> dict:
    """Attach report['ai'] without changing risk_summary."""
    out = report
    try:
        ai = generate_ai_explanation(out)
        if isinstance(ai, dict):
            if ai.get("body"):
                ai["body"] = strip_ai_markdown(str(ai["body"]))
            if ai.get("title"):
                ai["title"] = strip_ai_markdown(str(ai["title"]))
        out["ai"] = ai
    except Exception as exc:
        ai = rules_explanation(out)
        ai["errors"] = [str(exc)]
        out["ai"] = ai
    return out