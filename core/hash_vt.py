from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from config import CACHE_DIR, ensure_app_dirs

VT_API_URL = "https://www.virustotal.com/api/v3/files/{hash}"
CACHE_PATH = CACHE_DIR / "vt_cache.json"
MAX_HASH_FILES = 40
MAX_VT_LOOKUPS = 10
MIN_FILE_BYTES = 1024
MAX_FILE_BYTES = 50 * 1024 * 1024


def _api_key() -> str:
    return (
        os.environ.get("VT_API_KEY")
        or os.environ.get("VIRUSTOTAL_API_KEY")
        or ""
    ).strip()


def sha256_file(path: str | Path) -> str | None:
    p = Path(path)
    try:
        if not p.is_file():
            return None
        size = p.stat().st_size
        if size < MIN_FILE_BYTES or size > MAX_FILE_BYTES:
            return None
        h = hashlib.sha256()
        with p.open("rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _load_cache() -> dict:
    try:
        if CACHE_PATH.exists():
            return json.loads(CACHE_PATH.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def _save_cache(cache: dict) -> None:
    try:
        ensure_app_dirs()
        CACHE_PATH.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError:
        pass


def vt_lookup(sha256: str, api_key: str | None = None) -> dict[str, Any] | None:
    key = (api_key if api_key is not None else _api_key()).strip()
    if not key or not sha256 or len(sha256) != 64:
        return None

    cache = _load_cache()
    hit = cache.get(sha256)
    if isinstance(hit, dict) and hit.get("ts") and (time.time() - float(hit["ts"])) < 7 * 86400:
        return hit.get("data")

    url = VT_API_URL.format(hash=sha256)
    req = urllib.request.Request(url, headers={"x-apikey": key, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            body = json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            data = {"found": False, "malicious": 0, "suspicious": 0, "undetected": 0, "harmless": 0}
            cache[sha256] = {"ts": time.time(), "data": data}
            _save_cache(cache)
            return data
        return None
    except Exception:
        return None

    attrs = ((body.get("data") or {}).get("attributes") or {})
    stats = attrs.get("last_analysis_stats") or {}
    data = {
        "found": True,
        "malicious": int(stats.get("malicious") or 0),
        "suspicious": int(stats.get("suspicious") or 0),
        "undetected": int(stats.get("undetected") or 0),
        "harmless": int(stats.get("harmless") or 0),
        "reputation": attrs.get("reputation"),
        "meaningful_name": attrs.get("meaningful_name") or "",
    }
    cache[sha256] = {"ts": time.time(), "data": data}
    _save_cache(cache)
    return data


def _candidate_paths(report: dict) -> list[str]:
    paths: list[str] = []
    seen: set[str] = set()

    def add(p: str) -> None:
        p = (p or "").strip()
        if not p:
            return
        key = p.lower()
        if key in seen:
            return
        seen.add(key)
        paths.append(p)

    for it in report.get("suspicious_files") or []:
        if isinstance(it, dict):
            add(str(it.get("Path") or it.get("path") or ""))

    for it in report.get("unsigned_processes") or []:
        if isinstance(it, dict):
            add(str(it.get("Path") or it.get("path") or ""))

    for it in report.get("scored_files") or []:
        if isinstance(it, dict) and str(it.get("risk", "")).upper() in ("HIGH", "MEDIUM"):
            add(str(it.get("path") or ""))

    changes = report.get("changes") or {}
    for key in ("new_suspicious_files", "new_unsigned_processes"):
        for it in changes.get(key) or []:
            if isinstance(it, dict):
                add(str(it.get("Path") or it.get("path") or ""))
            elif isinstance(it, str):
                add(it)

    return paths[:MAX_HASH_FILES]


def enrich_hashes_and_vt(report: dict) -> dict:
    """Add sha256 + optional VT stats onto suspicious_files / unsigned_processes and report['hashes']."""
    out = report
    api_key = _api_key()
    paths = _candidate_paths(out)
    hash_map: dict[str, str] = {}
    vt_map: dict[str, dict] = {}

    for p in paths:
        h = sha256_file(p)
        if h:
            hash_map[p] = h

    lookups = 0
    for p, h in hash_map.items():
        if not api_key or lookups >= MAX_VT_LOOKUPS:
            break
        data = vt_lookup(h, api_key)
        if data is not None:
            vt_map[h] = data
            lookups += 1
            if data.get("found") is not False:
                time.sleep(0.25)

    def patch_list(items: list | None, path_keys: tuple[str, ...] = ("Path", "path")) -> None:
        if not items:
            return
        for it in items:
            if not isinstance(it, dict):
                continue
            p = ""
            for k in path_keys:
                if it.get(k):
                    p = str(it[k])
                    break
            h = hash_map.get(p) or it.get("SHA256") or it.get("sha256")
            if h:
                it["SHA256"] = h
                it["sha256"] = h
                vt = vt_map.get(h)
                if vt:
                    it["vt_malicious"] = int(vt.get("malicious") or 0)
                    it["vt_suspicious"] = int(vt.get("suspicious") or 0)
                    it["vt_positives"] = int(vt.get("malicious") or 0)
                    it["vt_total"] = (
                        int(vt.get("malicious") or 0)
                        + int(vt.get("suspicious") or 0)
                        + int(vt.get("undetected") or 0)
                        + int(vt.get("harmless") or 0)
                    )
                    it["vt_found"] = bool(vt.get("found"))

    patch_list(out.get("suspicious_files"))
    patch_list(out.get("unsigned_processes"))
    patch_list(out.get("processes"))
    patch_list(out.get("scored_files"), ("path", "Path"))

    out["hashes"] = {
        "count": len(hash_map),
        "vt_lookups": len(vt_map),
        "vt_enabled": bool(api_key),
        "items": [
            {
                "path": p,
                "sha256": h,
                "vt": vt_map.get(h),
            }
            for p, h in list(hash_map.items())[:MAX_HASH_FILES]
        ],
    }
    return out