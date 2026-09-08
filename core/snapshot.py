from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any

from config import HISTORY_DIR, REPORT_DIR


def _s(v: Any) -> str:
    return str(v or "").strip()


def _lower(v: Any) -> str:
    return _s(v).lower()


def _path_key(v: Any) -> str:
    return _lower(v).replace("/", "\\")


def _num(v: Any, default: float = 0.0) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def _as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        if not value:
            return []
        return list(value.values())
    return [value]


def _item_key(item: dict, fields: tuple[str, ...]) -> str:
    parts = []
    for f in fields:
        parts.append(_path_key(item.get(f) or ""))
    return "|".join(parts)


def build_snapshot(report: dict) -> dict:
    computer = report.get("computer") or {}
    meta = report.get("meta") or {}
    scan = report.get("scan") or {}
    disks = report.get("disks") or {}
    defender = report.get("defender")

    timestamp = _s(
        meta.get("generated_at")
        or scan.get("timestamp")
        or datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    )

    suspicious = []
    for it in _as_list(report.get("suspicious_files")):
        if not isinstance(it, dict):
            continue
        suspicious.append({
            "path": _s(it.get("Path") or it.get("path")),
            "name": _s(it.get("Name") or it.get("name")),
            "signature": _s(it.get("Signature") or it.get("signature")),
            "signer": _s(it.get("Signer") or it.get("signer")),
            "size_mb": _num(it.get("SizeMB") or it.get("size_mb")),
        })

    processes = []
    seen = set()
    for it in _as_list(report.get("processes") or report.get("unsigned_processes")):
        if not isinstance(it, dict):
            continue
        p = _s(it.get("Path") or it.get("path"))
        key = _path_key(p)
        if not key or key in seen:
            continue
        seen.add(key)
        processes.append({
            "path": p,
            "name": _s(it.get("Name") or it.get("name")),
            "signature": _s(it.get("Signature") or it.get("Status") or it.get("signature")),
            "signer": _s(it.get("Signer") or it.get("signer")),
            "parent_name": _s(it.get("ParentName") or it.get("parent_name")),
            "parent_path": _s(it.get("ParentPath") or it.get("parent_path")),
            "pid": it.get("Pid") or it.get("pid"),
            "parent_pid": it.get("ParentPid") or it.get("parent_pid"),
        })

    autorun = []
    for it in _as_list(report.get("autorun")):
        if not isinstance(it, dict):
            continue
        name = _s(it.get("Name") or it.get("name"))
        if _lower(name) in ("psdrive", "pspath", "psparentpath", "pschildname", "psprovider"):
            continue
        autorun.append({
            "key": _s(it.get("Key") or it.get("key")),
            "name": name,
            "value": _s(it.get("Value") or it.get("value")),
        })

    tasks = []
    for it in _as_list(report.get("scheduled_tasks")):
        if not isinstance(it, dict):
            continue
        tasks.append({
            "task_path": _s(it.get("TaskPath") or it.get("task_path") or it.get("Path")),
            "task_name": _s(it.get("TaskName") or it.get("task_name") or it.get("Name")),
            "state": _s(it.get("State") or it.get("state")),
        })

    services = []
    for it in _as_list(report.get("services")):
        if not isinstance(it, dict):
            continue
        services.append({
            "name": _s(it.get("Name") or it.get("ServiceName") or it.get("name")),
            "display_name": _s(it.get("DisplayName") or it.get("display_name")),
            "path": _s(it.get("Path") or it.get("ImagePath") or it.get("path")),
            "start_type": _s(it.get("StartMode") or it.get("StartType") or it.get("Start") or it.get("start_type")),
            "state": _s(it.get("State") or it.get("state")),
            "start_name": _s(it.get("StartName") or it.get("start_name")),
            "signature": _s(it.get("Signature") or it.get("signature")),
            "signer": _s(it.get("Signer") or it.get("signer")),
        })

    startup = []
    for it in _as_list(report.get("startup_items")):
        if isinstance(it, str):
            path = _s(it)
        elif isinstance(it, dict):
            path = _s(it.get("Path") or it.get("path") or it.get("Name"))
        else:
            continue
        leaf = path.replace("/", "\\").rsplit("\\", 1)[-1].lower()
        if not path or leaf == "desktop.ini":
            continue
        startup.append({"path": path})

    folders_c = []
    for it in _as_list(report.get("root_folders_c") or report.get("RootFoldersC")):
        if isinstance(it, dict):
            folders_c.append({
                "path": _s(it.get("Path") or it.get("path")),
                "size_gb": _num(it.get("SizeGB") or it.get("size_gb")),
            })

    folders_d = []
    for it in _as_list(report.get("root_folders_d") or report.get("RootFoldersD")):
        if isinstance(it, dict):
            folders_d.append({
                "path": _s(it.get("Path") or it.get("path")),
                "size_gb": _num(it.get("SizeGB") or it.get("size_gb")),
            })

    user_folders = []
    for it in _as_list(report.get("user_folders")):
        if isinstance(it, dict):
            user_folders.append({
                "path": _s(it.get("Path") or it.get("path")),
                "size_gb": _num(it.get("SizeGB") or it.get("size_gb")),
            })

    large_files = []
    for it in _as_list(report.get("large_files")):
        if isinstance(it, dict):
            large_files.append({
                "path": _s(it.get("Path") or it.get("path")),
                "size_gb": _num(it.get("SizeGB") or it.get("size_gb")),
            })

    scored = []
    for it in _as_list(report.get("scored_files")):
        if isinstance(it, dict) and not (it.get("facts") or {}).get("skipped"):
            scored.append({
                "path": _s(it.get("path")),
                "name": _s(it.get("name")),
                "score": it.get("score", 0),
                "risk": _s(it.get("risk")),
            })

    return {
        "version": 2,
        "timestamp": timestamp,
        "system": {
            "hostname": _s(computer.get("name")),
            "user": _s(computer.get("user")),
            "os": _s(computer.get("os")),
        },
        "storage": {
            "disks": disks if isinstance(disks, dict) else {},
            "root_folders_c": folders_c,
            "root_folders_d": folders_d,
            "user_folders": user_folders,
            "large_files": large_files,
        },
        "security": {
            "defender": defender if isinstance(defender, dict) else {},
            "suspicious_files": suspicious,
            "scored_files": scored,
        },
        "persistence": {
            "autorun": autorun,
            "scheduled_tasks": tasks,
            "services": services,
            "startup": startup,
        },
        "processes": {
            "unsigned": processes,
        },
        "meta": {
            "duration_sec": meta.get("duration_sec") or scan.get("duration_sec"),
            "files_scanned": meta.get("files_scanned") or scan.get("files_scanned"),
        },
    }


def save_snapshot(snapshot: dict, history_dir: Path | None = None) -> Path:
    history_dir = history_dir or HISTORY_DIR
    history_dir.mkdir(parents=True, exist_ok=True)

    ts = _s(snapshot.get("timestamp")).replace(":", "-").replace(" ", "_")
    if not ts:
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    path = history_dir / f"snapshot_{ts}.json"
    path.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding="utf-8")

    latest = history_dir / "snapshot_latest.json"
    latest.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding="utf-8")

    _prune_history(history_dir, keep=30)
    return path


def _prune_history(history_dir: Path, keep: int = 30) -> None:
    files = sorted(
        history_dir.glob("snapshot_*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    for f in files:
        if f.name == "snapshot_latest.json":
            continue
    real = [f for f in files if f.name != "snapshot_latest.json"]
    for f in real[keep:]:
        try:
            f.unlink()
        except OSError:
            pass


def normalize_snapshot(raw: dict) -> dict:
    if not isinstance(raw, dict):
        return {}
    if raw.get("version") == 2 and "persistence" in raw:
        return raw

    disks = {}
    if raw.get("DiskC"):
        disks["C"] = raw["DiskC"] if isinstance(raw["DiskC"], dict) else {}
    if raw.get("DiskD"):
        disks["D"] = raw["DiskD"] if isinstance(raw["DiskD"], dict) else {}

    def fold(items):
        out = []
        for it in _as_list(items):
            if isinstance(it, dict):
                out.append({
                    "path": _s(it.get("Path") or it.get("path")),
                    "size_gb": _num(it.get("SizeGB") or it.get("size_gb")),
                })
        return out

    autorun = []
    for it in _as_list(raw.get("AutorunRegistry") or raw.get("autorun")):
        if isinstance(it, dict):
            autorun.append({
                "key": _s(it.get("Key") or it.get("key")),
                "name": _s(it.get("Name") or it.get("name")),
                "value": _s(it.get("Value") or it.get("value")),
            })

    tasks = []
    for it in _as_list(raw.get("ScheduledTasks") or raw.get("scheduled_tasks")):
        if isinstance(it, dict):
            tasks.append({
                "task_path": _s(it.get("TaskPath") or it.get("task_path")),
                "task_name": _s(it.get("TaskName") or it.get("task_name") or it.get("Name")),
                "state": _s(it.get("State") or it.get("state")),
            })

    sus = []
    for it in _as_list(raw.get("SuspiciousFiles") or raw.get("suspicious_files")):
        if isinstance(it, dict):
            sus.append({
                "path": _s(it.get("Path") or it.get("path")),
                "name": _s(it.get("Name") or it.get("name")),
                "signature": _s(it.get("Signature") or it.get("signature")),
                "signer": _s(it.get("Signer") or it.get("signer")),
                "size_mb": _num(it.get("SizeMB") or it.get("size_mb")),
            })

    procs = []
    for it in _as_list(raw.get("UnsignedProcesses") or raw.get("unsigned_processes")):
        if isinstance(it, dict):
            procs.append({
                "path": _s(it.get("Path") or it.get("path")),
                "signature": _s(it.get("Status") or it.get("Signature") or ""),
                "signer": _s(it.get("Signer") or ""),
            })

    return {
        "version": 1,
        "timestamp": _s(raw.get("Timestamp") or raw.get("timestamp")),
        "system": {
            "hostname": _s((raw.get("system") or {}).get("hostname") if isinstance(raw.get("system"), dict) else ""),
        },
        "storage": {
            "disks": disks or (raw.get("storage") or {}).get("disks") or {},
            "root_folders_c": fold(raw.get("RootFoldersC") or raw.get("root_folders_c")),
            "root_folders_d": fold(raw.get("RootFoldersD") or raw.get("root_folders_d")),
            "user_folders": fold(raw.get("UserFolders") or raw.get("user_folders")),
            "large_files": [],
        },
        "security": {
            "defender": raw.get("Defender") or raw.get("defender") or {},
            "suspicious_files": sus,
            "scored_files": [],
        },
        "persistence": {
            "autorun": autorun,
            "scheduled_tasks": tasks,
            "services": [],
            "startup": [],
        },
        "processes": {
            "unsigned": procs,
        },
        "meta": {},
    }


def load_snapshot(path: Path) -> dict | None:
    try:
        raw = json.loads(path.read_text(encoding="utf-8-sig"))
        return normalize_snapshot(raw)
    except Exception:
        return None


def list_snapshots(history_dir: Path | None = None) -> list[Path]:
    history_dir = history_dir or HISTORY_DIR
    if not history_dir.exists():
        return []
    files = [
        p for p in history_dir.glob("snapshot_*.json")
        if p.name != "snapshot_latest.json"
    ]
    return sorted(files, key=lambda p: p.stat().st_mtime)


def get_previous_snapshot(
    history_dir: Path | None = None,
    exclude: Path | None = None,
) -> dict | None:
    history_dir = history_dir or HISTORY_DIR
    files = list_snapshots(history_dir)
    if exclude is not None:
        files = [f for f in files if f.resolve() != exclude.resolve()]
    if not files:
        latest = history_dir / "snapshot_latest.json"
        if latest.exists() and (exclude is None or latest.resolve() != exclude.resolve()):
            return load_snapshot(latest)
        return None
    if len(files) >= 2:
        return load_snapshot(files[-2] if exclude and files[-1].resolve() == exclude.resolve() else files[-1])
    return load_snapshot(files[-1]) if exclude is None else (
        load_snapshot(files[-2]) if len(files) >= 2 else None
    )


def _index(items: list[dict], fields: tuple[str, ...]) -> dict[str, dict]:
    out = {}
    for it in items:
        if not isinstance(it, dict):
            continue
        k = _item_key(it, fields)
        if k and k != "|" * (len(fields) - 1):
            out[k] = it
    return out


def _diff_lists(
    current: list[dict],
    previous: list[dict],
    fields: tuple[str, ...],
    *,
    baseline_if_prev_empty_min: int | None = None,
) -> tuple[list[dict], list[dict], list[dict]]:
    """Compare lists by composite key.

    Collection baseline (no added/removed noise) when:
    - previous empty and current size >= threshold, OR
    - previous small (< threshold) and current jumped sharply (>= threshold and >= 2x previous)
    """
    cur_map = _index(current, fields)
    prev_map = _index(previous, fields)
    n_cur = len(cur_map)
    n_prev = len(prev_map)

    if baseline_if_prev_empty_min is not None:
        thr = baseline_if_prev_empty_min
        is_baseline = False
        if n_prev == 0 and n_cur >= thr:
            is_baseline = True
        elif n_prev > 0 and n_prev < thr and n_cur >= thr and n_cur >= n_prev * 2:
            is_baseline = True
        if is_baseline:
            return [], [], [{"current": v, "previous": None} for v in cur_map.values()]

    added = [cur_map[k] for k in cur_map if k not in prev_map]
    removed = [prev_map[k] for k in prev_map if k not in cur_map]
    common = []
    for k in cur_map:
        if k in prev_map:
            common.append({"current": cur_map[k], "previous": prev_map[k]})
    return added, removed, common


def _folder_deltas(
    current: list[dict],
    previous: list[dict],
    threshold_gb: float = 0.5,
) -> list[dict]:
    cur_map = {_path_key(it.get("path")): it for it in current if isinstance(it, dict)}
    prev_map = {_path_key(it.get("path")): it for it in previous if isinstance(it, dict)}
    deltas = []
    for k, cur in cur_map.items():
        if k not in prev_map:
            continue
        old = _num(prev_map[k].get("size_gb"))
        new = _num(cur.get("size_gb"))
        delta = round(new - old, 2)
        if abs(delta) >= threshold_gb:
            deltas.append({
                "path": cur.get("path"),
                "old_gb": old,
                "new_gb": new,
                "delta_gb": delta,
            })
    deltas.sort(key=lambda x: abs(x["delta_gb"]), reverse=True)
    return deltas


def _disk_deltas(current: dict, previous: dict) -> list[dict]:
    result = []
    if not isinstance(current, dict) or not isinstance(previous, dict):
        return result
    for letter, cur in current.items():
        prev = previous.get(letter)
        if not isinstance(cur, dict) or not isinstance(prev, dict):
            continue
        used_delta = round(_num(cur.get("UsedGB")) - _num(prev.get("UsedGB")), 2)
        free_delta = round(_num(cur.get("FreeGB")) - _num(prev.get("FreeGB")), 2)
        if used_delta == 0 and free_delta == 0:
            continue
        result.append({
            "disk": letter,
            "used_delta_gb": used_delta,
            "free_delta_gb": free_delta,
            "used_pct": _num(cur.get("UsedPct")),
        })
    return result


def diff_snapshots(current: dict, previous: dict | None) -> dict:
    if not previous:
        return {
            "baseline": True,
            "previous_timestamp": None,
            "current_timestamp": current.get("timestamp"),
            "new_autorun": [],
            "removed_autorun": [],
            "new_scheduled_tasks": [],
            "removed_scheduled_tasks": [],
            "new_services": [],
            "removed_services": [],
            "new_unsigned_processes": [],
            "removed_unsigned_processes": [],
            "new_suspicious_files": [],
            "removed_suspicious_files": [],
            "new_startup": [],
            "removed_startup": [],
            "folder_deltas": [],
            "disk_deltas": [],
            "defender_changed": False,
            "summary": "Baseline snapshot — no previous scan to compare.",
        }

    cur_p = current.get("persistence") or {}
    prev_p = previous.get("persistence") or {}
    cur_sec = current.get("security") or {}
    prev_sec = previous.get("security") or {}
    cur_proc = current.get("processes") or {}
    prev_proc = previous.get("processes") or {}
    cur_st = current.get("storage") or {}
    prev_st = previous.get("storage") or {}

    new_autorun, rem_autorun, _ = _diff_lists(
        _as_list(cur_p.get("autorun")),
        _as_list(prev_p.get("autorun")),
        ("key", "name"),
        baseline_if_prev_empty_min=25,
    )
    new_tasks, rem_tasks, _ = _diff_lists(
        _as_list(cur_p.get("scheduled_tasks")),
        _as_list(prev_p.get("scheduled_tasks")),
        ("task_path", "task_name"),
        baseline_if_prev_empty_min=30,
    )
    new_services, rem_services, _ = _diff_lists(
        _as_list(cur_p.get("services")),
        _as_list(prev_p.get("services")),
        ("name",),
        baseline_if_prev_empty_min=15,
    )
    new_procs, rem_procs, _ = _diff_lists(
        _as_list(cur_proc.get("unsigned")),
        _as_list(prev_proc.get("unsigned")),
        ("path",),
        baseline_if_prev_empty_min=15,
    )
    new_sus, rem_sus, _ = _diff_lists(
        _as_list(cur_sec.get("suspicious_files")),
        _as_list(prev_sec.get("suspicious_files")),
        ("path",),
        baseline_if_prev_empty_min=40,
    )
    new_startup, rem_startup, _ = _diff_lists(
        _as_list(cur_p.get("startup")),
        _as_list(prev_p.get("startup")),
        ("path",),
        baseline_if_prev_empty_min=20,
    )

    folder_deltas = []
    folder_deltas += _folder_deltas(
        _as_list(cur_st.get("root_folders_c")),
        _as_list(prev_st.get("root_folders_c")),
    )
    folder_deltas += _folder_deltas(
        _as_list(cur_st.get("root_folders_d")),
        _as_list(prev_st.get("root_folders_d")),
    )
    folder_deltas += _folder_deltas(
        _as_list(cur_st.get("user_folders")),
        _as_list(prev_st.get("user_folders")),
    )
    folder_deltas.sort(key=lambda x: abs(x.get("delta_gb", 0)), reverse=True)

    disk_deltas = _disk_deltas(
        cur_st.get("disks") or {},
        prev_st.get("disks") or {},
    )

    cur_def = cur_sec.get("defender") or {}
    prev_def = prev_sec.get("defender") or {}
    defender_changed = False
    defender_details = []
    if isinstance(cur_def, dict) and isinstance(prev_def, dict) and (cur_def or prev_def):
        for field in ("Enabled", "RealTime", "SignatureAge"):
            if cur_def.get(field) != prev_def.get(field):
                defender_changed = True
                defender_details.append({
                    "field": field,
                    "old": prev_def.get(field),
                    "new": cur_def.get(field),
                })

    parts = []
    if new_autorun:
        parts.append(f"+{len(new_autorun)} autorun")
    if new_tasks:
        parts.append(f"+{len(new_tasks)} tasks")
    if new_services:
        parts.append(f"+{len(new_services)} services")
    if new_procs:
        parts.append(f"+{len(new_procs)} processes")
    if new_sus:
        parts.append(f"+{len(new_sus)} suspicious files")
    if folder_deltas:
        parts.append(f"{len(folder_deltas)} folder size changes")
    if defender_changed:
        parts.append("defender changed")
    summary = ", ".join(parts) if parts else "No significant changes since previous scan."

    return {
        "baseline": False,
        "previous_timestamp": previous.get("timestamp"),
        "current_timestamp": current.get("timestamp"),
        "new_autorun": new_autorun,
        "removed_autorun": rem_autorun,
        "new_scheduled_tasks": new_tasks,
        "removed_scheduled_tasks": rem_tasks,
        "new_services": new_services,
        "removed_services": rem_services,
        "new_unsigned_processes": new_procs,
        "removed_unsigned_processes": rem_procs,
        "new_suspicious_files": new_sus,
        "removed_suspicious_files": rem_sus,
        "new_startup": new_startup,
        "removed_startup": rem_startup,
        "folder_deltas": folder_deltas,
        "disk_deltas": disk_deltas,
        "defender_changed": defender_changed,
        "defender_details": defender_details,
        "summary": summary,
    }


def apply_snapshot_pipeline(report: dict) -> dict:
    from config import SCHEMA_VERSION
    report = dict(report)
    report["schema_version"] = report.get("schema_version") or SCHEMA_VERSION
    out = deepcopy(report)

    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    files = list_snapshots()
    previous = load_snapshot(files[-1]) if files else None

    snap = build_snapshot(out)

    if previous and _s(previous.get("timestamp")) == _s(snap.get("timestamp")):
        previous = load_snapshot(files[-2]) if len(files) >= 2 else None

    changes = diff_snapshots(snap, previous)
    snap_path = save_snapshot(snap)

    out["snapshot"] = {
        "path": str(snap_path),
        "timestamp": snap.get("timestamp"),
        "version": 2,
    }
    out["changes"] = {
        "new_autorun": changes.get("new_autorun") or [],
        "new_scheduled_tasks": changes.get("new_scheduled_tasks") or [],
        "new_unsigned_processes": changes.get("new_unsigned_processes") or [],
        "new_suspicious_files": changes.get("new_suspicious_files") or [],
        "new_services": changes.get("new_services") or [],
        "new_startup": changes.get("new_startup") or [],
        "removed_autorun": changes.get("removed_autorun") or [],
        "removed_scheduled_tasks": changes.get("removed_scheduled_tasks") or [],
        "removed_services": changes.get("removed_services") or [],
        "folder_deltas": [
            {
                "Path": d.get("path"),
                "OldGB": d.get("old_gb"),
                "NewGB": d.get("new_gb"),
                "DeltaGB": d.get("delta_gb"),
            }
            for d in (changes.get("folder_deltas") or [])
        ],
        "disk_deltas": changes.get("disk_deltas") or [],
        "defender_changed": changes.get("defender_changed"),
        "defender_details": changes.get("defender_details") or [],
        "summary": changes.get("summary"),
        "baseline": changes.get("baseline"),
        "previous_timestamp": changes.get("previous_timestamp"),
    }
    out["snapshot_full"] = snap
    out["diff"] = changes

    return out