from __future__ import annotations

from typing import Any


def _s(v: Any) -> str:
    return str(v or "").strip()


def _i(v: Any) -> int | None:
    try:
        if v is None or v == "":
            return None
        return int(v)
    except (TypeError, ValueError):
        return None


def index_processes(processes: list) -> dict[int, dict]:
    by_pid: dict[int, dict] = {}
    for it in processes or []:
        if not isinstance(it, dict):
            continue
        pid = _i(it.get("Pid") or it.get("pid") or it.get("ProcessId"))
        if pid is None:
            continue
        by_pid[pid] = {
            "pid": pid,
            "name": _s(it.get("Name") or it.get("name") or ""),
            "path": _s(it.get("Path") or it.get("path") or it.get("ExecutablePath") or ""),
            "parent_pid": _i(it.get("ParentPid") or it.get("parent_pid") or it.get("ParentProcessId")),
            "parent_name": _s(it.get("ParentName") or it.get("parent_name") or ""),
            "parent_path": _s(it.get("ParentPath") or it.get("parent_path") or ""),
            "command_line": _s(it.get("CommandLine") or it.get("command_line") or ""),
            "signature": _s(it.get("Signature") or it.get("signature") or it.get("Status") or ""),
            "signer": _s(it.get("Signer") or it.get("signer") or ""),
        }
    return by_pid


def build_chain(by_pid: dict[int, dict], pid: int | None, max_depth: int = 8) -> list[dict]:
    """Root → … → target (list of nodes)."""
    if pid is None or pid not in by_pid:
        return []
    chain_rev: list[dict] = []
    seen: set[int] = set()
    cur = pid
    depth = 0
    while cur is not None and cur in by_pid and depth < max_depth:
        if cur in seen:
            break
        seen.add(cur)
        node = dict(by_pid[cur])
        chain_rev.append(node)
        pp = node.get("parent_pid")
        if pp is None or pp == cur or pp == 0:
            break
        if pp not in by_pid:
            # synthetic parent from fields
            if node.get("parent_name") or node.get("parent_path"):
                chain_rev.append({
                    "pid": pp,
                    "name": node.get("parent_name") or f"pid:{pp}",
                    "path": node.get("parent_path") or "",
                    "parent_pid": None,
                    "signature": "",
                    "signer": "",
                    "command_line": "",
                    "synthetic": True,
                })
            break
        cur = pp
        depth += 1
    chain_rev.reverse()
    return chain_rev


def chain_for_path(by_pid: dict[int, dict], path: str) -> list[dict]:
    path_l = path.replace("/", "\\").lower().strip()
    if not path_l:
        return []
    # prefer longest-lived / any matching path — take first match with deepest chain
    best: list[dict] = []
    for pid, node in by_pid.items():
        p = (node.get("path") or "").replace("/", "\\").lower()
        if p == path_l or p.endswith("\\" + path_l.split("\\")[-1]):
            if p == path_l or path_l in p:
                ch = build_chain(by_pid, pid)
                if len(ch) > len(best):
                    best = ch
    return best


def format_tree_text(chain: list[dict]) -> str:
    if not chain:
        return ""
    lines = []
    for i, node in enumerate(chain):
        name = node.get("name") or (node.get("path") or "").split("\\")[-1] or f"pid:{node.get('pid')}"
        prefix = ("    " * i) + ("└── " if i else "")
        sig = (node.get("signature") or "").lower()
        mark = ""
        if sig in ("notsigned", "unsigned", "hashmismatch", "error"):
            mark = "  [unsigned]"
        elif sig in ("valid", "validsignature", "signed"):
            mark = "  [signed]"
        lines.append(f"{prefix}{name}{mark}")
    return "\n".join(lines)


def format_tree_html(chain: list[dict]) -> str:
    if not chain:
        return ""
    parts = ['<div class="proc-tree">']
    for i, node in enumerate(chain):
        name = node.get("name") or (node.get("path") or "").split("\\")[-1] or f"pid:{node.get('pid')}"
        path = node.get("path") or ""
        sig = (node.get("signature") or "").lower()
        cls = "u"
        if sig in ("valid", "validsignature", "signed"):
            cls = "s"
        elif sig in ("notsigned", "unsigned", "hashmismatch", "error"):
            cls = "u"
        else:
            cls = "n"
        indent = 14 * i
        branch = "└── " if i else ""
        parts.append(
            f'<div class="pt-node {cls}" style="padding-left:{indent}px" title="{path}">'
            f'<span class="pt-br">{branch}</span>'
            f'<span class="pt-name">{name}</span>'
            f'<span class="pt-sig">{sig or "—"}</span>'
            f"</div>"
        )
    parts.append("</div>")
    return "".join(parts)


def attach_trees_to_report(report: dict) -> dict:
    """Add process_tree to scored_processes and process_trees summary."""
    procs = report.get("processes") or []
    by_pid = index_processes(procs if isinstance(procs, list) else [])
    trees = []

    scored = report.get("scored_processes") or []
    for item in scored:
        if not isinstance(item, dict):
            continue
        path = _s(item.get("path") or (item.get("facts") or {}).get("path"))
        pid = _i((item.get("facts") or {}).get("pid") or item.get("pid"))
        chain = build_chain(by_pid, pid) if pid is not None else chain_for_path(by_pid, path)
        if not chain and path:
            # minimal 2-node from facts
            facts = item.get("facts") or {}
            parent_name = _s(facts.get("parent_name"))
            parent_path = _s(facts.get("parent_path"))
            if parent_name or parent_path:
                chain = [
                    {
                        "pid": None,
                        "name": parent_name or "parent",
                        "path": parent_path,
                        "signature": "",
                        "synthetic": True,
                    },
                    {
                        "pid": None,
                        "name": item.get("name") or path.split("\\")[-1],
                        "path": path,
                        "signature": _s(facts.get("signature")),
                    },
                ]
        item["process_tree"] = chain
        item["process_tree_text"] = format_tree_text(chain)
        risk_u = str(item.get("risk") or "").upper()
        score = int(item.get("score") or 0)
        sig = _s((item.get("facts") or {}).get("signature")).lower()
        interesting = (
            risk_u in ("HIGH", "MEDIUM")
            or score >= 8
            or sig in ("notsigned", "unsigned", "hashmismatch", "error")
            or any(
                str(e.get("type") or "") in (
                    "suspicious_parent", "parent_from_temp", "encoded_command",
                    "combo_unsigned_temp_parent", "combo_unsigned_temp",
                )
                for e in (item.get("evidence") or [])
                if isinstance(e, dict)
            )
        )
        if chain and interesting:
            trees.append({
                "name": item.get("name"),
                "path": path,
                "risk": item.get("risk"),
                "score": item.get("score"),
                "tree": chain,
                "tree_text": item["process_tree_text"],
            })

    # also: unsigned processes from raw list that were not scored
    seen_paths = {
        _s(t.get("path")).replace("/", "\\").lower()
        for t in trees
    }
    for it in (report.get("unsigned_processes") or []):
        if not isinstance(it, dict):
            continue
        path = _s(it.get("Path") or it.get("path"))
        key = path.replace("/", "\\").lower()
        if not key or key in seen_paths:
            continue
        pid = _i(it.get("Pid") or it.get("pid"))
        chain = build_chain(by_pid, pid) if pid is not None else chain_for_path(by_pid, path)
        if len(chain) < 2:
            continue
        seen_paths.add(key)
        trees.append({
            "name": _s(it.get("Name") or it.get("name") or path.split("\\")[-1]),
            "path": path,
            "risk": "LOW",
            "score": 0,
            "tree": chain,
            "tree_text": format_tree_text(chain),
        })

    trees.sort(key=lambda x: (
        {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(str(x.get("risk") or "LOW").upper(), 3),
        -int(x.get("score") or 0),
    ))
    report["process_trees"] = trees[:50]
    return report
