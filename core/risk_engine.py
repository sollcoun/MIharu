from __future__ import annotations

from copy import deepcopy
from typing import Any


KNOWN_PUBLISHERS = {
    "microsoft",
    "microsoft corporation",
    "microsoft windows",
    "google",
    "google llc",
    "mozilla",
    "mozilla corporation",
    "adobe",
    "adobe systems",
    "oracle",
    "intel",
    "nvidia",
    "amd",
    "apple",
    "dropbox",
    "spotify",
    "discord",
    "valve",
    "steam",
    "jetbrains",
    "python software foundation",
    "docker",
    "docker inc",
    "canonical",
    "github",
    "git for windows",
    "notepad++",
    "7-zip",
    "winrar",
    "vlc",
    "videolan",
}

SYSTEM_PATH_PREFIXES = (
    r"c:\windows\system32",
    r"c:\windows\syswow64",
    r"c:\windows\winsxs",
    r"c:\program files\windows",
    r"c:\program files (x86)\windows",
)

TEMP_PATH_MARKERS = (
    r"\temp\\",
    r"\tmp\\",
    r"\appdata\local\temp",
    r"\appdata\roaming\temp",
    r"\downloads\\",
)

SUSPICIOUS_NAME_PARTS = (
    "crack",
    "keygen",
    "activator",
    "patch",
    "loader",
    "injector",
    "svchost",
    "winlogon",
    "csrss",
    "lsass",
    "explorer",
    "invoice",
    "payment",
    "resume",
    "update_helper",
    "setup_",
)


WEIGHTS = {
    "valid_microsoft_signature": -30,
    "known_publisher": -15,
    "known_system_path": -15,
    "valid_signature": -10,
    "unsigned": 5,
    "unknown_publisher": 5,
    "new_executable": 5,
    "user_temp": 3,
    "suspicious_name": 8,
    "double_extension": 20,
    "suspicious_autorun": 20,
    "suspicious_scheduled_task": 20,
    "new_service": 15,
    "service_unknown_path": 10,
    "known_malicious_hash": 100,
    "vt_malicious": 40,
    "vt_suspicious": 15,
    "vt_clean": -8,
    "suspicious_parent": 12,
    "parent_from_temp": 10,
    "temp_process": 5,
    "encoded_command": 15,
    "combo_unsigned_temp": 12,
    "allowlisted": -50,
    "combo_unsigned_temp_parent": 18,
    "combo_new_persistence": 15,
    "combo_double_ext_new": 10,
    "combo_vt_unsigned": 12,
}

EVIDENCE_LABELS = {
    "unsigned": "No digital signature",
    "unknown_publisher": "Unknown publisher",
    "new_executable": "New since previous scan",
    "user_temp": "Located in user Temp/Downloads",
    "suspicious_name": "Suspicious file name",
    "double_extension": "Double extension",
    "suspicious_autorun": "Registered in autorun",
    "suspicious_scheduled_task": "Registered as scheduled task",
    "new_service": "New Windows service",
    "service_unknown_path": "Service binary outside system paths",
    "known_malicious_hash": "Known malicious hash",
    "vt_malicious": "VirusTotal detections (high)",
    "vt_suspicious": "VirusTotal detections (low)",
    "vt_clean": "VirusTotal clean",
    "valid_microsoft_signature": "Valid Microsoft signature",
    "known_publisher": "Known trusted publisher",
    "known_system_path": "Located in system path",
    "allowlisted": "Allowlisted (known benign path/name)",
    "valid_signature": "Valid digital signature",
    "suspicious_parent": "Suspicious parent process",
    "parent_from_temp": "Parent from Temp",
    "temp_process": "Process running from Temp",
    "encoded_command": "Encoded / obfuscated command line",
    "combo_unsigned_temp": "Chain: unsigned in Temp/Downloads",
    "combo_unsigned_temp_parent": "Chain: unsigned Temp + suspicious parent",
    "combo_new_persistence": "Chain: new object + persistence",
    "combo_double_ext_new": "Chain: double extension + new file",
    "combo_vt_unsigned": "Chain: VT detections + unsigned",
    "dev_tool_path": "Development tool path",
    "script_context": "Script context",
}


def _s(v: Any) -> str:
    return str(v or "").strip()


def _lower(v: Any) -> str:
    return _s(v).lower()


def _path(v: Any) -> str:
    return _lower(v).replace("/", "\\")


def _is_microsoft_signer(signer: str) -> bool:
    s = _lower(signer)
    return "microsoft" in s


def _is_known_publisher(signer: str) -> bool:
    s = _lower(signer)
    if not s:
        return False
    if _is_microsoft_signer(s):
        return True
    for p in KNOWN_PUBLISHERS:
        if p in s:
            return True
    return False


def _is_system_path(path: str) -> bool:
    p = _path(path)
    return any(p.startswith(pref) for pref in SYSTEM_PATH_PREFIXES)


def _is_temp_path(path: str) -> bool:
    p = _path(path)
    return any(m in p for m in TEMP_PATH_MARKERS)


def _has_double_extension(name: str) -> bool:
    n = _lower(name)
    import re
    return bool(re.search(
        r"\.(pdf|doc|docx|xls|xlsx|jpg|jpeg|png|txt|zip|rar)\s*\.(exe|scr|bat|cmd|vbs|js|jse|wsf)$",
        n,
    ))


def _has_suspicious_name(name: str) -> bool:
    n = _lower(name)
    return any(part in n for part in SUSPICIOUS_NAME_PARTS)


def _signature_status(facts: dict) -> str:
    return _lower(facts.get("signature") or facts.get("Signature") or facts.get("Status") or "")


def _score_to_risk(score: int) -> str:
    if score >= 30:
        return "HIGH"
    if score >= 15:
        return "MEDIUM"
    return "LOW"


def _confidence(evidence: list[dict], score: int) -> str:
    if not evidence:
        return "LOW"
    abs_weights = [abs(e.get("weight", 0)) for e in evidence]
    strong = sum(1 for w in abs_weights if w >= 15)
    total = len(evidence)
    if strong >= 2 or (strong >= 1 and total >= 3):
        return "HIGH"
    if score >= 25 and total >= 2:
        return "HIGH"
    if total == 1 and abs_weights[0] < 10:
        return "LOW"
    if total >= 3:
        return "HIGH"
    return "MEDIUM"



def _types(evidence: list[dict]) -> set[str]:
    return {str(e.get("type") or "") for e in evidence if isinstance(e, dict)}


def apply_combo_rules(evidence: list[dict], facts: dict | None = None) -> list[dict]:
    """Boost score when independent weak signals form a chain."""
    facts = facts or {}
    types = _types(evidence)
    out = list(evidence)

    def has(*need: str) -> bool:
        return all(t in types for t in need)

    def add(combo_type: str, weight: int, detail: str = "") -> None:
        if combo_type in types:
            return
        item = {"type": combo_type, "weight": weight}
        if detail:
            item["detail"] = detail
        out.append(item)
        types.add(combo_type)

    unsigned = "unsigned" in types or "unknown_publisher" in types
    in_temp = "user_temp" in types or "temp_process" in types
    parent_bad = "suspicious_parent" in types or "parent_from_temp" in types
    persistence = (
        "suspicious_autorun" in types
        or "suspicious_scheduled_task" in types
        or "new_service" in types
    )
    is_new = "new_executable" in types or bool(facts.get("new_since_snapshot"))
    vt_bad = "vt_malicious" in types or "vt_suspicious" in types

    if unsigned and in_temp:
        add("combo_unsigned_temp", WEIGHTS["combo_unsigned_temp"])
    if unsigned and in_temp and parent_bad:
        add("combo_unsigned_temp_parent", WEIGHTS["combo_unsigned_temp_parent"])
    if is_new and persistence:
        add("combo_new_persistence", WEIGHTS["combo_new_persistence"])
    if "double_extension" in types and is_new:
        add("combo_double_ext_new", WEIGHTS["combo_double_ext_new"])
    if vt_bad and unsigned:
        add("combo_vt_unsigned", WEIGHTS["combo_vt_unsigned"])

    return out


def make_verdict(
    *,
    name: str,
    path: str,
    kind: str,
    evidence: list[dict],
    facts: dict | None = None,
    extra: dict | None = None,
) -> dict:
    """Single product verdict: facts → evidence → score → risk → confidence."""
    facts = dict(facts or {})
    evidence = list(evidence or [])
    try:
        from core.allowlist import allowlist_hit
        hit = allowlist_hit(path, name)
        if hit and not any(isinstance(e, dict) and e.get("type") == "allowlisted" for e in evidence):
            evidence.append(hit)
    except Exception:
        pass
    evidence = apply_combo_rules(evidence, facts)
    score = max(0, sum(int(e.get("weight") or 0) for e in evidence if isinstance(e, dict)))
    risk = _score_to_risk(score)
    confidence = _confidence(evidence, score)

    positive = [e for e in evidence if int(e.get("weight") or 0) > 0]
    negative = [e for e in evidence if int(e.get("weight") or 0) < 0]
    why_flagged = [EVIDENCE_LABELS.get(e["type"], e["type"]) for e in positive]
    mitigating = [EVIDENCE_LABELS.get(e["type"], e["type"]) for e in negative]

    if risk == "HIGH":
        conclusion = "HIGH RISK. Strong indicators of potential threat."
    elif risk == "MEDIUM":
        conclusion = "MEDIUM RISK. Multiple indicators require investigation."
    else:
        conclusion = "LOW RISK. Insufficient evidence to classify as malicious."

    verdict = {
        "name": name,
        "path": path,
        "kind": kind,
        "facts": facts,
        "evidence": evidence,
        "score": score,
        "risk": risk,
        "confidence": confidence,
        "why_flagged": why_flagged,
        "mitigating": mitigating,
        "conclusion": conclusion,
        "schema": "verdict_v1",
    }
    if extra:
        for k, v in extra.items():
            if k not in verdict:
                verdict[k] = v
    return verdict


def evaluate_file(facts: dict) -> dict:
    evidence: list[dict] = []
    path = _s(facts.get("path") or facts.get("Path") or "")
    name = _s(facts.get("name") or facts.get("Name") or path.split("\\")[-1])
    signature = _signature_status(facts)
    signer = _s(facts.get("signer") or facts.get("Signer") or facts.get("publisher") or facts.get("Publisher") or "")
    is_new = bool(facts.get("new_since_snapshot") or facts.get("is_new") or False)
    in_autorun = bool(facts.get("autorun") or facts.get("in_autorun") or False)
    in_task = bool(facts.get("scheduled_task") or facts.get("in_task") or False)
    double_ext = bool(facts.get("double_extension")) or _has_double_extension(name)
    vt_positives = facts.get("vt_positives")
    vt_total = facts.get("vt_total")
    sha256 = _s(facts.get("sha256") or facts.get("hash") or "")

    if signature in ("valid", "validsignature", "signed"):
        if _is_microsoft_signer(signer):
            evidence.append({"type": "valid_microsoft_signature", "weight": WEIGHTS["valid_microsoft_signature"]})
        else:
            evidence.append({"type": "valid_signature", "weight": WEIGHTS["valid_signature"]})
    elif signature in ("notsigned", "unsigned", "not signed", "hashmismatch", "nottrusted", "error", "", "unknown"):
        in_pf = _is_system_path(path) or "\\program files" in _path(path)
        if signature in ("", "unknown"):
            evidence.append({"type": "unsigned", "weight": 1 if in_pf else 2})
        elif in_pf:
            evidence.append({"type": "unsigned", "weight": 2})
        else:
            evidence.append({"type": "unsigned", "weight": WEIGHTS["unsigned"]})

    in_pf = "\\program files" in _path(path) or _is_system_path(path)

    if signer:
        if _is_known_publisher(signer):
            evidence.append({"type": "known_publisher", "weight": WEIGHTS["known_publisher"]})
        elif not in_pf:
            evidence.append({"type": "unknown_publisher", "weight": WEIGHTS["unknown_publisher"]})
        else:
            evidence.append({"type": "unknown_publisher", "weight": 2})
    else:
        if signature not in ("valid", "validsignature", "signed"):
            if in_pf:
                evidence.append({"type": "unknown_publisher", "weight": 2})
            else:
                evidence.append({"type": "unknown_publisher", "weight": WEIGHTS["unknown_publisher"]})

    if _is_system_path(path):
        evidence.append({"type": "known_system_path", "weight": WEIGHTS["known_system_path"]})

    dev_markers = (
        "\\lightning-services\\",
        "\\xampp\\",
        "\\laragon\\",
        "\\wamp\\",
        "\\wamp64\\",
        "\\node_modules\\",
        "\\.venv\\",
        "\\venv\\",
        "\\virtualenv\\",
    )
    if any(m in _path(path) for m in dev_markers) and not is_new and not in_autorun:
        evidence.append({"type": "dev_tool_path", "weight": -4})

    if is_new:
        evidence.append({"type": "new_executable", "weight": WEIGHTS["new_executable"]})

    if _is_temp_path(path):
        evidence.append({"type": "user_temp", "weight": WEIGHTS["user_temp"]})

    if _has_suspicious_name(name):
        evidence.append({"type": "suspicious_name", "weight": WEIGHTS["suspicious_name"]})

    if double_ext:
        evidence.append({"type": "double_extension", "weight": WEIGHTS["double_extension"]})

    strong_bad = (
        is_new
        or double_ext
        or _is_temp_path(path)
        or _has_suspicious_name(name)
        or any(e["type"] in ("vt_malicious", "known_malicious_hash", "double_extension") for e in evidence)
    )
    positive_so_far = sum(e["weight"] for e in evidence if e["weight"] > 0)
    in_pf = "\\program files" in _path(path) or _is_system_path(path)

    if in_autorun:
        if strong_bad:
            evidence.append({"type": "suspicious_autorun", "weight": WEIGHTS["suspicious_autorun"]})
        elif not in_pf and positive_so_far >= 10:
            evidence.append({"type": "suspicious_autorun", "weight": 8})
        elif not in_pf:
            evidence.append({"type": "suspicious_autorun", "weight": 2})

    if in_task:
        if strong_bad:
            evidence.append({"type": "suspicious_scheduled_task", "weight": WEIGHTS["suspicious_scheduled_task"]})
        elif not in_pf and positive_so_far >= 10:
            evidence.append({"type": "suspicious_scheduled_task", "weight": 8})
        elif not in_pf:
            evidence.append({"type": "suspicious_scheduled_task", "weight": 2})

    if facts.get("known_malicious_hash") or facts.get("malicious_hash"):
        evidence.append({"type": "known_malicious_hash", "weight": WEIGHTS["known_malicious_hash"]})

    ext = ""
    if "." in name:
        ext = name.rsplit(".", 1)[-1].lower()
    is_script = ext in ("js", "jse", "mjs", "vbs", "wsf", "ps1")
    is_ext_path = any(m in _path(path) for m in (
        "\\extensions\\",
        "\\extension\\",
        "\\.vscode\\",
        "\\code\\user\\",
        "\\ms-vscode.",
        "\\wasmtt",
        "node_modules",
        "\\codex\\",
    ))

    if is_script and not in_autorun and not in_task and not double_ext and not is_new:
        if is_ext_path:
            evidence = [e for e in evidence if e["weight"] <= 0]
            evidence.append({"type": "script_context", "weight": 0})
        elif _is_temp_path(path):
            evidence = [e for e in evidence if e["type"] not in ("unsigned", "unknown_publisher", "user_temp")]
            evidence.append({"type": "unsigned", "weight": 3})
            evidence.append({"type": "user_temp", "weight": 2})
        else:
            evidence = [e for e in evidence if e["type"] not in ("unsigned", "unknown_publisher")]
            evidence.append({"type": "script_context", "weight": 2})

    if vt_positives is not None and vt_total is not None:
        try:
            pos = int(vt_positives)
            tot = int(vt_total)
            mal = facts.get("vt_malicious")
            if mal is None:
                mal = pos
            mal = int(mal)
            if tot > 0:
                if mal >= 10:
                    evidence.append({"type": "vt_malicious", "weight": WEIGHTS["vt_malicious"], "detail": f"{mal}/{tot}"})
                elif mal >= 5:
                    evidence.append({"type": "vt_suspicious", "weight": WEIGHTS["vt_suspicious"], "detail": f"{mal}/{tot}"})
                elif mal == 0:
                    evidence.append({"type": "vt_clean", "weight": -8, "detail": f"0/{tot}"})
        except (TypeError, ValueError):
            pass

    facts_out = {
        "signature": signature or "unknown",
        "signer": signer,
        "path": path,
        "new_since_snapshot": is_new,
        "autorun": in_autorun,
        "scheduled_task": in_task,
        "double_extension": double_ext,
        "sha256": sha256 or None,
        "vt_positives": vt_positives,
        "vt_total": vt_total,
        "vt_malicious": facts.get("vt_malicious"),
    }
    return make_verdict(
        name=name,
        path=path,
        kind="file",
        evidence=evidence,
        facts=facts_out,
    )


def evaluate_process(facts: dict) -> dict:
    path = _s(facts.get("path") or facts.get("Path") or "")
    name = _s(facts.get("name") or facts.get("Name") or path.split("\\")[-1])
    signature = _signature_status(facts)
    signer = _s(facts.get("signer") or facts.get("Signer") or facts.get("Status") or "")
    is_new = bool(facts.get("new_since_snapshot") or facts.get("is_new") or False)
    parent_name = _s(facts.get("parent_name") or facts.get("ParentName") or "")
    parent_path = _s(facts.get("parent_path") or facts.get("ParentPath") or "")
    cmd = _s(facts.get("command_line") or facts.get("CommandLine") or "")

    file_facts = {
        "name": name,
        "path": path,
        "signature": signature,
        "signer": signer,
        "new_since_snapshot": is_new,
        "autorun": False,
        "scheduled_task": False,
        "double_extension": False,
    }
    result = evaluate_file(file_facts)
    result["kind"] = "process"

    evidence = list(result.get("evidence") or [])
    suspicious_parents = ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe")
    system_parents = ("services.exe", "svchost.exe", "wininit.exe", "winlogon.exe", "explorer.exe", "userinit.exe")

    pn = _lower(parent_name)
    if pn in suspicious_parents and not _is_system_path(path):
        if signature not in ("valid", "validsignature", "signed") or not _is_microsoft_signer(signer):
            evidence.append({"type": "suspicious_parent", "weight": WEIGHTS["suspicious_parent"]})
    if parent_path and _is_temp_path(parent_path):
        evidence.append({"type": "parent_from_temp", "weight": WEIGHTS["parent_from_temp"]})
    if pn and pn not in system_parents and _is_temp_path(path):
        evidence.append({"type": "temp_process", "weight": WEIGHTS["temp_process"]})
    if cmd and (" -enc " in _lower(cmd) or "-encodedcommand" in _lower(cmd) or "frombase64" in _lower(cmd)):
        evidence.append({"type": "encoded_command", "weight": WEIGHTS["encoded_command"]})

    facts_out = dict(result.get("facts") or {})
    facts_out["parent_name"] = parent_name
    facts_out["parent_path"] = parent_path
    facts_out["command_line"] = cmd[:200] if cmd else ""
    facts_out["new_since_snapshot"] = is_new
    facts_out["pid"] = facts.get("pid")
    facts_out["parent_pid"] = facts.get("parent_pid")
    return make_verdict(
        name=name,
        path=path,
        kind="process",
        evidence=evidence,
        facts=facts_out,
    )


def _extract_exe_path(value: str) -> str:
    import re
    v = _s(value)
    if not v:
        return ""
    m = re.search(r'"([^"]+\.(?:exe|bat|cmd|vbs|js|scr|msi))"', v, re.I)
    if m:
        return m.group(1)
    m = re.search(r"([A-Za-z]:\\[^\s\"']+\.(?:exe|bat|cmd|vbs|js|scr|msi))", v, re.I)
    if m:
        return m.group(1)
    for part in v.replace('"', "").split():
        pl = part.lower()
        if pl.endswith((".exe", ".bat", ".cmd", ".vbs", ".js", ".scr", ".msi")) and ("\\" in part or "/" in part or ":" in part):
            return part
    return ""

def _is_junk_autorun(name: str, value: str, path: str) -> bool:
    n = _lower(name)
    v = _lower(value)
    p = _path(path)
    if n in ("psdrive", "pspath", "psparentpath", "pschildname", "psprovider"):
        return True
    if v in ("hkcu", "hklm", ""):
        return True
    if not path:
        return True
    if p in ("hkcu", "hklm") or len(p) < 5:
        return True
    if not any(p.endswith(ext) for ext in (".exe", ".bat", ".cmd", ".vbs", ".js", ".scr", ".msi")):
        return True
    return False


def evaluate_autorun(facts: dict) -> dict:
    name = _s(facts.get("name") or facts.get("Name") or "")
    value = _s(facts.get("value") or facts.get("Value") or "")
    key = _s(facts.get("key") or facts.get("Key") or "")
    path = _extract_exe_path(value) or _s(facts.get("path") or "")
    if _is_junk_autorun(name, value, path):
        return make_verdict(
            name=name,
            path=path or value,
            kind="autorun",
            evidence=[],
            facts={
                "signature": "skipped",
                "signer": "",
                "path": path,
                "new_since_snapshot": False,
                "autorun": True,
                "scheduled_task": False,
                "double_extension": False,
                "registry_key": key,
                "value": value,
                "skipped": True,
            },
        )

    signature = _signature_status(facts)
    signer = _s(facts.get("signer") or facts.get("Signer") or "")
    is_new = bool(facts.get("new_since_snapshot") or facts.get("is_new") or False)

    file_facts = {
        "name": name or path.split("\\")[-1],
        "path": path,
        "signature": signature,
        "signer": signer,
        "new_since_snapshot": is_new,
        "autorun": True,
        "scheduled_task": False,
        "double_extension": _has_double_extension(name or path),
    }
    result = evaluate_file(file_facts)
    facts_out = dict(result.get("facts") or {})
    facts_out["registry_key"] = key
    facts_out["value"] = value
    facts_out["autorun"] = True
    return make_verdict(
        name=result.get("name") or name,
        path=result.get("path") or path,
        kind="autorun",
        evidence=list(result.get("evidence") or []),
        facts=facts_out,
    )


def evaluate_task(facts: dict) -> dict:
    name = _s(facts.get("task_name") or facts.get("TaskName") or facts.get("Name") or "")
    path = _s(facts.get("task_path") or facts.get("TaskPath") or facts.get("Path") or "")
    action = _s(facts.get("action") or facts.get("Action") or facts.get("Execute") or "")
    is_new = bool(facts.get("new_since_snapshot") or facts.get("is_new") or False)
    signature = _signature_status(facts)
    signer = _s(facts.get("signer") or facts.get("Signer") or "")

    target = action or path
    file_facts = {
        "name": name,
        "path": target,
        "signature": signature,
        "signer": signer,
        "new_since_snapshot": is_new,
        "autorun": False,
        "scheduled_task": True,
        "double_extension": _has_double_extension(name or target),
    }
    result = evaluate_file(file_facts)
    facts_out = dict(result.get("facts") or {})
    facts_out["task_path"] = path
    facts_out["task_name"] = name
    facts_out["scheduled_task"] = True
    return make_verdict(
        name=result.get("name") or name,
        path=result.get("path") or target,
        kind="scheduled_task",
        evidence=list(result.get("evidence") or []),
        facts=facts_out,
    )


def evaluate_service(facts: dict) -> dict:
    evidence: list[dict] = []
    name = _s(facts.get("name") or facts.get("Name") or facts.get("ServiceName") or "")
    path = _s(facts.get("path") or facts.get("Path") or facts.get("ImagePath") or "")
    start_type = _lower(
        facts.get("start_type")
        or facts.get("StartMode")
        or facts.get("StartType")
        or facts.get("Start")
        or ""
    )
    signature = _signature_status(facts)
    if signature in ("", "unknown"):
        signature = _lower(facts.get("Signature") or facts.get("signature") or "")
    signer = _s(facts.get("signer") or facts.get("Signer") or facts.get("publisher") or "")
    is_new = bool(facts.get("new_since_snapshot") or facts.get("is_new") or False)

    in_system = _is_system_path(path) or "\\program files" in _path(path)
    not_checked = signature in ("", "unknown", "notchecked", "not checked")

    known_windows_svc = {
        "windefend", "wdnissvc", "securityhealthservice", "sense", "mpssvc",
        "trustedinstaller", "msiserver", "wuauserv", "bits", "cryptsvc",
        "eventlog", "rpcss", "dnscache", "dhcpc", "lanmanserver", "lanmanworkstation",
        "schedule", "spooler", "themes", "audiosrv", "fontcache", "fontcache3.0.0.0",
        "nettcpportsharing", "mdcoresvc", "samss", "lsass", "winmgmt", "wmiapsrv",
        "nlasvc", "netprofm", "gpsvc", "appinfo", "profsvc", "userenv", "sysmain",
        "wsearch", "dcomlaunch", "coremessagingregistrar", "staterepository",
        "brokerinfrastructure", "systemeventsbroker", "power", "plugplay",
    }
    is_known_svc = _lower(name) in known_windows_svc or any(
        _lower(name).startswith(p) for p in ("wmi", "clr_", "nettcp", "fontcache")
    )

    if is_new:
        evidence.append({"type": "new_service", "weight": WEIGHTS["new_service"]})

    if signature in ("valid", "validsignature", "signed"):
        if _is_microsoft_signer(signer):
            evidence.append({"type": "valid_microsoft_signature", "weight": WEIGHTS["valid_microsoft_signature"]})
        else:
            evidence.append({"type": "valid_signature", "weight": WEIGHTS["valid_signature"]})
    elif not_checked:
        if in_system or is_known_svc:
            pass
        else:
            evidence.append({"type": "unsigned", "weight": 2})
    elif signature in ("notsigned", "unsigned", "not signed", "error", "hashmismatch"):
        if in_system or is_known_svc:
            evidence.append({"type": "unsigned", "weight": 2})
        else:
            evidence.append({"type": "unsigned", "weight": WEIGHTS["unsigned"]})

    if signer:
        if _is_known_publisher(signer) or _is_microsoft_signer(signer):
            evidence.append({"type": "known_publisher", "weight": WEIGHTS["known_publisher"]})
        elif not in_system and not is_known_svc:
            evidence.append({"type": "unknown_publisher", "weight": WEIGHTS["unknown_publisher"]})
    elif not not_checked and not in_system and not is_known_svc:
        evidence.append({"type": "unknown_publisher", "weight": WEIGHTS["unknown_publisher"]})

    if path and not in_system and not is_known_svc:
        evidence.append({"type": "service_unknown_path", "weight": WEIGHTS["service_unknown_path"]})

    if _is_temp_path(path):
        evidence.append({"type": "user_temp", "weight": WEIGHTS["user_temp"]})

    if start_type in ("auto", "automatic", "2"):
        if is_new and not in_system and not is_known_svc:
            evidence.append({"type": "suspicious_autorun", "weight": 10})
        elif is_new:
            evidence.append({"type": "suspicious_autorun", "weight": 3})

    if in_system or is_known_svc:
        evidence.append({"type": "known_system_path", "weight": -10})

    facts_out = {
        "signature": signature or "unknown",
        "signer": signer,
        "path": path,
        "start_type": start_type,
        "new_since_snapshot": is_new,
    }
    return make_verdict(
        name=name,
        path=path,
        kind="service",
        evidence=evidence,
        facts=facts_out,
    )


def _mark_new_paths(new_items: list, key: str = "Path") -> set[str]:
    paths = set()
    for it in new_items or []:
        if isinstance(it, dict):
            p = _s(it.get(key) or it.get("path") or it.get("Name") or it.get("TaskName") or "")
            if p:
                paths.add(_path(p))
        elif isinstance(it, str):
            paths.add(_path(it))
    return paths


def _as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        if not value:
            return []
        return list(value.values()) if all(isinstance(v, (dict, str)) for v in value.values()) else [value]
    return [value]



def _top_findings(scored: list, limit: int = 10) -> list:
    seen: set[str] = set()
    out: list = []
    for x in sorted(scored, key=lambda z: z.get("score") or 0, reverse=True):
        path = _path((x.get("path") or x.get("name") or ""))
        key = path or _lower(x.get("name") or "")
        if not key or key in seen:
            continue
        seen.add(key)
        item = dict(x)
        if not item.get("why_flagged"):
            item["why_flagged"] = [
                e.get("type")
                for e in (item.get("evidence") or [])
                if isinstance(e, dict) and int(e.get("weight") or 0) > 0
            ]
        out.append(item)
        if len(out) >= limit:
            break
    return out


def enrich_report(report: dict) -> dict:
    from config import SCHEMA_VERSION
    out = deepcopy(report)
    out["schema_version"] = SCHEMA_VERSION
    meta: dict[str, Any] = {}
    meta_raw = out.get("meta")
    if isinstance(meta_raw, dict):
        meta.update(meta_raw)
    meta["schema_version"] = SCHEMA_VERSION
    out["meta"] = meta

    computer: dict[str, Any] = {}
    computer_raw = out.get("computer")
    if isinstance(computer_raw, dict):
        computer.update(computer_raw)
    if not isinstance(computer, dict):
        computer = {}
        out["computer"] = computer
    name = str(computer.get("name") or "").strip()
    if not name or name.upper() in ("UNKNOWN", "NONE", "NULL"):
        import platform
        computer["name"] = platform.node() or computer.get("name") or "UNKNOWN"
        out["computer"] = computer
    changes = out.get("changes") or {}
    if not isinstance(changes, dict):
        changes = {}

    new_file_paths = _mark_new_paths(_as_list(changes.get("new_suspicious_files")))
    new_proc_paths = _mark_new_paths(_as_list(changes.get("new_unsigned_processes")))
    new_autorun_names = set()
    for it in _as_list(changes.get("new_autorun")):
        if isinstance(it, dict):
            new_autorun_names.add(_lower(it.get("Name") or it.get("name") or ""))
    new_task_names = set()
    for it in _as_list(changes.get("new_scheduled_tasks")):
        if isinstance(it, dict):
            new_task_names.add(_lower(it.get("TaskName") or it.get("task_name") or it.get("Name") or ""))

    scored_files = []
    for item in out.get("suspicious_files") or []:
        if not isinstance(item, dict):
            continue
        facts = {
            "name": item.get("Name") or item.get("name"),
            "path": item.get("Path") or item.get("path"),
            "signature": item.get("Signature") or item.get("signature"),
            "signer": item.get("Signer") or item.get("signer"),
            "new_since_snapshot": _path(item.get("Path") or "") in new_file_paths,
            "autorun": False,
            "scheduled_task": False,
            "double_extension": False,
            "sha256": item.get("sha256") or item.get("SHA256"),
            "vt_positives": item.get("vt_positives"),
            "vt_malicious": item.get("vt_malicious"),
            "vt_total": item.get("vt_total"),
            "vt_found": item.get("vt_found"),
        }
        name = _s(facts["name"] or facts["path"])
        if any(_has_double_extension(x) for x in (name, _s(facts["path"]))):
            facts["double_extension"] = True
        scored = evaluate_file(facts)
        scored["kind"] = "file"
        scored["size_mb"] = item.get("SizeMB") or item.get("size_mb")
        scored["modified"] = item.get("Modified") or item.get("modified")
        scored_files.append(scored)
    out["scored_files"] = scored_files

    scored_procs = []
    seen_proc_paths: set[str] = set()
    proc_source = out.get("processes") or out.get("unsigned_processes") or []
    for item in proc_source:
        if not isinstance(item, dict):
            continue
        pth = _path(item.get("Path") or item.get("path") or "")
        if not pth or pth in seen_proc_paths:
            continue
        seen_proc_paths.add(pth)
        facts = {
            "name": item.get("Name") or item.get("name") or (item.get("Path") or "").split("\\")[-1],
            "path": item.get("Path") or item.get("path") or "",
            "signature": item.get("Signature") or item.get("Status") or item.get("signature") or "",
            "signer": item.get("Signer") or item.get("signer") or "",
            "parent_name": item.get("ParentName") or item.get("parent_name") or "",
            "parent_path": item.get("ParentPath") or item.get("parent_path") or "",
            "command_line": item.get("CommandLine") or item.get("command_line") or "",
            "pid": item.get("Pid") or item.get("pid"),
            "parent_pid": item.get("ParentPid") or item.get("parent_pid"),
            "new_since_snapshot": pth in new_proc_paths,
            "sha256": item.get("sha256") or item.get("SHA256"),
            "vt_positives": item.get("vt_positives"),
            "vt_total": item.get("vt_total"),
        }
        scored = evaluate_process(facts)
        if scored["risk"] in ("MEDIUM", "HIGH") or scored["score"] >= 10 or pth in new_proc_paths:
            scored_procs.append(scored)
    if not scored_procs:
        for item in out.get("unsigned_processes") or []:
            if not isinstance(item, dict):
                continue
            facts = {
                "path": item.get("Path") or item.get("path") or "",
                "signature": item.get("Status") or item.get("Signature") or "",
                "signer": item.get("Signer") or "",
                "new_since_snapshot": _path(item.get("Path") or "") in new_proc_paths,
            }
            scored_procs.append(evaluate_process(facts))
    out["scored_processes"] = scored_procs

    scored_autoruns = []
    for item in out.get("autorun") or []:
        if not isinstance(item, dict):
            continue
        facts = {
            "name": item.get("Name") or item.get("name"),
            "value": item.get("Value") or item.get("value"),
            "key": item.get("Key") or item.get("key"),
            "signature": item.get("Signature") or item.get("signature") or "",
            "signer": item.get("Signer") or item.get("signer") or "",
            "new_since_snapshot": _lower(item.get("Name") or "") in new_autorun_names,
        }
        scored_autoruns.append(evaluate_autorun(facts))
    out["scored_autoruns"] = scored_autoruns

    scored_tasks = []
    for item in out.get("scheduled_tasks") or []:
        if not isinstance(item, dict):
            continue
        facts = {
            "task_name": item.get("TaskName") or item.get("Name"),
            "task_path": item.get("TaskPath") or item.get("Path"),
            "action": item.get("Action") or item.get("Execute") or "",
            "signature": item.get("Signature") or "",
            "signer": item.get("Signer") or "",
            "new_since_snapshot": _lower(item.get("TaskName") or item.get("Name") or "") in new_task_names,
        }
        scored_tasks.append(evaluate_task(facts))
    out["scored_tasks"] = scored_tasks

    new_service_names = set()
    for it in _as_list(changes.get("new_services")):
        if isinstance(it, dict):
            n = _lower(it.get("Name") or it.get("name") or "")
            if n:
                new_service_names.add(n)
        elif isinstance(it, str) and it.strip():
            new_service_names.add(_lower(it))

    scored_services = []
    for item in out.get("services") or []:
        if not isinstance(item, dict):
            continue
        name = item.get("Name") or item.get("ServiceName") or ""
        is_new = _lower(name) in new_service_names or bool(item.get("is_new") or item.get("new_since_snapshot"))
        facts = {
            "name": name,
            "path": item.get("Path") or item.get("ImagePath") or "",
            "start_type": item.get("StartMode") or item.get("StartType") or item.get("Start") or "",
            "signature": item.get("Signature") or item.get("Status") or "",
            "signer": item.get("Signer") or item.get("Publisher") or "",
            "new_since_snapshot": is_new,
        }
        scored = evaluate_service(facts)
        if scored["risk"] in ("MEDIUM", "HIGH") or scored["score"] >= 12 or is_new:
            scored_services.append(scored)
    out["scored_services"] = scored_services

    for de in out.get("double_extensions") or []:
        path = _s(de) if not isinstance(de, dict) else _s(de.get("Path") or de.get("path"))
        if not path:
            continue
        already = any(_path(f.get("path")) == _path(path) for f in scored_files)
        if already:
            continue
        scored = evaluate_file({
            "name": path.split("\\")[-1],
            "path": path,
            "signature": "unknown",
            "signer": "",
            "new_since_snapshot": False,
            "double_extension": True,
        })
        scored["kind"] = "file"
        scored_files.append(scored)
    out["scored_files"] = scored_files

    all_scored = [
        x for x in (scored_files + scored_procs + scored_autoruns + scored_tasks + scored_services)
        if not (x.get("facts") or {}).get("skipped")
    ]
    high = [x for x in all_scored if x["risk"] == "HIGH"]
    medium = [x for x in all_scored if x["risk"] == "MEDIUM"]
    low = [x for x in all_scored if x["risk"] == "LOW"]

    max_score = max((x["score"] for x in all_scored), default=0)
    if high:
        overall_risk = "HIGH"
    elif medium:
        overall_risk = "MEDIUM"
    else:
        overall_risk = "LOW"

    conf_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for x in all_scored:
        conf_counts[x.get("confidence", "LOW")] = conf_counts.get(x.get("confidence", "LOW"), 0) + 1
    if high and conf_counts["HIGH"] >= 1:
        overall_confidence = "HIGH"
    elif medium or high:
        overall_confidence = "MEDIUM"
    else:
        overall_confidence = "HIGH" if not all_scored else "MEDIUM"

    try:
        from core.process_tree import attach_trees_to_report
        out = attach_trees_to_report(out)
    except Exception:
        out.setdefault("process_trees", [])

    out["risk_summary"] = {
        "schema": "risk_summary_v1",
        "overall_risk": overall_risk,
        "overall_confidence": overall_confidence,
        "max_score": max_score,
        "counts": {
            "HIGH": len(high),
            "MEDIUM": len(medium),
            "LOW": len(low),
            "total": len(all_scored),
        },
        "top_findings": _top_findings(all_scored, limit=10),
    }

    return out


def explain_why(scored: dict) -> dict:
    if scored.get("schema") == "verdict_v1" and scored.get("why_flagged") is not None:
        return {
            "name": scored.get("name"),
            "path": scored.get("path"),
            "kind": scored.get("kind"),
            "risk": scored.get("risk"),
            "score": scored.get("score"),
            "confidence": scored.get("confidence"),
            "why_flagged": list(scored.get("why_flagged") or []),
            "mitigating": list(scored.get("mitigating") or []),
            "evidence": list(scored.get("evidence") or []),
            "conclusion": scored.get("conclusion") or "",
        }
    evidence = scored.get("evidence") or []
    positive = [e for e in evidence if int(e.get("weight") or 0) > 0]
    negative = [e for e in evidence if int(e.get("weight") or 0) < 0]
    why_flagged = [EVIDENCE_LABELS.get(e["type"], e["type"]) for e in positive]
    mitigating = [EVIDENCE_LABELS.get(e["type"], e["type"]) for e in negative]
    risk = scored.get("risk") or "LOW"
    if risk == "HIGH":
        conclusion = "HIGH RISK. Strong indicators of potential threat."
    elif risk == "MEDIUM":
        conclusion = "MEDIUM RISK. Multiple indicators require investigation."
    else:
        conclusion = "LOW RISK. Insufficient evidence to classify as malicious."
    return {
        "name": scored.get("name"),
        "path": scored.get("path"),
        "kind": scored.get("kind"),
        "risk": risk,
        "score": scored.get("score"),
        "confidence": scored.get("confidence"),
        "why_flagged": why_flagged,
        "mitigating": mitigating,
        "evidence": evidence,
        "conclusion": conclusion,
    }


def format_explain(scored: dict) -> dict:
    """Human-readable score breakdown for Dashboard / Telegram / AI."""
    base = explain_why(scored)
    evidence = list(base.get("evidence") or scored.get("evidence") or [])
    lines = []
    for e in sorted(evidence, key=lambda x: int(x.get("weight") or 0), reverse=True):
        if not isinstance(e, dict):
            continue
        w = int(e.get("weight") or 0)
        if w == 0:
            continue
        label = EVIDENCE_LABELS.get(str(e.get("type") or ""), str(e.get("type") or ""))
        detail = str(e.get("detail") or "").strip()
        sign = f"+{w}" if w > 0 else str(w)
        line = f"{sign:>4}  {label}"
        if detail:
            line += f" ({detail})"
        lines.append({
            "weight": w,
            "type": e.get("type"),
            "label": label,
            "detail": detail,
            "text": line.strip(),
        })
    base["breakdown"] = lines
    base["score"] = int(scored.get("score") or base.get("score") or 0)
    base["risk"] = str(scored.get("risk") or base.get("risk") or "LOW").upper()
    base["confidence"] = str(scored.get("confidence") or base.get("confidence") or "MEDIUM").upper()
    return base