"""Stage-2 Verdict Engine · deterministic rules.

Each rule is a pure function of the canonical Stage-2 input.  Rules
NEVER read Mongo, NEVER call the network, NEVER invoke an LLM.
The engine is a pure data → data transformation.

Rule contract:
    def RULE_FN(inp: Stage2Input) -> List[EvidenceRow]
where every row returned already carries its weight_contribution.

Weights are integer deltas on the risk_score (positive = malicious
lean; negative = benign lean).  Absolute contributions are bounded
so no single rule can dominate the score (see MAX_ABS_WEIGHT below).
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Optional, Tuple

from .model import EvidenceRow


MAX_ABS_WEIGHT = 30           # single rule's max absolute contribution
_TRUNC = 240                  # value truncation for the UI card


def _row_id(rule_id: str, canonical_field: str, value: str, ev_ids: List[str]) -> str:
    """Deterministic evidence row id — same inputs → same id."""
    m = hashlib.sha256()
    m.update(rule_id.encode()); m.update(b"|")
    m.update(canonical_field.encode()); m.update(b"|")
    m.update(value.encode()); m.update(b"|")
    m.update(",".join(sorted(ev_ids)).encode())
    return m.hexdigest()[:16]


def _trunc(v: Any) -> str:
    s = "" if v is None else str(v)
    return s if len(s) <= _TRUNC else s[:_TRUNC] + "…"


# ── PROC-SUSPICIOUS-PARENT ──────────────────────────────────────────
_SUSP_CHILDREN = {"powershell.exe", "cmd.exe", "wscript.exe",
                   "cscript.exe", "mshta.exe", "rundll32.exe",
                   "regsvr32.exe", "certutil.exe", "bitsadmin.exe"}
_SUSP_PARENTS  = {"winword.exe", "excel.exe", "outlook.exe",
                   "powerpnt.exe", "acrord32.exe", "acrobat.exe",
                   "chrome.exe", "msedge.exe", "firefox.exe",
                   "explorer.exe"}


def rule_proc_suspicious_parent(inp) -> List[EvidenceRow]:
    """Suspicious process-lineage rule.  Fires when a known LOLBin /
    scripting host is spawned by a user-facing app (office, browser,
    explorer)."""
    rows: List[EvidenceRow] = []
    for ev in inp.timeline_events:
        proc = (ev.get("process") or "").lower()
        parent = (ev.get("parent_process") or "").lower()
        if not proc or not parent:
            continue
        if proc in _SUSP_CHILDREN and parent in _SUSP_PARENTS:
            eid = ev.get("event_id") or ""
            rows.append(EvidenceRow(
                row_id=_row_id("PROC-SUSPICIOUS-PARENT",
                                 "canonical.process.parent",
                                 f"{parent}→{proc}", [eid]),
                rule_id="PROC-SUSPICIOUS-PARENT",
                canonical_field_matched="canonical.process.parent",
                matched_value=_trunc(f"{parent} → {proc}"),
                weight_contribution=20,
                lane=ev.get("lane") or "log",
                event_ids=[eid] if eid else [],
                provenance_chain=list(ev.get("provenance_chain") or []),
                display_summary=f"{proc} spawned by {parent}",
            ))
    return rows


# ── CMD-OBFUSCATION ─────────────────────────────────────────────────
_OBF_PATTERNS = (
    (re.compile(r"-e(?:nc|ncoded|ncodedcommand)\b", re.I), "PowerShell -EncodedCommand"),
    (re.compile(r"iex\s*\(", re.I),                         "PowerShell IEX invocation"),
    (re.compile(r"downloadstring", re.I),                    "PowerShell DownloadString"),
    (re.compile(r"::frombase64string", re.I),                "Base64 decode + reflection"),
    (re.compile(r"powershell(?:\s+-\w+)*\s+-nop\b", re.I),   "PowerShell -NoProfile flag"),
    (re.compile(r"\bregsvr32\s+/s\s+/u\s+/i:http", re.I),    "regsvr32 Squiblydoo"),
    (re.compile(r"\bmshta\s+http", re.I),                    "mshta remote HTA"),
)


def rule_cmd_obfuscation(inp) -> List[EvidenceRow]:
    rows: List[EvidenceRow] = []
    for ev in inp.timeline_events:
        cmd = ev.get("command_line") or ""
        if not cmd:
            continue
        for rx, desc in _OBF_PATTERNS:
            if rx.search(cmd):
                eid = ev.get("event_id") or ""
                rows.append(EvidenceRow(
                    row_id=_row_id("CMD-OBFUSCATION",
                                     "canonical.process.command_line",
                                     desc + "::" + cmd[:80], [eid]),
                    rule_id="CMD-OBFUSCATION",
                    canonical_field_matched="canonical.process.command_line",
                    matched_value=_trunc(cmd),
                    weight_contribution=25,
                    lane=ev.get("lane") or "log",
                    event_ids=[eid] if eid else [],
                    provenance_chain=list(ev.get("provenance_chain") or []),
                    display_summary=desc,
                ))
                break         # one obfuscation per event is enough
    return rows


# ── FILE-DROP-EXECUTABLE ────────────────────────────────────────────
_DROP_EXTS = (".exe", ".dll", ".scr", ".js", ".vbs", ".ps1", ".bat", ".hta")
_TEMP_PATH_MARKERS = ("\\temp\\", "\\appdata\\", "\\programdata\\",
                       "/tmp/", "/var/tmp/", "\\users\\public\\")


def rule_file_drop_executable(inp) -> List[EvidenceRow]:
    rows: List[EvidenceRow] = []
    for ev in inp.timeline_events:
        f = ev.get("file_ref") or {}
        path = (f.get("path") or "").lower()
        name = (f.get("name") or "").lower()
        if not (path or name):
            continue
        # Only for CREATE/WRITE actions.
        action = (ev.get("action") or "").lower()
        if action not in {"create", "created", "write", "written",
                            "modify", "modified", "drop", "dropped"}:
            continue
        low = path or name
        if not low.endswith(_DROP_EXTS):
            continue
        if not any(m in low for m in _TEMP_PATH_MARKERS):
            continue
        eid = ev.get("event_id") or ""
        rows.append(EvidenceRow(
            row_id=_row_id("FILE-DROP-EXECUTABLE",
                             "canonical.file.path", low, [eid]),
            rule_id="FILE-DROP-EXECUTABLE",
            canonical_field_matched="canonical.file.path",
            matched_value=_trunc(low),
            weight_contribution=20,
            lane=ev.get("lane") or "log",
            event_ids=[eid] if eid else [],
            provenance_chain=list(ev.get("provenance_chain") or []),
            display_summary=f"{action}: {name or path}",
        ))
    return rows


# ── NETWORK-SUSPICIOUS ──────────────────────────────────────────────
# Non-whitelisted destination that a script/scripting-host contacted.
# Whitelist is intentionally narrow — enterprise-cloud endpoints only.
_NET_WHITELIST = {
    "microsoft.com", "windowsupdate.com", "office.com",
    "office365.com", "azure.com", "azureedge.net",
    "google.com", "gstatic.com", "google-analytics.com",
    "apple.com", "icloud.com",
}


def _domain_root(host: str) -> str:
    parts = (host or "").lower().strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host or ""


def rule_network_suspicious(inp) -> List[EvidenceRow]:
    rows: List[EvidenceRow] = []
    for ev in inp.timeline_events:
        dest = ev.get("destination") or ""
        if not dest:
            continue
        host_part = dest.split("/")[2] if "://" in dest else dest.split(":")[0]
        root = _domain_root(host_part)
        if not root or root in _NET_WHITELIST:
            continue
        # Only flag when the source process is a scripting host.
        proc = (ev.get("process") or "").lower()
        if proc and proc not in _SUSP_CHILDREN:
            continue
        eid = ev.get("event_id") or ""
        rows.append(EvidenceRow(
            row_id=_row_id("NETWORK-SUSPICIOUS",
                             "canonical.destination.host", dest, [eid]),
            rule_id="NETWORK-SUSPICIOUS",
            canonical_field_matched="canonical.destination.host",
            matched_value=_trunc(dest),
            weight_contribution=15,
            lane=ev.get("lane") or "log",
            event_ids=[eid] if eid else [],
            provenance_chain=list(ev.get("provenance_chain") or []),
            display_summary=f"{proc or 'process'} → {dest}",
        ))
    return rows


# ── MITRE-IMPACT / MITRE-EXFILTRATION ────────────────────────────────
def _mk_mitre_row(inp, tactic_name: str, rule_id: str, weight: int, summary: str) -> Optional[EvidenceRow]:
    tactics = inp.observed_tactics or set()
    if tactic_name not in tactics:
        return None
    # Collect event_ids that carry this tactic via intent.
    ev_ids = [e.get("event_id") for e in inp.timeline_events
               if e.get("event_id")]
    return EvidenceRow(
        row_id=_row_id(rule_id, "intent.tactic", tactic_name, ev_ids),
        rule_id=rule_id,
        canonical_field_matched="intent.tactic",
        matched_value=tactic_name,
        weight_contribution=weight,
        lane="narrative",
        event_ids=ev_ids[:16],
        provenance_chain=["services.die.intent"],
        display_summary=summary,
    )


def rule_mitre_impact(inp) -> List[EvidenceRow]:
    r = _mk_mitre_row(inp, "Impact", "MITRE-IMPACT", 25,
                        "ATT&CK Impact tactic observed")
    return [r] if r else []


def rule_mitre_exfiltration(inp) -> List[EvidenceRow]:
    r = _mk_mitre_row(inp, "Exfiltration", "MITRE-EXFILTRATION", 20,
                        "ATT&CK Exfiltration tactic observed")
    return [r] if r else []


# ── OBJECTIVE-DOUBLE-EXTORTION ─────────────────────────────────────
def rule_objective_double_extortion(inp) -> List[EvidenceRow]:
    """When services.die.intent.classify_intent identifies the
    double_extortion_ransomware objective, weight it heavily.
    Deterministic pass-through — no independent detection."""
    if inp.objective_rule != "double_extortion_ransomware":
        return []
    return [EvidenceRow(
        row_id=_row_id("OBJECTIVE-DOUBLE-EXTORTION", "intent.rule",
                         inp.objective_rule, []),
        rule_id="OBJECTIVE-DOUBLE-EXTORTION",
        canonical_field_matched="intent.rule",
        matched_value=inp.objective_rule,
        weight_contribution=30,
        lane="narrative",
        event_ids=[],
        provenance_chain=["services.die.intent"],
        display_summary="Double-extortion ransomware objective (Impact + Exfiltration)",
    )]


# ── SIGNED-BENIGN-COUNTERWEIGHT ─────────────────────────────────────
_TRUSTED_SIGNERS = ("microsoft corporation", "microsoft windows",
                    "apple inc.", "google llc", "adobe inc.",
                    "adobe systems incorporated", "mozilla corporation")


def rule_signed_benign_counterweight(inp) -> List[EvidenceRow]:
    rows: List[EvidenceRow] = []
    for ev in inp.timeline_events:
        cf = ev.get("canonical_fields") or {}
        signer = (cf.get("canonical.file.signer")
                     or cf.get("canonical.process.signer") or "").lower()
        if not signer:
            continue
        if not any(t in signer for t in _TRUSTED_SIGNERS):
            continue
        eid = ev.get("event_id") or ""
        rows.append(EvidenceRow(
            row_id=_row_id("SIGNED-BENIGN-COUNTERWEIGHT",
                             "canonical.file.signer", signer, [eid]),
            rule_id="SIGNED-BENIGN-COUNTERWEIGHT",
            canonical_field_matched="canonical.file.signer",
            matched_value=_trunc(signer),
            weight_contribution=-10,
            lane=ev.get("lane") or "log",
            event_ids=[eid] if eid else [],
            provenance_chain=list(ev.get("provenance_chain") or []),
            display_summary=f"Signed by trusted signer: {signer}",
        ))
    return rows


# ── V3X-VERDICT-CARRY ───────────────────────────────────────────────
# Read existing v3.x verdict as one input signal.  Owner rule #3 —
# Stage-2 builds on top, does not replace.
def rule_v3x_verdict_carry(inp) -> List[EvidenceRow]:
    v3x_label = (inp.v3x_verdict or "").lower()
    if v3x_label not in ("malicious", "suspicious", "benign"):
        return []
    weight = {"malicious": 20, "suspicious": 10, "benign": -15}[v3x_label]
    return [EvidenceRow(
        row_id=_row_id("V3X-VERDICT-CARRY", "case.verdict.verdict",
                         v3x_label, []),
        rule_id="V3X-VERDICT-CARRY",
        canonical_field_matched="case.verdict.verdict",
        matched_value=v3x_label,
        weight_contribution=weight,
        lane="narrative",
        event_ids=[],
        provenance_chain=["services.die.canonical_bridge",
                           "services.uaie.ssot_projector"],
        display_summary=f"v3.x verdict carry: {v3x_label}",
    )]


# ── Registry of rules — insertion order determines evaluation order.
RULES: Tuple[Tuple[str, str, callable, str], ...] = (
    ("PROC-SUSPICIOUS-PARENT",     "Suspicious Process Parent",
        rule_proc_suspicious_parent,   "malicious"),
    ("CMD-OBFUSCATION",            "Command-line Obfuscation",
        rule_cmd_obfuscation,          "malicious"),
    ("FILE-DROP-EXECUTABLE",       "Executable Dropped to Temp/AppData",
        rule_file_drop_executable,     "malicious"),
    ("NETWORK-SUSPICIOUS",         "Suspicious Network Connection",
        rule_network_suspicious,       "suspicious"),
    ("MITRE-IMPACT",               "MITRE ATT&CK · Impact",
        rule_mitre_impact,             "malicious"),
    ("MITRE-EXFILTRATION",         "MITRE ATT&CK · Exfiltration",
        rule_mitre_exfiltration,       "malicious"),
    ("OBJECTIVE-DOUBLE-EXTORTION", "Double-Extortion Ransomware Objective",
        rule_objective_double_extortion, "malicious"),
    ("V3X-VERDICT-CARRY",          "Existing v3.x Verdict Carry",
        rule_v3x_verdict_carry,        "carry"),
    ("SIGNED-BENIGN-COUNTERWEIGHT", "Signed by Trusted Signer",
        rule_signed_benign_counterweight, "benign"),
)


__all__ = ["RULES", "MAX_ABS_WEIGHT"]
