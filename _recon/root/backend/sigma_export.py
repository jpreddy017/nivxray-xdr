"""Sigma rule auto-exporter (Feb 2026).

Converts a NivXRay investigation (verdict + IOCs + MITRE + LOLBAS + decode chain)
into a SIEM-ready Sigma detection rule.

Design goals:
    • Deterministic (no AI) — same case in → same YAML out.
    • Conservative — only emit conditions that map to concrete
      observable events (process-creation, network, image-load).
    • Analyst-friendly — every rule carries the case name, verdict,
      confidence, MITRE tags, chain, and originating case_id.

Output covers the two most common Sigma sinks:
    1. `process_creation` on Windows (CommandLine / ParentImage / Image)
    2. `network_connection` (DestinationIp / DestinationHostname)

Callers: routers/cases.py → GET /cases/{id}/sigma
         routers/history.py → GET /history/{id}/sigma
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import yaml  # already in requirements via other packages

# Ordered by fidelity — process_creation gets emitted first because
# behavioural rules survive IOC rotation better than pure network rules.
_LOG_SOURCES = [
    ("process_creation", ["windows"]),
    ("network_connection", []),
]


def _slug(s: str, cap: int = 60) -> str:
    """SIEM-safe id: lowercase alnum + dash, capped at N chars."""
    s = re.sub(r"[^A-Za-z0-9]+", "-", (s or "").strip().lower()).strip("-")
    return (s or "case")[:cap]


def _iocs(iocs: Dict[str, Any]) -> Dict[str, List[str]]:
    if not isinstance(iocs, dict):
        return {"urls": [], "ips": [], "domains": [], "hashes": []}
    out = {
        "urls":    [str(x) for x in (iocs.get("urls")    or [])],
        "ips":     [str(x) for x in (iocs.get("ips")     or [])],
        "domains": [str(x) for x in (iocs.get("domains") or [])],
        "hashes":  [str(x) for x in (iocs.get("hashes")  or [])],
    }
    return {k: [v for v in vs if v] for k, vs in out.items()}


def _mitre_tags(mitre: List[Dict[str, Any]]) -> List[str]:
    """MITRE technique IDs (e.g. T1059.001) → Sigma-style `attack.t1059.001`."""
    tags = []
    for m in mitre or []:
        if not isinstance(m, dict):
            continue
        tid = m.get("id") or m.get("technique_id") or ""
        if tid:
            tags.append(f"attack.{tid.lower()}")
    return sorted(set(tags))


def _lolbas_binaries(lolbas: List[Any]) -> List[str]:
    """Extract binary names (e.g. `certutil.exe`, `mshta.exe`) from LOLBAS entries."""
    out: List[str] = []
    for l in lolbas or []:
        if isinstance(l, str):
            out.append(l)
        elif isinstance(l, dict):
            n = l.get("name") or l.get("binary") or l.get("tool") or l.get("bin")
            if n:
                out.append(n)
    # Normalise casing + strip prefixes
    norm = []
    for b in out:
        b = b.strip()
        if not b:
            continue
        b = b.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]  # basename
        if "." not in b:
            b += ".exe"
        norm.append(b.lower())
    return sorted(set(norm))


def _command_fragments(input_text: str, output_text: str) -> List[str]:
    """Extract CommandLine substrings likely to survive in customer telemetry.

    We prefer the *decoded* output (the peeled shell command) — that's what
    lands in Windows Event 4688 / Sysmon EID 1. Fall back to raw input if
    output is binary / empty.
    """
    src = output_text or input_text or ""
    # Cheap printable-ratio guard — binary/PE payload isn't a CommandLine
    if src and sum(1 for c in src[:1024] if 32 <= ord(c) <= 126) / max(1, min(len(src), 1024)) < 0.6:
        src = input_text or ""
    src = src[:4000]

    fragments: List[str] = []
    for pat in (
        # PowerShell one-liners
        r"powershell(\.exe)?\s+[-/][^\s]+",
        # Certutil / mshta / bitsadmin / regsvr32 canonical LOLBAS invocations
        r"certutil(\.exe)?\s+[-/]urlcache\s+[-/]split\s+[-/]f\s+\S+",
        r"mshta(\.exe)?\s+https?://\S+",
        r"bitsadmin(\.exe)?\s+/transfer\s+\S+",
        r"regsvr32(\.exe)?\s+/s\s+/u\s+/i:https?://\S+",
        r"rundll32(\.exe)?\s+\S+\.dll,\S+",
        # Wget/curl download-execute
        r"(?:curl|wget)\s+https?://\S+\s*\|\s*(?:sh|bash|iex)",
        # FromBase64String shellcode pattern
        r"\[System\.Convert\]::FromBase64String\(",
        # PowerShell reflective load
        r"\[Reflection\.Assembly\]::Load\(",
    ):
        for m in re.finditer(pat, src, flags=re.IGNORECASE):
            frag = m.group(0)
            if 8 <= len(frag) <= 200:
                fragments.append(frag)
    # Dedupe preserving order
    seen, out = set(), []
    for f in fragments:
        if f.lower() in seen:
            continue
        seen.add(f.lower()); out.append(f)
    return out[:5]


def build_sigma_rule(
    *,
    case_name: str,
    case_id: Optional[str],
    verdict: Dict[str, Any],
    input_text: str,
    output_text: str,
    chain: List[str],
    iocs: Dict[str, Any],
    mitre: List[Dict[str, Any]],
    lolbas: List[Any],
    author: str = "NivXRay",
) -> Dict[str, Any]:
    """Return a Sigma rule as a Python dict (caller can yaml.safe_dump it).

    The chosen `logsource` is process_creation when we have LOLBAS binaries
    or command fragments; otherwise network_connection when we only have
    URLs/IPs/domains.
    """
    ioc = _iocs(iocs)
    bins = _lolbas_binaries(lolbas)
    frags = _command_fragments(input_text, output_text)

    prefer_proc = bool(bins or frags)
    logsource = (
        {"category": "process_creation", "product": "windows"}
        if prefer_proc
        else {"category": "network_connection"}
    )

    v = (verdict or {}).get("verdict") or (verdict or {}).get("label") or "Malicious"
    conf = (verdict or {}).get("confidence") or (verdict or {}).get("risk_score") or 0
    level = (
        "critical" if v == "Malicious" and conf >= 80
        else "high" if v == "Malicious"
        else "medium" if v == "Suspicious"
        else "low"
    )

    # Build the detection block
    detection: Dict[str, Any] = {}
    condition_parts: List[str] = []

    if prefer_proc:
        if bins:
            detection["proc_image"] = {"Image|endswith": [f"\\{b}" for b in bins]}
            condition_parts.append("proc_image")
        if frags:
            detection["cmd_fragments"] = {"CommandLine|contains": frags}
            condition_parts.append("cmd_fragments")
    else:
        if ioc["ips"]:
            detection["dst_ips"] = {"DestinationIp": ioc["ips"]}
            condition_parts.append("dst_ips")
        if ioc["domains"] or ioc["urls"]:
            hosts = list(dict.fromkeys(ioc["domains"] + [u.split("/")[2] for u in ioc["urls"] if "//" in u]))
            if hosts:
                detection["dst_hosts"] = {"DestinationHostname|contains": hosts}
                condition_parts.append("dst_hosts")

    condition = " or ".join(condition_parts) if condition_parts else "selection"
    if not condition_parts:
        detection["selection"] = {"CommandLine|contains": [input_text[:80]]}
        condition = "selection"

    references: List[str] = []
    if case_id:
        references.append(f"nivxray://case/{case_id}")

    rule = {
        "title": f"NivXRay · {case_name or 'Case'} · {v}",
        "id": f"nivxray-{_slug(case_name)}-{(_slug(case_id or 'auto'))[:8]}",
        "status": "experimental",
        "description": (
            (verdict or {}).get("summary")
            or (verdict or {}).get("headline")
            or f"Auto-generated from NivXRay case '{case_name}' — {v} verdict "
            f"({conf}/100). Chain: {' → '.join(chain or []) or 'n/a'}"
        ),
        "author": author,
        "date": datetime.now(timezone.utc).strftime("%Y/%m/%d"),
        "references": references,
        "logsource": logsource,
        "detection": {**detection, "condition": condition},
        "fields": ["CommandLine", "Image", "ParentImage", "DestinationIp", "DestinationHostname"],
        "falsepositives": ["Legitimate administrative use — review parent process context."],
        "level": level,
        "tags": _mitre_tags(mitre) + [f"nivxray.chain.{c}" for c in (chain or [])[:6]],
    }
    return rule


def rule_to_yaml(rule: Dict[str, Any]) -> str:
    """Sigma YAML dump — deterministic key order, no aliases."""
    return yaml.safe_dump(rule, sort_keys=False, default_flow_style=False, allow_unicode=True)
