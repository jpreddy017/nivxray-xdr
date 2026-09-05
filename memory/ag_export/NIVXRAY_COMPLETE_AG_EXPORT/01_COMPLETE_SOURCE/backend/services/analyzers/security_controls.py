"""Defensive Security Control & Evasion Analyzer (AMSI & ETW Tampering).

DEFENSIVE ANALYSIS ONLY.
Detects attacker attempts to disable, patch, tamper with, or evade:
- AMSI (Antimalware Scan Interface)
- ETW (Event Tracing for Windows)
- Security Event Logging

Strictly analyzes and explains tampering behavior; never implements bypass mechanisms.
Attributes findings to MITRE ATT&CK T1562.001 and T1562.006.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Set, Union


# ── AMSI Tampering Signatures (Case-Insensitive Patterns) ───────────────────
_AMSI_SIGNATURES = [
    # 1. Reflection-based tampering with internal fields (amsiInitFailed / amsiContext)
    (
        r"amsiInitFailed",
        "AMSI Init Flag Tampering: Attempt to set amsiInitFailed to true to suppress scanning",
        "T1562.001",
        "High",
    ),
    (
        r"System\.Management\.Automation\.AmsiUtils",
        "AMSI Utilities Reflection: Accessing internal AmsiUtils class via reflection",
        "T1562.001",
        "High",
    ),
    (
        r"\[Ref\]\.Assembly\.GetType\(.*AmsiUtils",
        "AMSI Reflection Primitive: Dynamic type resolution targeting AmsiUtils",
        "T1562.001",
        "Critical",
    ),
    (
        r"amsiContext",
        "AMSI Context Tampering: Direct manipulation of amsiContext handle",
        "T1562.001",
        "High",
    ),

    # 2. Dynamic loading of amsi.dll and API resolution
    (
        r"(?:loadlibrary|getprocaddress).*(?:amsi\.dll|amsiscanbuffer)",
        "AMSI API Resolution: Dynamic acquisition of AmsiScanBuffer address",
        "T1562.001",
        "High",
    ),
    (
        r"amsiscanbuffer",
        "AMSI Scan Hook Target: Direct reference to AmsiScanBuffer function",
        "T1562.001",
        "Medium",
    ),

    # 3. Memory patching primitives targeting AMSI buffer
    (
        r"\[Runtime\.InteropServices\.Marshal\]::Copy\(.*amsi",
        "AMSI Memory Patching: Overwriting AmsiScanBuffer instructions in memory",
        "T1562.001",
        "Critical",
    ),
    (
        r"VirtualProtect.*amsi",
        "AMSI Memory Permission Modification: Altering memory page protection to patch AMSI",
        "T1562.001",
        "Critical",
    ),
    (
        r"0x80070057",
        "AMSI Return Value Patch (E_INVALIDARG): Common patch return code forcing AMSI scan bypass",
        "T1562.001",
        "High",
    ),
    (
        r"(?:0xc3|0xb8,?\s*0x57,?\s*0x00,?\s*0x07,?\s*0x80)",
        "AMSI Byte Patch Sequence: Bytecode sequence used to patch AmsiScanBuffer prologue",
        "T1562.001",
        "Critical",
    ),
]

# ── ETW Tampering Signatures ───────────────────────────────────────────────
_ETW_SIGNATURES = [
    (
        r"EtwEventWrite",
        "ETW Event Write Target: Reference to ntdll!EtwEventWrite auditing export",
        "T1562.006",
        "Medium",
    ),
    (
        r"(?:virtualprotect|writeprocessmemory).*etweventwrite",
        "ETW Patching Attempt: Attempting to patch ntdll!EtwEventWrite to blind telemetry",
        "T1562.006",
        "Critical",
    ),
    (
        r"\[Runtime\.InteropServices\.Marshal\]::Copy\(.*etw",
        "ETW Memory Patching: Overwriting EtwEventWrite in memory to disable logging",
        "T1562.006",
        "Critical",
    ),
    (
        r"System\.Diagnostics\.Eventing\.EventProvider",
        "ETW Provider Reflection: Manipulating internal EventProvider state",
        "T1562.006",
        "Medium",
    ),
]


def analyze_security_controls(content: Union[str, bytes]) -> Dict[str, Any]:
    """Deterministically analyze content for defensive security control tampering."""
    if isinstance(content, bytes):
        text = content.decode("utf-8", errors="replace")
    else:
        text = content or ""

    findings: List[Dict[str, Any]] = []
    mitre_techniques: Set[str] = set()
    amsi_detected = False
    etw_detected = False

    # 1. Scan AMSI signatures
    for pat, desc, tid, sev in _AMSI_SIGNATURES:
        if re.search(pat, text, re.IGNORECASE):
            amsi_detected = True
            mitre_techniques.add(tid)
            findings.append({
                "control": "AMSI",
                "technique": tid,
                "severity": sev,
                "description": desc,
                "pattern": pat,
            })

    # 2. Scan ETW signatures
    for pat, desc, tid, sev in _ETW_SIGNATURES:
        if re.search(pat, text, re.IGNORECASE):
            etw_detected = True
            mitre_techniques.add(tid)
            findings.append({
                "control": "ETW",
                "technique": tid,
                "severity": sev,
                "description": desc,
                "pattern": pat,
            })

    # Determine tampering verdict
    is_tampering = len(findings) > 0
    verdict = "BENIGN"
    if any(f["severity"] == "Critical" for f in findings):
        verdict = "CRITICAL_TAMPERING"
    elif is_tampering:
        verdict = "SUSPICIOUS_TAMPERING"

    return {
        "tampering_detected": is_tampering,
        "verdict": verdict,
        "amsi_tampering": amsi_detected,
        "etw_tampering": etw_detected,
        "findings": findings,
        "mitre_techniques": sorted(list(mitre_techniques)),
        "finding_count": len(findings),
    }


__all__ = ["analyze_security_controls"]
