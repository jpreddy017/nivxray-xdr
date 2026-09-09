"""NivXRay — AMSI-bypass detector.

Signature-based scanner for the most common AMSI (Antimalware Scan Interface)
bypass techniques used in real-world PowerShell payloads. Runs on the raw
command line *and* on every decoded layer produced by the pipeline, so it
catches bypasses hidden inside base64/xor wrappers.

Returns a structured report:
    {
        "detected":  bool,
        "severity":  "low" | "medium" | "high" | "critical",
        "techniques": [{name, pattern_id, evidence, confidence, mitre_id}],
        "amsi_related_count": int,
        "etw_related_count":  int,
    }
"""
from __future__ import annotations
import re
from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass
class Technique:
    pattern_id: str
    name: str
    pattern: re.Pattern
    confidence: float
    mitre_id: str
    category: str = "amsi"                                  # "amsi" | "etw" | "reflection"


TECHNIQUES: List[Technique] = [
    # -------------------------- Direct string references --------------------------
    Technique(
        "amsi-utils-ref",
        "AmsiUtils direct reference",
        re.compile(r"System\.Management\.Automation\.AmsiUtils", re.I),
        confidence=0.85, mitre_id="T1562.001",
    ),
    Technique(
        "amsi-initfailed-field",
        "amsiInitFailed field access (classic bypass)",
        re.compile(r"\bamsiInitFailed\b", re.I),
        confidence=0.98, mitre_id="T1562.001",
    ),
    Technique(
        "amsi-scanbuffer",
        "AmsiScanBuffer reference (unhooking / patching)",
        re.compile(r"AmsiScanBuffer\w*", re.I),
        confidence=0.95, mitre_id="T1562.001",
    ),
    Technique(
        "amsi-context",
        "AmsiContext / AmsiSession references",
        re.compile(r"\bAmsi(?:Context|Session|OpenSession|CloseSession)\b", re.I),
        confidence=0.80, mitre_id="T1562.001",
    ),

    # -------------------------- Reflection-based patching --------------------------
    Technique(
        "reflection-amsi-getfield",
        "Reflection: GetField('amsiInitFailed', ...)",
        re.compile(
            r"GetField\s*\(\s*['\"]amsiInitFailed['\"]",
            re.I,
        ),
        confidence=0.98, mitre_id="T1562.001", category="reflection",
    ),
    Technique(
        "reflection-amsi-setvalue-true",
        "Reflection: SetValue($null, $true) on AmsiUtils",
        re.compile(
            r"AmsiUtils[^\n]{0,120}SetValue\s*\(\s*\$?null\s*,\s*\$?true\s*\)",
            re.I | re.S,
        ),
        confidence=0.99, mitre_id="T1562.001", category="reflection",
    ),
    Technique(
        "reflection-getassembly-automation",
        "[Ref].Assembly.GetType('System.Management.Automation.…')",
        re.compile(
            r"\[?Ref\]?\.Assembly\.GetType\s*\(\s*['\"]System\.Management\.Automation\.",
            re.I,
        ),
        confidence=0.80, mitre_id="T1562.001", category="reflection",
    ),

    # -------------------------- Byte-patch sequences ---------------------------
    Technique(
        "amsi-bytepatch-metsysbench",
        "Metsysbench AmsiScanBuffer byte patch (0xB8 0x57 0x00 0x07 0x80 0xC3)",
        re.compile(
            r"0xB8\s*,\s*0x57\s*,\s*0x00\s*,\s*0x07\s*,\s*0x80\s*,\s*0xC3",
            re.I,
        ),
        confidence=0.99, mitre_id="T1562.001",
    ),
    Technique(
        "amsi-bytepatch-xor-ret",
        "AmsiScanBuffer patch: xor eax,eax; ret (0x31 0xC0 0xC3)",
        re.compile(r"0x31\s*,\s*0xC0\s*,\s*0xC3", re.I),
        confidence=0.85, mitre_id="T1562.001",
    ),

    # -------------------------- Memory helpers ---------------------------------
    Technique(
        "virtualprotect-amsi",
        "VirtualProtect on AMSI region (patching)",
        re.compile(r"VirtualProtect[^\n]{0,180}(?:Amsi|amsiInitFailed)", re.I | re.S),
        confidence=0.95, mitre_id="T1562.001", category="reflection",
    ),
    Technique(
        "loadlibrary-amsi",
        "LoadLibrary('amsi.dll') — pre-patch step",
        re.compile(r"LoadLibrary\s*\(\s*['\"]amsi\.dll['\"]", re.I),
        confidence=0.90, mitre_id="T1562.001",
    ),

    # -------------------------- ETW logging bypass -----------------------------
    Technique(
        "etw-eventwrite",
        "EtwEventWrite patch (silence ETW logging)",
        re.compile(r"\bEtwEventWrite\b", re.I),
        confidence=0.90, mitre_id="T1562.006", category="etw",
    ),
    Technique(
        "etw-eventpipe",
        "System.Diagnostics.Eventing / EventPipe tampering",
        re.compile(r"System\.Diagnostics\.Eventing", re.I),
        confidence=0.65, mitre_id="T1562.006", category="etw",
    ),

    # -------------------------- Known bypass strings ---------------------------
    Technique(
        "bypass-known-nishang",
        "Known bypass phrasing (Nishang-style)",
        re.compile(
            r"amsi(?:InitFailed|Utils)[^\n]{0,60}(?:True|1)",
            re.I,
        ),
        confidence=0.90, mitre_id="T1562.001",
    ),
    Technique(
        "bypass-known-mattifest",
        "Known bypass phrasing (Mattifestation / matt.graeber pattern)",
        re.compile(
            r"amsiInitFailed[^\n]{0,60}NonPublic\s*,\s*Static",
            re.I,
        ),
        confidence=0.95, mitre_id="T1562.001",
    ),
]


def _find_evidence(text: str, pat: re.Pattern) -> str:
    m = pat.search(text)
    if not m:
        return ""
    start = max(0, m.start() - 12)
    end   = min(len(text), m.end() + 24)
    snip  = text[start:end].strip().replace("\n", "\\n")
    if len(snip) > 100:
        snip = snip[:100] + "…"
    return snip


def _severity_from_matches(matches: List[Dict[str, Any]]) -> str:
    if not matches:
        return "none"
    best = max(m["confidence"] for m in matches)
    n = len(matches)
    if best >= 0.98 or n >= 3:
        return "critical"
    if best >= 0.90:
        return "high"
    if best >= 0.75:
        return "medium"
    return "low"


def detect_amsi_bypass(text: str) -> Dict[str, Any]:
    """Scan `text` (raw or decoded) for AMSI/ETW bypass indicators."""
    if not text:
        return {"detected": False, "severity": "none", "techniques": [],
                "amsi_related_count": 0, "etw_related_count": 0}

    seen_ids = set()
    hits: List[Dict[str, Any]] = []
    for t in TECHNIQUES:
        if t.pattern.search(text) and t.pattern_id not in seen_ids:
            seen_ids.add(t.pattern_id)
            hits.append({
                "pattern_id": t.pattern_id,
                "name":       t.name,
                "category":   t.category,
                "confidence": t.confidence,
                "mitre_id":   t.mitre_id,
                "evidence":   _find_evidence(text, t.pattern),
            })
    # sort by confidence desc so the strongest signal is first
    hits.sort(key=lambda h: -h["confidence"])
    amsi_ct = sum(1 for h in hits if h["category"] in ("amsi", "reflection"))
    etw_ct  = sum(1 for h in hits if h["category"] == "etw")
    return {
        "detected":            bool(hits),
        "severity":            _severity_from_matches(hits),
        "techniques":          hits,
        "amsi_related_count":  amsi_ct,
        "etw_related_count":   etw_ct,
    }
