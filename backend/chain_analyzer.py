"""Multi-Stage Payload Chain Analyzer.

Real-world attack chains (like the Lumma Stealer ClickFix flow documented by
Sophos, Feb 2025) span multiple PowerShell/CMD command lines: a stager that
copies a second command to clipboard, then a downloader, then a loader, then
the C2 beacon. Analysts need to trace the FULL chain, not just one snippet.

This module accepts an ordered list of stages, decodes each one deterministically
(no LLM), then computes a unified aggregate:
  * merged IOCs (URLs, IPs, domains, hashes, BTC)
  * merged MITRE ATT&CK techniques with tactic ordering
  * merged LOLBAS hits
  * merged YARA rules
  * detected malware family (heuristic vote across stages)
  * cross-stage kill-chain sequence
  * an overall SOC risk verdict

The aggregate is then optionally fed to Claude ONCE (not per-stage) to produce
an analyst-style attack-chain narrative — this is the "AI runs on aggregate"
design principle: deterministic bytes first, LLM narrative last.
"""
from __future__ import annotations
import re
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple


# ────────────────────────────────────────────────────────────────────────
# Auto-split: paste multiple payloads separated by blank lines (2+ newlines)
# ────────────────────────────────────────────────────────────────────────
_BLANK_LINE_SPLIT = re.compile(r"\n\s*\n+")


def auto_split_stages(text: str) -> List[str]:
    """Split a raw paste on blank-line boundaries. Trims whitespace.

    A single-stage input returns a 1-element list. Splitting only occurs
    when the caller pastes an obvious multi-payload block.
    """
    if not text or not text.strip():
        return []
    parts = [p.strip() for p in _BLANK_LINE_SPLIT.split(text.strip()) if p.strip()]
    return parts or [text.strip()]


# ────────────────────────────────────────────────────────────────────────
# Per-stage decode (reuses the deterministic engine — NO LLM per stage)
# ────────────────────────────────────────────────────────────────────────
async def decode_single_stage(payload: str, stage_index: int = 0) -> Dict[str, Any]:
    """Run the deterministic best-decode + extract all threat signals for one stage."""
    from analysis_core import deterministic_best_decode
    from operations import extract_iocs, mitre_map, yara_lite_scan, risk_score
    from lolbas import scan_lolbas
    from corrupt_payload_detector import detect_corrupt_payload
    import re as _re

    det = deterministic_best_decode(payload)
    decoded = det.get("output") or ""
    # Augment the scan corpus with reversed copies of same-quote-paired
    # string literals from the raw payload — captures PowerShell's
    # `[1..0]` char-reverse obfuscation trick (Feb-2026 fix, same logic
    # as /api/decode/smart).
    _quoted = _re.findall(r"(['\"])([^'\"\r\n]{6,256})\1", payload)
    _reversed_bits = [g[1][::-1] for g in _quoted if g and g[1]]
    combined = payload + "\n" + decoded
    if _reversed_bits:
        combined = combined + "\n" + "\n".join(_reversed_bits)

    iocs = extract_iocs(combined)
    mitre = mitre_map(combined)
    yara = yara_lite_scan(combined)
    lolbas = scan_lolbas(combined)
    corrupt = detect_corrupt_payload(payload)
    risk = risk_score(mitre, yara, iocs)

    return {
        "stage_index": stage_index,
        "input_preview": payload[:200] + ("…" if len(payload) > 200 else ""),
        "input_length": len(payload),
        "output": decoded,
        "output_length": len(decoded),
        "engine": det.get("engine"),
        "confidence": int(round((det.get("score") or 0.0) * 100)) if det.get("score") is not None else 100,
        "reached_shellcode": bool(det.get("reached_shellcode")),
        "steps": det.get("steps") or [],
        "iocs": iocs,
        "mitre": mitre,
        "yara": yara,
        "lolbas": lolbas,
        "risk": risk,
        "corrupt_payload": corrupt,
    }


# ────────────────────────────────────────────────────────────────────────
# Aggregate merging
# ────────────────────────────────────────────────────────────────────────
def _merge_iocs(stages: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    merged: Dict[str, List[str]] = {}
    for s in stages:
        for k, v in (s.get("iocs") or {}).items():
            if isinstance(v, list):
                merged.setdefault(k, [])
                for x in v:
                    if x not in merged[k]:
                        merged[k].append(x)
    return merged


def _merge_mitre(stages: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Merge MITRE technique hits across stages, preserving KILL-CHAIN ordering."""
    _TACTIC_ORDER = [
        "Reconnaissance", "Resource Development", "Initial Access", "Execution",
        "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
        "Discovery", "Lateral Movement", "Collection", "Command and Control",
        "Exfiltration", "Impact",
    ]
    seen: Dict[str, Dict[str, str]] = {}
    for s in stages:
        for m in (s.get("mitre") or []):
            tid = m.get("id")
            if not tid:
                continue
            if tid not in seen:
                seen[tid] = {**m, "first_seen_stage": s["stage_index"]}
            else:
                # Track that a technique fired in multiple stages
                seen[tid].setdefault("stages", []).append(s["stage_index"])
    ordered = sorted(seen.values(),
                     key=lambda m: (_TACTIC_ORDER.index(m.get("tactic", ""))
                                    if m.get("tactic", "") in _TACTIC_ORDER
                                    else 99, m["id"]))
    return ordered


def _merge_lolbas(stages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: Dict[str, Dict[str, Any]] = {}
    for s in stages:
        for h in (s.get("lolbas") or []):
            key = h.get("binary") or h.get("name") or str(h)
            if key not in seen:
                seen[key] = {**h, "first_seen_stage": s["stage_index"]}
    return list(seen.values())


def _merge_yara(stages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: Dict[str, Dict[str, Any]] = {}
    for s in stages:
        for r in (s.get("yara") or []):
            key = r.get("rule")
            if not key:
                continue
            if key not in seen:
                seen[key] = {**r, "first_seen_stage": s["stage_index"]}
    return list(seen.values())


# ────────────────────────────────────────────────────────────────────────
# Malware-family heuristic (voter across stages)
# ────────────────────────────────────────────────────────────────────────
_FAMILY_SIGNATURES: List[Tuple[str, re.Pattern[str]]] = [
    ("Lumma Stealer",     re.compile(r"lumma|stealc|artistsponsorship|clickfix", re.I)),
    ("Meterpreter/MSF",   re.compile(r"msfvenom|meterpreter|reverse_tcp|reverse_https|-bxor\s+0x", re.I)),
    ("Cobalt Strike",     re.compile(r"cobalt\s*strike|beacon|malleable|artifact\.exe", re.I)),
    ("Empire",            re.compile(r"invoke-empire|empire[_\-]?stage|-noni\s+-w\s+hidden.*iex", re.I)),
    ("QakBot",            re.compile(r"qakbot|qbot|regsvr32.*\.dat", re.I)),
    ("Emotet",            re.compile(r"emotet|epoch\s*[0-9]|feodo", re.I)),
    ("IcedID",            re.compile(r"icedid|bokbot|photoloader", re.I)),
    ("AsyncRAT",          re.compile(r"asyncrat|dcrat|venomrat", re.I)),
    ("Amadey",            re.compile(r"amadey", re.I)),
    ("RedLine Stealer",   re.compile(r"redline\s*stealer|redlinestealer|rl-token", re.I)),
    ("BumbleBee",         re.compile(r"bumblebee|bumble\.dll", re.I)),
    ("Generic Reverse Shell", re.compile(r"tcpclient.*443|new-object\s+net\.sockets", re.I)),
    ("Generic PowerShell Downloader", re.compile(r"downloadstring|invoke-webrequest|net\.webclient", re.I)),
]


def detect_malware_family(stages: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Vote for the most likely family across stages. Returns None if no signal."""
    votes: Counter[str] = Counter()
    evidence: Dict[str, List[str]] = {}
    for s in stages:
        text = (s.get("output") or "") + "\n" + (s.get("input_preview") or "")
        for family, rx in _FAMILY_SIGNATURES:
            m = rx.search(text)
            if m:
                votes[family] += 1
                evidence.setdefault(family, []).append(
                    f"stage {s['stage_index']}: '{m.group(0)}'")
    if not votes:
        return None
    top, count = votes.most_common(1)[0]
    return {
        "family": top,
        "confidence": min(100, count * 40),
        "hits": count,
        "evidence": evidence[top][:5],
    }


# ────────────────────────────────────────────────────────────────────────
# Aggregate risk (higher than max-of-stages — chains amplify)
# ────────────────────────────────────────────────────────────────────────
def _aggregate_risk(stages: List[Dict[str, Any]], merged_iocs: Dict[str, List[str]],
                    merged_mitre: List[Dict], merged_yara: List[Dict],
                    family: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Chain-aware risk score. Multi-stage attacks are strictly worse than single-stage."""
    from operations import risk_score
    base = risk_score(merged_mitre, merged_yara, merged_iocs)
    score = base["score"]
    # Chain amplifier: +5 per additional stage beyond the first, capped
    if len(stages) > 1:
        score = min(100, score + (len(stages) - 1) * 5)
    if family:
        # Known-family match is a huge tell
        score = min(100, score + 15)
    if score >= 70:
        verdict, level = "Malicious", "high"
    elif score >= 40:
        verdict, level = "Suspicious", "medium"
    elif score >= 15:
        verdict, level = "Low Risk", "low"
    else:
        verdict, level = "Benign", "safe"
    return {"score": score, "verdict": verdict, "level": level}


# ────────────────────────────────────────────────────────────────────────
# Main entry: decode chain → aggregate
# ────────────────────────────────────────────────────────────────────────
async def analyze_chain(stage_inputs: List[str]) -> Dict[str, Any]:
    """Decode + aggregate a chain of payloads. Returns per-stage results
    AND a unified aggregate (family, verdict, merged IOCs/MITRE/LOLBAS/YARA)."""
    stages: List[Dict[str, Any]] = []
    for i, payload in enumerate(stage_inputs):
        try:
            stages.append(await decode_single_stage(payload, stage_index=i))
        except Exception as e:
            stages.append({
                "stage_index": i, "input_preview": payload[:200],
                "output": "", "engine": None, "confidence": 0,
                "reached_shellcode": False, "steps": [],
                "iocs": {}, "mitre": [], "yara": [], "lolbas": [],
                "risk": {"score": 0, "verdict": "error", "level": "safe"},
                "corrupt_payload": None,
                "error": str(e)[:200],
            })

    merged_iocs   = _merge_iocs(stages)
    merged_mitre  = _merge_mitre(stages)
    merged_lolbas = _merge_lolbas(stages)
    merged_yara   = _merge_yara(stages)
    family        = detect_malware_family(stages)
    agg_risk      = _aggregate_risk(stages, merged_iocs, merged_mitre, merged_yara, family)

    # Kill-chain sequence: technique IDs in tactic-order with source stage
    kill_chain = [{
        "id": m["id"], "technique": m.get("technique", ""),
        "tactic": m.get("tactic", ""),
        "stage": m.get("first_seen_stage"),
    } for m in merged_mitre]

    concatenated_output = "\n\n───── stage boundary ─────\n\n".join(
        f"[Stage {s['stage_index']}] engine={s.get('engine')} conf={s.get('confidence')}\n{s.get('output') or ''}"
        for s in stages
    )

    return {
        "stage_count": len(stages),
        "stages": stages,
        "aggregate": {
            "iocs": merged_iocs,
            "mitre": merged_mitre,
            "lolbas": merged_lolbas,
            "yara": merged_yara,
            "family": family,
            "risk": agg_risk,
            "kill_chain": kill_chain,
            "concatenated_output": concatenated_output,
        },
    }
