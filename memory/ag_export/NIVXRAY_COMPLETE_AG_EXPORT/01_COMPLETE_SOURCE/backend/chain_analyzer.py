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

    Feb 2026 v1.3.1: also normalises `<br>`, `<br/>`, `<br />` HTML line
    breaks (common in Splunk / Kibana / Sentinel log exports) so pasted
    dumps split cleanly.
    """
    if not text or not text.strip():
        return []
    # Normalise HTML line breaks → real newlines. Case-insensitive.
    normalised = re.sub(r"(?i)<\s*br\s*/?\s*>", "\n\n", text)
    parts = [p.strip() for p in _BLANK_LINE_SPLIT.split(normalised.strip()) if p.strip()]
    return parts or [normalised.strip()]


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

    # ── Confidence formula (Feb 2026) ───────────────────────────────────
    # Base confidence = deterministic-decoder score. But for plain-text
    # LOLBAS payloads (no encoding, nothing to decode) the score sits
    # near 0.4-0.6 while the payload IS still a high-fidelity malicious
    # command (e.g. `reg.exe add HKLM\...\Run /v Backdoor`). We upgrade
    # confidence proportional to the strength of MITRE + LOLBAS + YARA
    # signals so plain-command scenarios read as high-confidence bad,
    # while noisy edge cases stay near their deterministic score.
    _base_conf = (
        int(round((det.get("score") or 0.0) * 100))
        if det.get("score") is not None else 100
    )
    _signal_boost = min(
        30,
        3 * len(mitre) + 4 * len(lolbas) + 6 * len(yara),
    )
    _confidence = min(100, max(_base_conf, _base_conf + _signal_boost // 2))
    # Also clamp: if we have ≥2 LOLBAS + ≥1 MITRE hit, floor at 75 —
    # this is deterministically an "actionable" verdict for a SOC even
    # without any decoding.
    if len(lolbas) >= 2 and len(mitre) >= 1:
        _confidence = max(_confidence, 75)
    elif len(lolbas) >= 1 and len(mitre) >= 1:
        _confidence = max(_confidence, 70)
    elif len(mitre) >= 2 and len(yara) >= 1:
        _confidence = max(_confidence, 68)
    elif len(mitre) >= 1 and len(yara) >= 2:
        # Weaker but still deterministically actionable: one MITRE + two YARA
        # (e.g. bash reverse-pipe: T1027.010 + Bash_Rev_Pipe_Shell + case-mixed)
        _confidence = max(_confidence, 65)
    elif len(mitre) >= 1 and len(lolbas) == 0 and len(yara) >= 1:
        # LOLBIN doesn't classify (cmstp, xwizard, etc.) but MITRE fires
        _confidence = max(_confidence, 65)

    return {
        "stage_index": stage_index,
        "input_preview": payload[:200] + ("…" if len(payload) > 200 else ""),
        "input_length": len(payload),
        "output": decoded,
        "output_length": len(decoded),
        "engine": det.get("engine"),
        "confidence": _confidence,
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

    # ── LOLBAS-based Destructive Wiper / Ransomware Precursor heuristic ──
    # Fires when the aggregate LOLBAS set contains ≥3 unique binaries from
    # the destructive-impact family (VSS deletion, backup deletion, event-log
    # wipe, boot-config tamper, USN-journal wipe, free-space overwrite).
    # This runs INDEPENDENTLY of the regex voter above and wins on tie because
    # the LOLBAS signal is a much higher-fidelity indicator than a string match.
    _WIPER_BINS = {"vssadmin.exe", "wbadmin.exe", "wevtutil.exe",
                   "bcdedit.exe", "fsutil.exe", "cipher.exe"}
    seen_wiper: Dict[str, str] = {}
    for s in stages:
        for hit in (s.get("lolbas") or []):
            bin_name = (hit.get("binary") or hit.get("name") or "").lower()
            if bin_name in _WIPER_BINS and bin_name not in seen_wiper:
                seen_wiper[bin_name] = f"stage {s['stage_index']}: {bin_name}"
    if len(seen_wiper) >= 3:
        wiper_conf = min(100, 60 + (len(seen_wiper) - 3) * 10)
        return {
            "family": "Destructive Wiper / Ransomware Precursor",
            "confidence": wiper_conf,
            "hits": len(seen_wiper),
            "evidence": list(seen_wiper.values())[:6],
        }

    if not votes:
        return None
    top, count = votes.most_common(1)[0]
    # Feb-2026 · weak-evidence gate (Priority 1 correctness):
    # A single regex hit is NOT sufficient to attribute a malware family.
    # Require ≥ 2 corroborating signal hits before returning a family
    # match — a single string coincidence must not drive verdict
    # elevation. Weak single-hit candidates are surfaced as
    # `provisional=True` for analyst review but do NOT influence risk.
    if count < 2:
        return {
            "family": top,
            "confidence": 20,           # low, and NOT verdict-elevating
            "hits": count,
            "evidence": evidence[top][:5],
            "provisional": True,
        }
    return {
        "family": top,
        "confidence": min(100, count * 40),
        "hits": count,
        "evidence": evidence[top][:5],
        "provisional": False,
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
    if family and not family.get("provisional", False):
        # Feb-2026 · Only firm (non-provisional) family attributions
        # contribute to risk. Weak single-hit provisional matches are
        # surfaced for analyst review but must not elevate verdict tier.
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

    # ── Feb-2026 v1.2.0 · Threat-Intel enrichment on the AGGREGATE ─────
    # Prior versions only ran TI lookups per-stage in the single-decode
    # router, leaving `/api/decode/chain` blind — multi-line pastes showed
    # 0 TI-HITS even when merged IOCs matched local feed entries. We now
    # run lookup_ti_hits(...) ONCE on the merged IOC set so the chain
    # response exposes the same enrichment surface as single-stage decode.
    ti_hits: List[Dict[str, Any]] = []
    try:
        from analysis_core import lookup_ti_hits as _lookup_ti
        ti_hits = await _lookup_ti(merged_iocs)
    except Exception:
        ti_hits = []

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
            "ti_hits": ti_hits,
        },
    }
