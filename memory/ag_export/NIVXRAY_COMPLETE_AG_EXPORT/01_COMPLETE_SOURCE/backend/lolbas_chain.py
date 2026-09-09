"""NivXRay — LOLBAS multi-stage chain + parent-child lineage detection (L2/L3).

Reads the list of `scan_lolbas()` hits for a decoded payload and returns:

- `stages[]`   — mapping of LOLBAS purposes to canonical adversary flow slots
                 (Download → Decode → Execute → Persist → Impact)
- `chain_score` (0–1) — normalised: 0.25 per distinct stage covered
- `is_chain`   — True when ≥ 2 distinct stages are covered
- `parent_child` — list of (parent_bin, child_bin) where a shell one-liner
                   contains another LOLBAS invocation (severity boost)
- `severity_boost` — {"low" | "medium" | "high"} qualitative uplift on the
                     verdict card

Pure Python, no I/O, no framework deps — safe to call from any decoder path.
"""
from __future__ import annotations
import re
from typing import Any, Dict, List, Tuple

# Canonical adversary flow stages — a payload that visits every column is
# a full-blown kill chain. The mapping below groups LOLBAS-declared
# "purposes" (Download, Decode, Execute, Persistence, ...) into 4 buckets.
STAGE_ORDER: List[str] = ["Download", "Decode", "Execute", "Persist", "Impact"]

_PURPOSE_TO_STAGE: Dict[str, str] = {
    "Download":         "Download",
    "Exfil":            "Impact",
    "Impact":           "Impact",
    "Decode":           "Decode",
    "AWL Bypass":       "Execute",
    "Execute":          "Execute",
    "Compile":          "Execute",
    "Lateral":          "Execute",
    "Persistence":      "Persist",
    "Discovery":        "Execute",   # discovery counts under execution slot
    "Defense Evasion":  "Execute",
    "Credential Access":"Execute",
    "File Copy":        "Download",
    "Staging":          "Download",
}

# Parent shells whose command-line may embed another LOLBAS invocation.
_PARENT_SHELLS = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe",
    "cscript.exe", "mshta.exe", "wmic.exe",
}


def compute_lolbas_chain(hits: List[Dict[str, Any]],
                          text: str = "") -> Dict[str, Any]:
    """Return chain-level metadata for a set of LOLBAS hits.

    Args:
        hits: output of `lolbas.scan_lolbas(text)`
        text: original decoded blob (needed for parent-child detection)

    Returns:
        A JSON-safe dict — always well-formed even when `hits` is empty.
    """
    if not hits:
        return {
            "stages": {s: [] for s in STAGE_ORDER},
            "distinct_stages": 0,
            "chain_score": 0.0,
            "is_chain": False,
            "parent_child": [],
            "severity_boost": "low",
            "flow_summary": "",
        }

    # ── Stage bucketing ─────────────────────────────────────────────
    stages: Dict[str, List[str]] = {s: [] for s in STAGE_ORDER}
    for h in hits:
        bin_name = h.get("binary", "?")
        for p in h.get("purposes", []) or []:
            slot = _PURPOSE_TO_STAGE.get(p)
            if slot and bin_name not in stages[slot]:
                stages[slot].append(bin_name)

    distinct = sum(1 for s in STAGE_ORDER if stages[s])
    chain_score = round(min(1.0, distinct * 0.25), 2)
    is_chain = distinct >= 2

    # ── Parent-child detection ──────────────────────────────────────
    parent_child: List[Tuple[str, str]] = []
    if text:
        text_lc = text.lower()
        for h in hits:
            b = h.get("binary", "").lower()
            if b not in _PARENT_SHELLS:
                continue
            # Find the shell's position; scan the following window (up
            # to 400 chars) for any other LOLBAS binary name.
            for m in re.finditer(re.escape(b), text_lc):
                window = text_lc[m.end(): m.end() + 400]
                for other in hits:
                    ob = other.get("binary", "").lower()
                    if ob == b or not ob:
                        continue
                    if re.search(rf"\b{re.escape(ob)}\b", window):
                        pair = (b, ob)
                        if pair not in parent_child:
                            parent_child.append(pair)

    # ── Severity uplift ─────────────────────────────────────────────
    # base = low. Chain of 2 stages OR any parent-child → medium.
    # Chain of ≥ 3 stages OR ≥ 2 parent-child edges → high.
    boost = "low"
    if is_chain or parent_child:
        boost = "medium"
    if distinct >= 3 or len(parent_child) >= 2:
        boost = "high"

    flow_summary = " → ".join(
        f"{s}({','.join(stages[s])})" for s in STAGE_ORDER if stages[s]
    )

    return {
        "stages": stages,
        "distinct_stages": distinct,
        "chain_score": chain_score,
        "is_chain": is_chain,
        "parent_child": [{"parent": p, "child": c} for p, c in parent_child],
        "severity_boost": boost,
        "flow_summary": flow_summary,
    }
