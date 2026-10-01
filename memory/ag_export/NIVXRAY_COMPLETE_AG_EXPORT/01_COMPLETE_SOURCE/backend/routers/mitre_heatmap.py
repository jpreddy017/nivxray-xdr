"""MITRE ATT&CK Detection Coverage Heatmap — Feb 2026

Read-only endpoint that returns the tool's MITRE ATT&CK coverage as a
matrix suitable for a frontend heatmap visualization.

Returned shape:
    {
      "total_heuristics": int,
      "unique_techniques": int,
      "tactics": ["Initial Access", "Execution", ...],  # ordered ATT&CK kill-chain
      "matrix": {
        "Execution": [
          {"id": "T1059.001", "name": "PowerShell", "count": 7,
           "severity": "high|medium|low", "sources": ["heuristics","yara","lolbas"]},
          ...
        ],
        ...
      },
      "top_techniques":  [(id, count), ...],       # 20 hottest
      "sparse_tactics":  ["Lateral Movement", ...] # < 5 techniques covered
    }

Endpoints:
    GET  /api/mitre/heatmap                — full coverage matrix
    GET  /api/mitre/heatmap/tactic/{name}  — techniques for one tactic
    POST /api/mitre/heatmap/probe          — probe a payload → return which
                                              heatmap cells lit up
"""
from __future__ import annotations
from collections import Counter, defaultdict
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from deps import get_current_user
from operations import MITRE_HEURISTICS, YARA_LITE, mitre_map

router = APIRouter()

# Canonical MITRE ATT&CK Enterprise kill-chain order
KILL_CHAIN = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]

# Best-effort technique name lookup (from heuristics + yara-lite metadata)
def _build_technique_index() -> Dict[str, Dict[str, Any]]:
    """Aggregate every known T-ID across MITRE_HEURISTICS + YARA_LITE + LOLBAS."""
    idx: Dict[str, Dict[str, Any]] = {}

    # 1) MITRE_HEURISTICS — richest metadata (id, name, tactic)
    for _pat, (tid, name, tactic) in MITRE_HEURISTICS:
        d = idx.setdefault(tid, {
            "id": tid, "name": name, "tactic": tactic,
            "sources": set(), "count": 0, "severity": "medium",
        })
        d["count"] += 1
        d["sources"].add("heuristics")
        # Prefer the shortest, cleanest name
        if len(name) < len(d.get("name") or ""):
            d["name"] = name

    # 2) YARA-lite → derive T-IDs from rule descriptions (best-effort)
    import re as _re
    for rule in YARA_LITE:
        for tid_m in _re.findall(r"\bT\d{4}(?:\.\d{3})?\b", rule.get("desc", "")):
            d = idx.setdefault(tid_m, {
                "id": tid_m, "name": rule.get("desc") or tid_m,
                "tactic": None, "sources": set(), "count": 0,
                "severity": rule.get("severity", "medium"),
            })
            d["sources"].add("yara")
            # Escalate severity if yara rule says high
            if rule.get("severity") == "high":
                d["severity"] = "high"

    # 3) LOLBAS registry
    try:
        from lolbas import LOLBAS_REGISTRY  # noqa: WPS433
        for lb in LOLBAS_REGISTRY:
            for tid_m in lb.get("mitre", []) or []:
                if isinstance(tid_m, str) and tid_m.startswith("T"):
                    d = idx.setdefault(tid_m, {
                        "id": tid_m, "name": lb.get("binary") or tid_m,
                        "tactic": None, "sources": set(), "count": 0,
                        "severity": "medium",
                    })
                    d["sources"].add("lolbas")
    except Exception:
        pass

    # Derive severity from heuristic-count if not set by yara
    for d in idx.values():
        d["sources"] = sorted(d["sources"])
        if d["count"] >= 8:
            d["severity"] = "high"
        elif d["count"] >= 3 and d["severity"] == "medium":
            d["severity"] = "high"

    return idx


def _default_tactic(tid: str) -> str:
    """Fallback tactic for T-IDs where MITRE_HEURISTICS didn't record one.
    Uses well-known ATT&CK conventions."""
    KNOWN = {
        "T1003": "Credential Access",
        "T1007": "Discovery",
        "T1016": "Discovery",
        "T1027": "Defense Evasion",
        "T1033": "Discovery",
        "T1036": "Defense Evasion",
        "T1047": "Execution",
        "T1049": "Discovery",
        "T1053": "Persistence",
        "T1055": "Defense Evasion",
        "T1057": "Discovery",
        "T1059": "Execution",
        "T1069": "Discovery",
        "T1074": "Collection",
        "T1082": "Discovery",
        "T1087": "Discovery",
        "T1090": "Command and Control",
        "T1095": "Command and Control",
        "T1102": "Command and Control",
        "T1105": "Command and Control",
        "T1120": "Discovery",
        "T1124": "Discovery",
        "T1136": "Persistence",
        "T1140": "Defense Evasion",
        "T1197": "Defense Evasion",
        "T1201": "Discovery",
        "T1218": "Defense Evasion",
        "T1219": "Command and Control",
        "T1486": "Impact",
        "T1490": "Impact",
        "T1497": "Defense Evasion",
        "T1518": "Discovery",
        "T1543": "Persistence",
        "T1547": "Persistence",
        "T1552": "Credential Access",
        "T1555": "Credential Access",
        "T1562": "Defense Evasion",
        "T1566": "Initial Access",
        "T1567": "Exfiltration",
        "T1571": "Command and Control",
        "T1583": "Resource Development",
        "T1588": "Resource Development",
        "T1615": "Discovery",
        "T1622": "Discovery",
    }
    base = tid.split(".")[0]
    return KNOWN.get(base, "Defense Evasion")


@router.get("/mitre/heatmap")
async def mitre_heatmap(user=Depends(get_current_user)):
    """Full MITRE ATT&CK coverage matrix, grouped by tactic."""
    idx = _build_technique_index()

    # Fill in missing tactics via default lookup
    for tid, d in idx.items():
        if not d.get("tactic"):
            d["tactic"] = _default_tactic(tid)

    matrix: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for tid, d in idx.items():
        matrix[d["tactic"]].append({
            "id": tid,
            "name": d["name"],
            "count": d["count"],
            "severity": d["severity"],
            "sources": d["sources"],
        })

    # Sort each tactic's techniques by count desc, then T-ID asc
    for tactic in matrix:
        matrix[tactic].sort(key=lambda t: (-t["count"], t["id"]))

    # Ordered tactic list (kill-chain order, then any extras alphabetically)
    ordered = [t for t in KILL_CHAIN if t in matrix]
    ordered += sorted([t for t in matrix if t not in KILL_CHAIN])

    # Top-20 hottest techniques
    top = sorted(idx.values(), key=lambda d: -d["count"])[:20]
    top_out = [{"id": d["id"], "name": d["name"], "count": d["count"],
                "tactic": d["tactic"], "severity": d["severity"]} for d in top]

    # Sparse tactics (< 5 techniques)
    sparse = [t for t in ordered if len(matrix[t]) < 5]

    return {
        "total_heuristics":  len(MITRE_HEURISTICS),
        "unique_techniques": len(idx),
        "tactics":           ordered,
        "matrix":            {t: matrix[t] for t in ordered},
        "top_techniques":    top_out,
        "sparse_tactics":    sparse,
    }


@router.get("/mitre/heatmap/tactic/{name}")
async def mitre_heatmap_by_tactic(name: str, user=Depends(get_current_user)):
    """Techniques covered under a single tactic."""
    full = await mitre_heatmap(user=user)
    if name not in full["matrix"]:
        raise HTTPException(status_code=404, detail=f"Unknown tactic: {name}")
    return {"tactic": name, "techniques": full["matrix"][name]}


class ProbeIn(BaseModel):
    text: str


@router.post("/mitre/heatmap/probe")
async def mitre_heatmap_probe(body: ProbeIn, user=Depends(get_current_user)):
    """Run mitre_map on a payload and return which heatmap cells lit up.
    Handy for "what does this trigger?" analyst queries."""
    text = (body.text or "").strip()
    if not text:
        raise HTTPException(status_code=422, detail="empty text")
    hits = mitre_map(text)
    cells = []
    for h in hits:
        cells.append({
            "id":      h["id"],
            "name":    h.get("technique") or h["id"],
            "tactic":  h.get("tactic") or _default_tactic(h["id"]),
        })
    # Group by tactic
    by_tactic: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for c in cells:
        by_tactic[c["tactic"]].append(c)
    return {
        "input_snippet":     text[:200],
        "total_hits":        len(cells),
        "unique_techniques": len({c["id"] for c in cells}),
        "cells":             cells,
        "by_tactic":         dict(by_tactic),
    }
