"""project_attck — canonical MITRE ATT&CK projection.

Reads mitre_technique evidence nodes + reasoning_steps. Byte_identity.
"""
from __future__ import annotations

from typing import Any, Dict, List

from ..ssot import AuthoritativeSSOT
from ..ssot.models import AttckProjection
from ._helpers import mitre_nodes, reasoning_by_rule_prefix


# Canonical technique → tactic + kill-chain phase mapping.
# ADR-005: this map is the ONLY place technique metadata lives (D4-3).
_TECHNIQUE_META: Dict[str, Dict[str, str]] = {
    "T1059.001": {"tactic": "execution",
                  "kill_chain": "actions_on_objectives"},
    "T1059.003": {"tactic": "execution",
                  "kill_chain": "actions_on_objectives"},
    "T1218.010": {"tactic": "defense_evasion",
                  "kill_chain": "actions_on_objectives"},
    "T1218.011": {"tactic": "defense_evasion",
                  "kill_chain": "actions_on_objectives"},
    "T1105":     {"tactic": "command_and_control",
                  "kill_chain": "command_and_control"},
}


def project_attck(ssot: AuthoritativeSSOT) -> AttckProjection:
    """Project ATT&CK techniques + tactics from evidence graph.

    Determinism: nodes iterated in stored order; result lists are
    sorted-unique.
    """
    techniques: List[Dict[str, Any]] = []
    seen_ids = set()

    # Match reasoning steps to their techniques for evidence linkage.
    rs_map: Dict[str, List[str]] = {}
    for r in reasoning_by_rule_prefix(ssot, "mitre."):
        # rs id shape: "rs.mitre.T1059.001"
        parts = r.id.split(".")
        if len(parts) >= 3:
            tid = ".".join(parts[2:])
            rs_map.setdefault(tid, []).append(r.rationale)

    for n in mitre_nodes(ssot):
        tid = str(n.attrs.get("technique_id", ""))
        if not tid or tid in seen_ids:
            continue
        seen_ids.add(tid)
        meta = _TECHNIQUE_META.get(tid, {})
        techniques.append({
            "id": tid,
            "name": n.label.split(":", 1)[-1].strip() if ":" in n.label else n.label,
            "tactic": meta.get("tactic", "unknown"),
            "kill_chain": meta.get("kill_chain", "unknown"),
            "matched_terms": sorted(list(n.attrs.get("matched", []))),
            "evidence_id": n.id,
            "rationales": sorted(rs_map.get(tid, [])),
        })

    # Sort techniques deterministically by id.
    techniques.sort(key=lambda t: t["id"])

    tactics    = sorted({t["tactic"] for t in techniques} - {"unknown"})
    kill_chain = sorted({t["kill_chain"] for t in techniques} - {"unknown"})

    return AttckProjection(
        techniques=techniques,
        tactics=tactics,
        kill_chain=kill_chain,
    )
