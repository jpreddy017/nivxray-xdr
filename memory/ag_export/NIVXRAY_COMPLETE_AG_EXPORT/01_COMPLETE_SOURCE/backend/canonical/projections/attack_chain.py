"""project_attack_chain — canonical kill-chain reconstruction.

Groups mitre_technique nodes into ordered kill-chain stages.
Byte_identity for stage structure; canonical_normalised for stage titles.
"""
from __future__ import annotations

from typing import Any, Dict, List

from ..ssot import AuthoritativeSSOT
from ._helpers import mitre_nodes
from .attck import _TECHNIQUE_META


# Canonical ordered kill-chain phases (Lockheed Martin + MITRE tactics mix).
_STAGE_ORDER: List[str] = [
    "reconnaissance",
    "resource_development",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact",
    "actions_on_objectives",
]
_STAGE_INDEX = {s: i for i, s in enumerate(_STAGE_ORDER)}


def project_attack_chain(ssot: AuthoritativeSSOT) -> List[Dict[str, Any]]:
    """Return an ordered list of kill-chain stages populated with the
    techniques observed at that stage.

    Empty when no MITRE evidence. No hand-waving inference — every
    stage entry must trace to at least one mitre_technique node.
    """
    stage_map: Dict[str, List[str]] = {}
    for n in mitre_nodes(ssot):
        tid = str(n.attrs.get("technique_id", ""))
        if not tid:
            continue
        meta = _TECHNIQUE_META.get(tid)
        if not meta:
            continue
        # Prefer tactic-as-stage; fall back to kill_chain if tactic not in order.
        stage = meta["tactic"] if meta["tactic"] in _STAGE_INDEX else meta["kill_chain"]
        stage_map.setdefault(stage, [])
        if tid not in stage_map[stage]:
            stage_map[stage].append(tid)

    stages: List[Dict[str, Any]] = []
    for stage in sorted(stage_map.keys(),
                        key=lambda s: _STAGE_INDEX.get(s, len(_STAGE_ORDER))):
        stages.append({
            "stage": stage,
            "order": _STAGE_INDEX.get(stage, len(_STAGE_ORDER)),
            "title": stage.replace("_", " ").title(),  # canonical
            "techniques": sorted(stage_map[stage]),
        })
    return stages
