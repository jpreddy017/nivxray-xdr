"""RC5 · Phase 5 · MITRE ATT&CK Navigator layer JSON export.

Given a list of `MitreMapping[]`, produce a valid Navigator v4.5 layer
document that can be pasted into https://mitre-attack.github.io/attack-navigator/
or attached to a case as evidence.

Layer schema reference: https://github.com/mitre-attack/attack-navigator/blob/master/layers/LAYERFORMAT.md

Deterministic:
  * Same mappings ⇒ byte-equal JSON (techniques sorted by
    (technique_id, sub_technique_id) to guarantee stability).
  * No datetime.now() — timestamps come from the caller if desired.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple

from .mitre_mapper import MitreMapping, MITRE_TACTIC_IDS


NAV_LAYER_VERSION = "4.5"
ATTACK_DOMAIN = "enterprise-attack"
ATTACK_VERSION = "14"


def _score_from_confidence(c: int) -> int:
    """Navigator score is 0-100; we reuse mapping confidence directly."""
    return max(0, min(100, int(c)))


def _color(c: int) -> str:
    # Deterministic 5-band gradient (green → red).
    if c >= 90:  return "#8b0000"    # dark red
    if c >= 75:  return "#c0392b"
    if c >= 50:  return "#e67e22"
    if c >= 25:  return "#f1c40f"
    return "#27ae60"


def build_navigator_layer(
    mappings: Iterable[MitreMapping],
    name: str = "NivXRay RC5 · MITRE v2",
    description: str = "Auto-generated ATT&CK layer from deterministic Behaviors.",
    case_id: Optional[str] = None,
) -> Dict[str, Any]:
    mappings = list(mappings)
    # Group by (technique_id, sub_technique_id) and merge — same technique
    # can appear in multiple mappings via different rules.
    per_tech: Dict[Tuple[str, Optional[str]], Dict[str, Any]] = {}
    for m in mappings:
        key = (m.technique_id, m.sub_technique_id)
        if key not in per_tech:
            per_tech[key] = {
                "technique_id": m.sub_technique_id or m.technique_id,
                "tactic": m.tactic,
                "tactic_name": m.tactic_name,
                "confidences": [],
                "comments": [],
                "rule_ids": [],
                "behavior_ids": [],
                "node_ids": [],
                "technique_name": m.technique_name,
            }
        g = per_tech[key]
        g["confidences"].append(m.confidence)
        g["comments"].append(
            f"{m.rule_id}: conf={m.confidence}, behaviors={len(m.evidence_behavior_ids)}, "
            f"nodes={len(m.evidence_node_ids)}"
        )
        g["rule_ids"].append(m.rule_id)
        g["behavior_ids"].extend(m.evidence_behavior_ids)
        g["node_ids"].extend(m.evidence_node_ids)

    techniques: List[Dict[str, Any]] = []
    for key in sorted(per_tech.keys(), key=lambda k: (k[0], k[1] or "")):
        g = per_tech[key]
        max_conf = max(g["confidences"])
        techniques.append({
            "techniqueID": g["technique_id"],
            "tactic": g["tactic"],
            "score": _score_from_confidence(max_conf),
            "color": _color(max_conf),
            "comment": (
                f"{g['technique_name']}\n"
                + "\n".join(sorted(set(g["comments"])))
                + f"\n--\nBehaviors: {', '.join(sorted(set(g['behavior_ids'])))}"
                + f"\nNodes:     {', '.join(sorted(set(g['node_ids'])))}"
            ),
            "enabled": True,
            "metadata": [
                {"name": "rule_ids", "value": ",".join(sorted(set(g["rule_ids"])))},
                {"name": "max_confidence", "value": str(max_conf)},
            ],
        })

    layer: Dict[str, Any] = {
        "name": name if not case_id else f"{name} · case={case_id}",
        "versions": {
            "layer": NAV_LAYER_VERSION,
            "attack": ATTACK_VERSION,
            "navigator": NAV_LAYER_VERSION,
        },
        "domain": ATTACK_DOMAIN,
        "description": description,
        "sorting": 3,
        "layout": {"layout": "side", "aggregateFunction": "max",
                   "showID": True, "showName": True},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#27ae60", "#f1c40f", "#e67e22", "#c0392b", "#8b0000"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "≥90 confidence", "color": "#8b0000"},
            {"label": "75-89 confidence", "color": "#c0392b"},
            {"label": "50-74 confidence", "color": "#e67e22"},
            {"label": "25-49 confidence", "color": "#f1c40f"},
            {"label": "<25 confidence", "color": "#27ae60"},
        ],
        "metadata": [
            {"name": "generator", "value": "nivxray-rc5-mitre-v2"},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#252525",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }
    return layer


__all__ = ["build_navigator_layer", "NAV_LAYER_VERSION",
           "ATTACK_DOMAIN", "ATTACK_VERSION"]
