"""v2/investigation/attack_mapping.py · ATT&CK projection of the IKG.

Produces the "ATT&CK view" of the Investigation Knowledge Graph:
    · tactic-level coverage (deterministic level 0..3)
    · per-tactic technique list
    · kill-chain ordered stages
    · MITRE Navigator layer JSON (v4.5) for one-click export
    · STIX 2.1 bundle summary (fully rendered STIX still lives in
      v2/report/stix.py; this module hands it the technique set)

Read-only. Pure projection of ikg + verdict outputs. No new scoring.
"""
from __future__ import annotations
from typing import Any


# Deterministic tactic order — Enterprise ATT&CK canonical order.
TACTIC_ORDER: list[str] = [
    "reconnaissance", "resource_development",
    "initial_access", "execution", "persistence",
    "privilege_escalation", "defense_evasion", "credential_access",
    "discovery", "lateral_movement", "collection",
    "command_and_control", "exfiltration", "impact",
]

TACTIC_OF_BASE: dict[str, str] = {
    "T1189": "initial_access", "T1204": "initial_access", "T1566": "initial_access",
    "T1059": "execution",       "T1053": "execution",       "T1218": "execution",
    "T1547": "persistence",     "T1197": "persistence",     "T1546": "persistence",
    "T1027": "defense_evasion", "T1562": "defense_evasion", "T1055": "defense_evasion",
    "T1620": "defense_evasion", "T1140": "defense_evasion",
    "T1003": "credential_access", "T1555": "credential_access", "T1552": "credential_access",
    "T1087": "discovery", "T1082": "discovery", "T1482": "discovery", "T1033": "discovery",
    "T1021": "lateral_movement", "T1570": "lateral_movement",
    "T1560": "collection", "T1005": "collection",
    "T1071": "command_and_control", "T1105": "command_and_control", "T1090": "command_and_control",
    "T1041": "exfiltration", "T1567": "exfiltration",
    "T1486": "impact", "T1489": "impact", "T1490": "impact",
    "T1485": "impact", "T1491": "impact",
}


def _tactic_of(base: str) -> str | None:
    return TACTIC_OF_BASE.get(base)


def build_attack_mapping(ikg_dict: dict, dev_verdict: dict | None) -> dict[str, Any]:
    """Return the ATT&CK view of the case.

    Structure:
        {
          "tactics":     [{tactic, techniques: [{id, base, count}], level}, …],
          "techniques":  [{id, base, tactic, count}],
          "kill_chain":  [{tactic, techniques[], covered: bool}],
          "navigator":   { … MITRE Navigator v4.5 layer JSON … },
          "stix":        { technique_ids: [T…] }   (STIX rendered elsewhere)
        }
    """
    # 1 · Collect technique nodes + how often each is referenced by an event.
    technique_nodes = [n for n in ikg_dict.get("nodes", []) if n["type"] == "technique"]
    edges           = ikg_dict.get("edges", [])
    ref_count: dict[str, int] = {}
    for e in edges:
        if e["type"] == "maps_to":
            ref_count[e["target"]] = ref_count.get(e["target"], 0) + 1

    techniques: list[dict] = []
    for n in technique_nodes:
        tech_id = n["attrs"].get("technique_id") or n["label"]
        base    = str(tech_id).split(".", 1)[0]
        techniques.append({
            "id":     tech_id,
            "base":   base,
            "tactic": _tactic_of(base) or "unknown",
            "count":  ref_count.get(n["id"], 0),
        })
    techniques.sort(key=lambda t: (t["tactic"], t["id"]))

    # 2 · Tactic buckets.
    by_tactic: dict[str, list[dict]] = {}
    for t in techniques:
        by_tactic.setdefault(t["tactic"], []).append(t)
    tactics = []
    for tac in TACTIC_ORDER:
        techs = by_tactic.get(tac, [])
        if not techs:
            continue
        n_unique = len({t["base"] for t in techs})
        level = 3 if n_unique >= 3 else (2 if n_unique == 2 else 1)
        tactics.append({
            "tactic":     tac,
            "techniques": techs,
            "unique":     n_unique,
            "count":      sum(t["count"] for t in techs),
            "level":      level,
        })

    # 3 · Kill chain — every canonical tactic, marked covered when observed.
    kill_chain = []
    covered_set = {t["tactic"] for t in tactics}
    for tac in TACTIC_ORDER:
        kill_chain.append({
            "tactic":     tac,
            "techniques": [t["id"] for t in by_tactic.get(tac, [])],
            "covered":    tac in covered_set,
        })

    # 4 · MITRE Navigator v4.5 layer JSON.
    navigator = {
        "name":        f"NivXRay · IKG projection",
        "description": "Deterministic ATT&CK coverage exported by NivXRay.",
        "version":     "4.5",
        "domain":      "enterprise-attack",
        "techniques":  [
            {
                "techniqueID": t["id"],
                "score":       min(100, 25 + 15 * (t["count"] - 1)),
                "color":       "",
                "comment":     f"{t['count']} event(s) mapped this technique.",
                "enabled":     True,
                "metadata":    [],
            }
            for t in techniques
        ],
        "gradient": {
            "colors":   ["#8ec843", "#ffe766", "#ff6666"],
            "minValue": 0,
            "maxValue": 100,
        },
    }

    # 5 · STIX handoff — just the unique technique IDs.
    stix_techniques = sorted({t["id"] for t in techniques})

    return {
        "tactics":    tactics,
        "techniques": techniques,
        "kill_chain": kill_chain,
        "navigator":  navigator,
        "stix":       {"technique_ids": stix_techniques},
        "coverage_summary": {
            "unique_techniques": len(techniques),
            "unique_bases":      len({t["base"] for t in techniques}),
            "unique_tactics":    len(tactics),
        },
    }
