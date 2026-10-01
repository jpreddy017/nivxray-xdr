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
#
# Phase 3.y (2026-08-10) additive entries — narrative MITRE analyzer
# extension. Data-catalog completion ONLY; no projection LOGIC change.
# Existing entries above the divider are byte-identical to Phase 4 exit.
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
    # ── Phase 3.y additive entries (narrative vendor-report vocabulary) ──
    "T1219":     {"tactic": "command_and_control",
                  "kill_chain": "command_and_control"},
    "T1204.002": {"tactic": "execution",
                  "kill_chain": "actions_on_objectives"},
    "T1071":     {"tactic": "command_and_control",
                  "kill_chain": "command_and_control"},
    "T1486":     {"tactic": "impact",
                  "kill_chain": "actions_on_objectives"},
    "T1003":     {"tactic": "credential_access",
                  "kill_chain": "actions_on_objectives"},
    "T1566":     {"tactic": "initial_access",
                  "kill_chain": "delivery"},
    # ── Extended catalog (2026-08-10) so common legacy IDA techniques
    # get canonical tactic/kill-chain assignments in Workspace views.
    "T1027":     {"tactic": "defense_evasion",
                  "kill_chain": "actions_on_objectives"},
    "T1564.003": {"tactic": "defense_evasion",
                  "kill_chain": "actions_on_objectives"},
    "T1548.002": {"tactic": "privilege_escalation",
                  "kill_chain": "actions_on_objectives"},
    "T1562.001": {"tactic": "defense_evasion",
                  "kill_chain": "actions_on_objectives"},
    # ── Item-2 additive entries (2026-08-12, ADR-0010e §10 item 2)
    # Previously-missing metadata rows that caused the narrative
    # enricher to silently drop these techniques from the analyst
    # summary and mitre_matrix. Owner sign-off in the file header:
    # "Data-catalog completion ONLY; no projection LOGIC change".
    # Every row here has an official MITRE tactic mapping.
    "T1218.005": {"tactic": "defense_evasion",         # mshta
                  "kill_chain": "actions_on_objectives"},
    "T1218.004": {"tactic": "defense_evasion",         # InstallUtil
                  "kill_chain": "actions_on_objectives"},
    "T1218.007": {"tactic": "defense_evasion",         # msiexec
                  "kill_chain": "actions_on_objectives"},
    "T1218.008": {"tactic": "defense_evasion",         # odbcconf
                  "kill_chain": "actions_on_objectives"},
    "T1218.009": {"tactic": "defense_evasion",         # regasm / regsvcs
                  "kill_chain": "actions_on_objectives"},
    "T1562.004": {"tactic": "defense_evasion",         # netsh firewall disable
                  "kill_chain": "actions_on_objectives"},
    "T1197":     {"tactic": "defense_evasion",         # BITS jobs
                  "kill_chain": "actions_on_objectives"},
    "T1140":     {"tactic": "defense_evasion",         # deobfuscate / decode
                  "kill_chain": "actions_on_objectives"},
    "T1047":     {"tactic": "execution",               # WMI
                  "kill_chain": "actions_on_objectives"},
    "T1059.005": {"tactic": "execution",               # VBScript
                  "kill_chain": "actions_on_objectives"},
    "T1059.007": {"tactic": "execution",               # JavaScript
                  "kill_chain": "actions_on_objectives"},
    "T1112":     {"tactic": "defense_evasion",         # Modify Registry
                  "kill_chain": "actions_on_objectives"},
    "T1053.005": {"tactic": "persistence",             # Scheduled Task
                  "kill_chain": "actions_on_objectives"},
    "T1543.003": {"tactic": "persistence",             # Windows Service
                  "kill_chain": "actions_on_objectives"},
    "T1134.004": {"tactic": "defense_evasion",         # PPID Spoofing
                  "kill_chain": "actions_on_objectives"},
    "T1036.005": {"tactic": "defense_evasion",         # Masquerading
                  "kill_chain": "actions_on_objectives"},
    "T1490":     {"tactic": "impact",                  # Inhibit System Recovery
                  "kill_chain": "actions_on_objectives"},
    "T1070.001": {"tactic": "defense_evasion",         # Clear Event Logs
                  "kill_chain": "actions_on_objectives"},
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
