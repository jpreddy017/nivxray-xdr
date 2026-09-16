"""project_recommendations — canonical evidence-derived recommendations.

** P4-FW3 · NO GENERIC FALLBACK **

If SSOT has NO MITRE evidence, this returns an empty list plus a
projection reasoning note stating exactly that. NEVER emits the generic
"IMMEDIATE / THREAT HUNTING / CONTAINMENT" block.
"""
from __future__ import annotations

from typing import Any, Dict, List

from ..ssot import AuthoritativeSSOT
from ._helpers import make_reasoning_note, mitre_nodes


# Per-technique deterministic recommendations. NO GENERIC FALLBACK.
#
# Phase 3.y (2026-08-10) additive entries — data-catalog completion for
# the narrative MITRE rules. No projection LOGIC change; entries above
# the divider are byte-identical to Phase 4 exit.
_RECS_BY_TECHNIQUE: Dict[str, List[Dict[str, str]]] = {
    "T1059.001": [
        {"action": "audit_powershell_execution_policy",
         "severity": "high",
         "rationale": "T1059.001 evidence — restrict PowerShell execution"},
        {"action": "enable_scriptblock_logging",
         "severity": "high",
         "rationale": "T1059.001 evidence — capture EncodedCommand payloads"},
    ],
    "T1059.003": [
        {"action": "audit_cmd_child_processes",
         "severity": "medium",
         "rationale": "T1059.003 evidence — inventory cmd.exe descendants"},
    ],
    "T1218.010": [
        {"action": "block_regsvr32_scriptlet_execution",
         "severity": "high",
         "rationale": "T1218.010 evidence — Squiblydoo variant risk"},
    ],
    "T1218.011": [
        {"action": "restrict_rundll32_execution_paths",
         "severity": "high",
         "rationale": "T1218.011 evidence — proxied DLL execution"},
    ],
    "T1105": [
        {"action": "block_outbound_tool_ingress",
         "severity": "high",
         "rationale": "T1105 evidence — certutil/curl/wget observed"},
    ],
    # ── Phase 3.y additive entries ────────────────────────────────────
    "T1219": [
        {"action": "isolate_endpoint_and_block_c2_egress",
         "severity": "critical",
         "rationale": "T1219 evidence — Remote Access Software identified"},
        {"action": "collect_edr_process_tree_for_rat_binary",
         "severity": "high",
         "rationale": "T1219 evidence — capture RAT process ancestry"},
    ],
    "T1204.002": [
        {"action": "quarantine_reported_malicious_file",
         "severity": "high",
         "rationale": "T1204.002 evidence — user execution of malicious file"},
        {"action": "review_delivery_vector_email_or_web",
         "severity": "medium",
         "rationale": "T1204.002 evidence — trace how the file reached the user"},
    ],
    "T1071": [
        {"action": "block_c2_domain_and_ip",
         "severity": "critical",
         "rationale": "T1071 evidence — command-and-control channel active"},
    ],
    "T1486": [
        {"action": "activate_ransomware_incident_response_plan",
         "severity": "critical",
         "rationale": "T1486 evidence — data encrypted for impact"},
        {"action": "restore_from_offline_backup",
         "severity": "critical",
         "rationale": "T1486 evidence — recovery required from clean backup"},
    ],
    "T1003": [
        {"action": "rotate_domain_credentials",
         "severity": "critical",
         "rationale": "T1003 evidence — credential dumping tool observed"},
    ],
    "T1566": [
        {"action": "block_sender_and_pull_message_from_all_mailboxes",
         "severity": "high",
         "rationale": "T1566 evidence — phishing delivery identified"},
    ],
}


def project_recommendations(ssot: AuthoritativeSSOT) -> Dict[str, Any]:
    """Return {"items": [...], "notes": [...]}.

    P4-FW3 enforced: if no MITRE evidence, items = [] and notes contains
    the mandatory "no evidence-derived recommendations" statement. No
    generic Isolate/Threat-Hunt/Containment template is EVER emitted.
    """
    mnodes = mitre_nodes(ssot)

    if not mnodes:
        return {
            "items": [],
            "notes": [
                make_reasoning_note(
                    projection="project_recommendations",
                    message=("no evidence-derived recommendations for this "
                             "case (no MITRE evidence)"),
                ),
            ],
        }

    items: List[Dict[str, Any]] = []
    seen_ids = set()
    for n in mnodes:
        tid = str(n.attrs.get("technique_id", ""))
        if not tid or tid in seen_ids:
            continue
        seen_ids.add(tid)
        for rec in _RECS_BY_TECHNIQUE.get(tid, []):
            items.append({
                **rec,
                "technique_id": tid,
                "evidence_id": n.id,
            })

    if not items:
        # MITRE evidence exists but the technique is not in the canonical
        # recommendation map — still MUST NOT invent generic advice.
        return {
            "items": [],
            "notes": [make_reasoning_note(
                projection="project_recommendations",
                message=("MITRE evidence present but no canonical "
                         "recommendation registered for observed techniques"),
            )],
        }

    # Deterministic order: by technique_id, then action.
    items.sort(key=lambda x: (x["technique_id"], x["action"]))
    return {"items": items, "notes": []}
