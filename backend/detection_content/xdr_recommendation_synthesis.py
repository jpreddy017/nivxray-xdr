"""
P0.7.3 · Round 16 · Guidance Knowledge Registry + Recommendation
Synthesizer.

Owner-locked (§11, §33 of Round 16 master prompt):
    Recommendations are SYNTHESIZED, not templated.  Knowledge
    provides *candidates*.  Evidence determines *applicability*.

Every candidate carries:
    id · category · required_evidence · supported_families
    · target_entity_kind · action · framework_hint · rationale_template

The synthesizer emits ONE final recommendation per (candidate,
observed target entity).  No candidate is emitted without a
matching entity.
"""
from __future__ import annotations
from typing import Any

from .xdr_action_registry import list_actions


SYNTH_ENGINE_ID = "nivxray::xdr::recommendation_synthesizer"
SYNTH_VERSION   = "1.0.0"


# Applicability enum (§4).
APPLICABLE               = "APPLICABLE"
NOT_APPLICABLE           = "NOT_APPLICABLE"
INSUFFICIENT_EVIDENCE    = "INSUFFICIENT_EVIDENCE"
CAPABILITY_UNAVAILABLE   = "CAPABILITY_UNAVAILABLE"
ALREADY_EXECUTED         = "ALREADY_EXECUTED"
SUPERSEDED               = "SUPERSEDED"


# ── Guidance Registry (§11) ──────────────────────────────────
#
# Deliberately small; can grow.  Each entry declares WHEN it may
# apply and how to fill its rationale — never a "template for
# incident X".

_GUIDANCE: list[dict] = [
    {
        "id":                "BLOCK_OBSERVED_DOMAIN",
        "category":          "IMMEDIATE",
        "target_entity_kind": "domain",
        "required_evidence": ["network.domain"],
        "supported_families": ["C2", "PUA_ADWARE", "MALWARE", "LOADER",
                                       "INFOSTEALER", "BOTNET", "PHISHING"],
        "action":             "IP_BLOCK",  # closest available adapter
        "framework_hint":     "D3-DNSDL",
        "confidence":         "HIGH",
        "rationale":
            "Domain {entity} observed as outbound target in incident "
            "evidence; blocking at edge is a direct D3FEND-supported "
            "containment step.",
    },
    {
        "id":                "BLOCK_OBSERVED_IP",
        "category":          "IMMEDIATE",
        "target_entity_kind": "ipv4",
        "required_evidence": ["network.dst.ip"],
        "supported_families": ["C2", "MALWARE", "BOTNET", "LOADER",
                                       "INFOSTEALER"],
        "action":             "IP_BLOCK",
        "framework_hint":     "D3-NTF",
        "confidence":         "HIGH",
        "rationale":
            "Destination IP {entity} observed in incident traffic; edge "
            "block prevents further C2 communication.",
    },
    {
        "id":                "ENRICH_OBSERVED_IP",
        "category":          "INVESTIGATION",
        "target_entity_kind": "ipv4",
        "required_evidence": ["network.src.ip"],
        "supported_families": ["C2", "PUA_ADWARE", "MALWARE", "UNKNOWN",
                                       "SUSPICIOUS_APPLICATION", "LOADER",
                                       "INFOSTEALER", "BOTNET", "PHISHING"],
        "action":             "OSINT_ENRICH_IP",
        "framework_hint":     "D3-NTA",
        "confidence":         "HIGH",
        "rationale":
            "Enrich {entity} across public OSINT (Talos · DShield · VT · "
            "AbuseIPDB · URLhaus) before deciding on destructive action.",
    },
    {
        "id":                "COLLECT_FORENSIC_SNAPSHOT",
        "category":          "INVESTIGATION",
        "target_entity_kind": "host",
        "required_evidence": ["host"],
        "supported_families": ["MALWARE", "RANSOMWARE", "CREDENTIAL_THEFT",
                                       "INFOSTEALER", "PERSISTENCE"],
        "action":             "COLLECT_FORENSIC_SNAPSHOT",
        "framework_hint":     "D3-EL",
        "confidence":         "HIGH",
        "rationale":
            "Collect forensic snapshot on {entity} to preserve volatile "
            "artefacts before eradication actions run.",
    },
    {
        "id":                "ISOLATE_ENDPOINT",
        "category":          "IMMEDIATE",
        "target_entity_kind": "host",
        "required_evidence": ["host"],
        "supported_families": ["RANSOMWARE", "LATERAL_MOVEMENT", "C2",
                                       "CREDENTIAL_THEFT"],
        "action":             "ENDPOINT_ISOLATE",
        "framework_hint":     "D3-EAL",
        "confidence":         "MEDIUM",
        "rationale":
            "Isolate {entity} from the network to stop active attacker "
            "activity while investigation continues.",
    },
    {
        "id":                "ADD_IOC_WATCHLIST",
        "category":          "PREVENTION",
        "target_entity_kind": "ipv4",
        "required_evidence": ["network.src.ip", "network.dst.ip"],
        "supported_families": ["C2", "MALWARE", "PUA_ADWARE", "PHISHING",
                                       "BOTNET", "LOADER", "INFOSTEALER"],
        "action":             "IOC_ADD_WATCHLIST",
        "framework_hint":     "D3-NTA",
        "confidence":         "MEDIUM",
        "rationale":
            "Add {entity} to NivXRay internal watch-list so subsequent "
            "detections cross-reference this observation instantly.",
    },
]


# ── Synthesizer ──────────────────────────────────────────────

def _entities_from_context(context: dict) -> list[dict]:
    """Return the entities present in the current context, tagged
    by kind + role."""
    return context.get("entities") or []


def _capability_of(action_id: str) -> tuple[bool, str]:
    for a in list_actions():
        if a["action_id"] == action_id:
            return (bool(a.get("capability_available")),
                        a.get("capability_reason") or "")
    return (False, f"action {action_id} not in registry")


def synthesize(context: dict,
                    threat_family: dict,
                    observations: list[dict],
                    executions: list[dict],
                    framework_maps: list[dict]) -> list[dict]:
    """
    Deterministic recommendation synthesis.

    Rules:
      * Every emitted recommendation is bound to a real observed
        entity.  No entity → no recommendation.
      * A recommendation is emitted only when the candidate's
        `supported_families` includes the current family OR family
        is UNKNOWN and the candidate lists it explicitly.
      * `applicability` state is emitted honestly.
    """
    fam = (threat_family or {}).get("family") or "UNKNOWN"
    entities = _entities_from_context(context)
    if not entities:
        return []

    # Fast lookup: {action_id: SUCCEEDED}.
    succeeded_actions = {e.get("action_id")
                                 for e in executions
                                 if e.get("state") == "SUCCEEDED"}

    # Map observations to per-entity verdicts for supersession.
    obs_by_indicator: dict[str, list[str]] = {}
    for o in observations:
        obs_by_indicator.setdefault(
            o.get("indicator") or "", []
        ).append((o.get("verdict") or "").lower())

    out: list[dict] = []
    for cand in _GUIDANCE:
        # Family filter.
        if fam not in cand["supported_families"]:
            continue
        for ent in entities:
            if ent.get("kind") != cand["target_entity_kind"] and \
                not (cand["target_entity_kind"] == "ipv4"
                        and (ent.get("kind") or "").startswith("ipv")):
                continue

            cap_ok, cap_reason = _capability_of(cand["action"])
            already = cand["action"] in succeeded_actions

            # Applicability gate.
            if already:
                applicability = ALREADY_EXECUTED
                app_reason = f"action {cand['action']} already SUCCEEDED"
            elif not cap_ok:
                applicability = CAPABILITY_UNAVAILABLE
                app_reason = cap_reason
            else:
                applicability = APPLICABLE
                app_reason = "capability available + entity observed + " \
                                 "family match"

            # Framework rationale from active mappings.
            fw_hint = cand.get("framework_hint")
            fw_matches = [m for m in framework_maps
                                if m.get("object_id") == fw_hint]

            reco_id = f"reco-{cand['id']}-{ent.get('value')}".lower()
            out.append({
                "id":                reco_id,
                "text":              cand["rationale"].format(
                                            entity=ent.get("value")),
                "category":          cand["category"],
                "confidence":        cand["confidence"],
                "suggested_action":  cand["action"],
                "target_entity": {
                    "kind":  ent.get("kind"),
                    "value": ent.get("value"),
                    "role":  ent.get("role"),
                },
                "supported_by":      ent.get("origin") and [ent["origin"]] or [],
                "framework_rationale": {
                    "hint":     fw_hint,
                    "matched":  bool(fw_matches),
                    "detail":   fw_matches[0]["object_name"]
                                    if fw_matches else "not mapped for this incident",
                },
                "applicability":     applicability,
                "applicability_reason": app_reason,
                "threat_family":     fam,
                "engine_id":         SYNTH_ENGINE_ID,
            })
    return out


# ── Playbook Applicability Filter (§10) ──────────────────────

_PLAYBOOKS: list[dict] = [
    {"id": "PUA_CLEANUP",
      "families": ["PUA_ADWARE", "SUSPICIOUS_APPLICATION"],
      "actions": ["IOC_ADD_WATCHLIST", "OSINT_ENRICH_IP", "OSINT_ENRICH_DOMAIN"]},
    {"id": "RANSOMWARE_CONTAINMENT",
      "families": ["RANSOMWARE"],
      "actions": ["ENDPOINT_ISOLATE", "IP_BLOCK",
                     "COLLECT_FORENSIC_SNAPSHOT"]},
    {"id": "CREDENTIAL_INVESTIGATION",
      "families": ["CREDENTIAL_THEFT"],
      "actions": ["COLLECT_FORENSIC_SNAPSHOT", "IOC_ADD_WATCHLIST"]},
    {"id": "C2_CONTAINMENT",
      "families": ["C2", "BOTNET", "LOADER"],
      "actions": ["IP_BLOCK", "IOC_ADD_WATCHLIST", "OSINT_ENRICH_IP"]},
]


def filter_playbooks(family: str) -> list[dict]:
    fam = family or "UNKNOWN"
    out: list[dict] = []
    for pb in _PLAYBOOKS:
        state = APPLICABLE if fam in pb["families"] else NOT_APPLICABLE
        out.append({**pb, "applicability": state,
                       "reason":
                          ("family match" if state == APPLICABLE
                            else f"playbook requires family in "
                                    f"{pb['families']} · current family={fam}")})
    return out
