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
from .xdr_mitigation_intelligence import (
    enrich_recommendation, is_exclusion as _is_exclusion,
)
from .xdr_response_strategy import (
    compose_candidate_set as _compose_strategy_set,
)


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
        "action":             "IP_BLOCK",
        "framework_hint":     "D3-DNSDL",
        "confidence":         "HIGH",
        "evidence_strength":  "DIRECT",
        "base_priority":      "HIGH",
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
        "evidence_strength":  "DIRECT",
        "base_priority":      "HIGH",
        "rationale":
            "Destination IP {entity} observed in incident traffic; edge "
            "block prevents further C2 communication.",
    },
    {
        "id":                "BLOCK_OBSERVED_HASH",
        "category":          "IMMEDIATE",
        "target_entity_kind": "hash",
        "required_evidence": ["file.hash"],
        "supported_families": ["MALWARE", "RANSOMWARE", "INFOSTEALER",
                                       "LOADER", "WORM"],
        "action":             "IOC_ADD_WATCHLIST",
        "framework_hint":     "D3-EAL",
        "confidence":         "HIGH",
        "evidence_strength":  "DIRECT",
        "base_priority":      "HIGH",
        "rationale":
            "File hash {entity} observed on affected endpoint; add to "
            "block-list to prevent execution across environment.",
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
        "evidence_strength":  "DIRECT",
        "base_priority":      "MEDIUM",
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
        "evidence_strength":  "DIRECT",
        "base_priority":      "HIGH",
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
        "evidence_strength":  "CORROBORATED",
        "base_priority":      "CRITICAL",
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
        "evidence_strength":  "DIRECT",
        "base_priority":      "MEDIUM",
        "rationale":
            "Add {entity} to NivXRay internal watch-list so subsequent "
            "detections cross-reference this observation instantly.",
    },
    # ── Round 17 · new candidates (guidance knowledge only) ─────
    {
        "id":                "REMOVE_STARTUP_PERSISTENCE",
        "category":          "REMEDIATION",
        "target_entity_kind": "startup_entry",
        "required_evidence": ["persistence.startup"],
        "supported_families": ["PUA_ADWARE", "MALWARE", "PERSISTENCE",
                                       "INFOSTEALER", "LOADER"],
        "action":             "COLLECT_FORENSIC_SNAPSHOT",  # via EDR when wired
        "framework_hint":     "D3-EL",
        "confidence":         "HIGH",
        "evidence_strength":  "DIRECT",
        "base_priority":      "HIGH",
        "rationale":
            "Startup persistence entry {entity} observed; remove to prevent "
            "the associated application from re-launching at boot.",
    },
    {
        "id":                "UNINSTALL_APPLICATION",
        "category":          "REMEDIATION",
        "target_entity_kind": "application",
        "required_evidence": ["application.name"],
        "supported_families": ["PUA_ADWARE", "SUSPICIOUS_APPLICATION"],
        "action":             "COLLECT_FORENSIC_SNAPSHOT",
        "framework_hint":     "D3-EAL",
        "confidence":         "HIGH",
        "evidence_strength":  "DIRECT",
        "base_priority":      "HIGH",
        "rationale":
            "Uninstall application {entity} — observed on affected "
            "endpoint and consistent with PUA/adware behaviour.",
    },
    {
        "id":                "TERMINATE_PROCESS",
        "category":          "IMMEDIATE",
        "target_entity_kind": "process",
        "required_evidence": ["process.image"],
        "supported_families": ["PUA_ADWARE", "MALWARE", "RANSOMWARE",
                                       "INFOSTEALER", "LOADER", "C2"],
        "action":             "COLLECT_FORENSIC_SNAPSHOT",
        "framework_hint":     "D3-EAL",
        "confidence":         "MEDIUM",
        "evidence_strength":  "DIRECT",
        "base_priority":      "HIGH",
        "rationale":
            "Terminate process {entity} — observed as an associated "
            "component of the incident.",
    },
    {
        "id":                "REVOKE_CREDENTIAL",
        "category":          "IMMEDIATE",
        "target_entity_kind": "user",
        "required_evidence": ["identity.user"],
        "supported_families": ["CREDENTIAL_THEFT", "LATERAL_MOVEMENT"],
        "action":             "COLLECT_FORENSIC_SNAPSHOT",  # IAM adapter TBD
        "framework_hint":     "D3-EAL",
        "confidence":         "HIGH",
        "evidence_strength":  "CORROBORATED",
        "base_priority":      "CRITICAL",
        "rationale":
            "Revoke credential/session for {entity} — credential-theft "
            "signal detected.",
    },
    {
        "id":                "SEARCH_ENVIRONMENT_FOR_INDICATOR",
        "category":          "INVESTIGATION",
        "target_entity_kind": "ipv4",
        "required_evidence": ["network.src.ip", "network.dst.ip"],
        "supported_families": ["C2", "MALWARE", "PUA_ADWARE", "RANSOMWARE",
                                       "INFOSTEALER", "LOADER", "BOTNET",
                                       "LATERAL_MOVEMENT"],
        "action":             "IOC_ADD_WATCHLIST",
        "framework_hint":     "D3-NTA",
        "confidence":         "MEDIUM",
        "evidence_strength":  "INFERRED",
        "base_priority":      "MEDIUM",
        "rationale":
            "Search other endpoints/telemetry for indicator {entity} to "
            "determine whether the incident has spread.",
    },
    {
        "id":                "ENRICH_OBSERVED_DOMAIN",
        "category":          "INVESTIGATION",
        "target_entity_kind": "domain",
        "required_evidence": ["network.domain"],
        "supported_families": ["C2", "PUA_ADWARE", "MALWARE", "UNKNOWN",
                                       "PHISHING"],
        "action":             "OSINT_ENRICH_DOMAIN",
        "framework_hint":     "D3-DNSAL",
        "confidence":         "HIGH",
        "evidence_strength":  "DIRECT",
        "base_priority":      "MEDIUM",
        "rationale":
            "Enrich domain {entity} across public OSINT reputation "
            "sources before deciding on blocking.",
    },
    # ── Round 18 · Exclusion candidates (knowledge only) ───────
    # Synthesizer emits these when the analyst may realistically be
    # asked to whitelist/exclude the sample. The Mitigation Intelligence
    # knowledge layer attaches the risk model (visibility impact,
    # security risk, safer alternative) so the analyst sees the
    # trade-off before accepting.
    {
        "id":                "EXCLUDE_APPLICATION_ALLOWLIST",
        "category":          "PREVENTION",
        "target_entity_kind": "hash",
        "required_evidence": ["file.hash"],
        "supported_families": ["PUA_ADWARE", "SUSPICIOUS_APPLICATION",
                                       "MALWARE", "LOADER", "UNKNOWN"],
        "action":             "APPLICATION_ALLOW_LIST_ADD",
        "framework_hint":     "D3-EAL",
        "confidence":         "MEDIUM",
        "evidence_strength":  "DIRECT",
        "base_priority":      "MEDIUM",
        "rationale":
            "Allow-list SHA256 {entity} — narrowest possible exclusion "
            "(single hash · Cloud IOC visibility only). Verify publisher "
            "and legitimacy before accepting.",
    },
    {
        "id":                "EXCLUDE_PROCESS",
        "category":          "PREVENTION",
        "target_entity_kind": "process",
        "required_evidence": ["process.image"],
        "supported_families": ["PUA_ADWARE", "SUSPICIOUS_APPLICATION",
                                       "MALWARE", "UNKNOWN"],
        "action":             "PROCESS_EXCLUSION_ADD",
        "framework_hint":     "D3-EAL",
        "confidence":         "LOW",
        "evidence_strength":  "INFERRED",
        "base_priority":      "MEDIUM",
        "rationale":
            "Exclude process {entity} from Behavioural Protection. "
            "High visibility cost — narrower parent→child scoping is "
            "strongly preferred.",
    },
    {
        "id":                "EXCLUDE_PATH",
        "category":          "PREVENTION",
        "target_entity_kind": "path",
        "required_evidence": ["file.path"],
        "supported_families": ["PUA_ADWARE", "SUSPICIOUS_APPLICATION",
                                       "MALWARE", "UNKNOWN"],
        "action":             "PATH_EXCLUSION_ADD",
        "framework_hint":     "D3-EAL",
        "confidence":         "LOW",
        "evidence_strength":  "INFERRED",
        "base_priority":      "MEDIUM",
        "rationale":
            "Exclude filesystem path {entity} from on-access scanning. "
            "Broad subtree exclusion — TETRA + Cloud IOC visibility "
            "lost across all files beneath the path.",
    },
    {
        "id":                "EXCLUDE_THREAT_NAME",
        "category":          "PREVENTION",
        "target_entity_kind": "threat_name",
        "required_evidence": ["threat.name"],
        "supported_families": ["PUA_ADWARE", "SUSPICIOUS_APPLICATION",
                                       "MALWARE", "LOADER", "UNKNOWN"],
        "action":             "THREAT_EXCLUSION_ADD",
        "framework_hint":     "D3-EAL",
        "confidence":         "LOW",
        "evidence_strength":  "INFERRED",
        "base_priority":      "LOW",
        "rationale":
            "Threat-name exclusion for {entity} — suppresses this "
            "detection name across ALL endpoints and future incidents. "
            "Dual approval required · hash allow-list is strongly "
            "preferred.",
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

    Round 19 · a Response-Strategy knowledge layer sits between family
    classification and this synthesizer.  For every candidate action:

        * The family activates one or more strategies
          (xdr_response_strategy).
        * A candidate is only surfaced when it appears in at least
          ONE active strategy's candidate_action_ids list.
        * Exclusion candidates are only surfaced when at least one
          active strategy sets allow_exclusions=True.
        * The emitted reco carries `strategy_id` + `objective` so the
          analyst reads the response NARRATIVE, not a flat list of
          verbs.

    Rules preserved from Round 17.5:
      * Every emitted recommendation is bound to a real observed
        entity.  No entity → no recommendation.
      * `applicability` is emitted honestly.
      * NO malware-name templates — recommendations emerge from the
        combination of Family × Strategy × Evidence.
    """
    fam = (threat_family or {}).get("family") or "UNKNOWN"
    entities = _entities_from_context(context)
    if not entities:
        return []

    # ── Round 19 · Strategy layer ─────────────────────────────
    strategy_set = _compose_strategy_set(fam)
    active_action_ids: set[str] = set(strategy_set["candidate_action_ids"])
    strategies_by_action:   dict[str, list[str]] = \
        strategy_set["provenance_by_action"]
    strategies_index = {s["id"]: s for s in strategy_set["strategies"]}
    exclusions_allowed = any(s.get("allow_exclusions")
                                       for s in strategy_set["strategies"])

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
        # Family filter (still enforced independently — a candidate
        # never surfaces when the family filter excludes it).
        if fam not in cand["supported_families"]:
            continue
        # Round 19 · Strategy filter.  A candidate must be endorsed
        # by at least one active strategy for this family.
        if cand["id"] not in active_action_ids:
            continue
        # Round 19 · Exclusion guardrail.  Exclusion candidates only
        # surface when the active strategy explicitly permits them.
        if _is_exclusion(cand["action"]) and not exclusions_allowed:
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
                                 "family match + strategy endorsed"

            # Framework rationale from active mappings.
            fw_hint = cand.get("framework_hint")
            fw_matches = [m for m in framework_maps
                                if m.get("object_id") == fw_hint]

            # Round 19 · Strategy provenance.
            strat_ids = strategies_by_action.get(cand["id"], [])
            primary_strat = strategies_index.get(strat_ids[0]) if strat_ids else None

            reco_id = f"reco-{cand['id']}-{ent.get('value')}".lower()
            reco = {
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
                "strategy": {
                    "id":         (primary_strat or {}).get("id"),
                    "objective":  (primary_strat or {}).get("objective"),
                    "description": (primary_strat or {}).get("description"),
                    "all_ids":    strat_ids,
                },
            }
            # Round 18 · attach Mitigation Intelligence risk model
            # ONLY when this candidate's action is an exclusion.
            # Ordinary mitigations return unchanged (guardrail).
            out.append(enrich_recommendation(reco))
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
