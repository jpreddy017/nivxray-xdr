"""
P0 · Round 19 · Threat-Family → Response Strategy Layer
────────────────────────────────────────────────────────

**Knowledge layer only.**  Sits between Threat Family (Round 16) and
the Candidate Mitigations registry (Round 17 · `_GUIDANCE`) inside
`xdr_recommendation_synthesis.py`.

Architectural rule (LOCKED, PRD § Round 19):

    Threat family determines the RESPONSE STRATEGY.
    Evidence determines which INDIVIDUAL ACTIONS are applicable.

The strategy layer NEVER:
  * Hardcodes malware-name playbooks (no "if PCAppStore → do X").
  * Emits recommendations directly.
  * Overrides applicability, risk, framework context or the analyst
    decision.

It DOES:
  * Declare one or more Strategies per family.
  * Each strategy carries an OBJECTIVE (Cleanup / Containment /
    Credential Protection / Eradication / Recovery Verification /
    Investigation / Prevention).
  * Each strategy declares the REQUIRED_EVIDENCE_DIMS it consumes
    (process · application · persistence · file · identity · network).
  * Each strategy enumerates the CANDIDATE ACTION IDs it composes —
    referencing entries in `xdr_recommendation_synthesis._GUIDANCE`.
  * Return a set of (strategy_id, candidate_action_ids) tuples for
    the synthesizer to compose from.

Result: the earlier Round 17.5 recommendations (remove startup
persistence · uninstall observed application · terminate observed
process · block observed domain · investigate infrastructure)
emerge NATURALLY when the PUA_CLEANUP strategy fires and the
evidence supports each candidate — never from a hardcoded rule.
"""
from __future__ import annotations
from typing import Any


STRATEGY_ENGINE_ID = "nivxray::xdr::response_strategy_layer"
STRATEGY_VERSION   = "1.0.0"


# ── Objectives (locked enum) ────────────────────────────────────
CLEANUP                = "Cleanup"
CONTAINMENT            = "Containment"
CREDENTIAL_PROTECTION  = "Credential Protection"
ERADICATION            = "Eradication"
RECOVERY_VERIFICATION  = "Recovery Verification"
INVESTIGATION          = "Investigation"
PREVENTION             = "Prevention"


# ── Evidence dimensions (locked) ────────────────────────────────
EV_PROCESS       = "process"
EV_APPLICATION   = "application"
EV_PERSISTENCE   = "persistence"
EV_FILE          = "file"
EV_IDENTITY      = "identity"
EV_NETWORK       = "network"
EV_HOST          = "host"


# ── Strategy registry ───────────────────────────────────────────
#
# Every entry:
#   id                       · stable strategy identifier
#   family                   · exact family enum matched by
#                              xdr_threat_family
#   objective                · what the strategy is trying to
#                              accomplish (analyst-facing narrative)
#   required_evidence_dims   · evidence dimensions the strategy CAN
#                              consume; recommendations only surface
#                              when the corresponding entity was
#                              observed
#   candidate_action_ids     · candidate GUIDANCE ids the strategy
#                              composes (never invents)
#   framework_hint           · optional NIST-IR phase this strategy
#                              maps to
#   allow_exclusions         · whether the strategy may surface
#                              exclusion candidates (default False)
#   description              · analyst-facing one-liner

_STRATEGIES: list[dict[str, Any]] = [
    # ── PUA / PCAppStore family ─────────────────────────────
    {
        "id":                      "PUA_CLEANUP",
        "family":                  "PUA_ADWARE",
        "objective":               CLEANUP,
        "required_evidence_dims":  [EV_APPLICATION, EV_PROCESS,
                                                EV_PERSISTENCE, EV_FILE,
                                                EV_NETWORK],
        "candidate_action_ids":    [
            "UNINSTALL_APPLICATION",
            "REMOVE_STARTUP_PERSISTENCE",
            "TERMINATE_PROCESS",
            "BLOCK_OBSERVED_DOMAIN",
            "BLOCK_OBSERVED_IP",
            "SEARCH_ENVIRONMENT_FOR_INDICATOR",
            "ENRICH_OBSERVED_DOMAIN",
            "ENRICH_OBSERVED_IP",
            "COLLECT_FORENSIC_SNAPSHOT",
            # Round 18 exclusion candidates — surfaced ONLY when the
            # strategy explicitly permits (PUA is the canonical case).
            "EXCLUDE_APPLICATION_ALLOWLIST",
            "EXCLUDE_PROCESS",
            "EXCLUDE_PATH",
            "EXCLUDE_THREAT_NAME",
        ],
        "framework_hint":          {"nist_ir": "CONTAINMENT_ERADICATION_RECOVERY"},
        "allow_exclusions":        True,     # PUA is the canonical case
        "description":
            "Remove observed PUA/adware artefacts (application, "
            "persistence, associated processes) and block/enrich the "
            "distribution infrastructure. Exclusions may be considered "
            "for confirmed legitimate applications.",
    },
    # ── Suspicious application family ──────────────────────
    {
        "id":                      "SUSPICIOUS_APP_INVESTIGATION",
        "family":                  "SUSPICIOUS_APPLICATION",
        "objective":               INVESTIGATION,
        "required_evidence_dims":  [EV_APPLICATION, EV_PROCESS, EV_FILE,
                                                EV_NETWORK],
        "candidate_action_ids":    [
            "COLLECT_FORENSIC_SNAPSHOT",
            "SEARCH_ENVIRONMENT_FOR_INDICATOR",
            "ENRICH_OBSERVED_IP",
            "ENRICH_OBSERVED_DOMAIN",
            "TERMINATE_PROCESS",
            # Exclusions available for confirmed-benign apps.
            "EXCLUDE_APPLICATION_ALLOWLIST",
        ],
        "framework_hint":          {"nist_ir": "DETECTION_AND_ANALYSIS"},
        "allow_exclusions":        True,
        "description":
            "Investigate an observed suspicious application before "
            "eradication.  Preserve forensic evidence, enrich "
            "infrastructure, and search for spread.",
    },
    # ── Ransomware family ──────────────────────────────────
    {
        "id":                      "RANSOMWARE_CONTAINMENT",
        "family":                  "RANSOMWARE",
        "objective":               CONTAINMENT,
        "required_evidence_dims":  [EV_HOST, EV_PROCESS, EV_FILE,
                                                EV_NETWORK],
        "candidate_action_ids":    [
            "ISOLATE_ENDPOINT",
            "COLLECT_FORENSIC_SNAPSHOT",
            "TERMINATE_PROCESS",
            "BLOCK_OBSERVED_IP",
            "SEARCH_ENVIRONMENT_FOR_INDICATOR",
            "ADD_IOC_WATCHLIST",
        ],
        "framework_hint":          {"nist_ir": "CONTAINMENT_ERADICATION_RECOVERY"},
        "allow_exclusions":        False,
        "description":
            "Isolate affected endpoint, preserve forensic evidence, "
            "identify encryption activity, contain propagation, "
            "protect/verify recovery infrastructure.",
    },
    # ── Credential theft family ────────────────────────────
    {
        "id":                      "CREDENTIAL_PROTECTION",
        "family":                  "CREDENTIAL_THEFT",
        "objective":               CREDENTIAL_PROTECTION,
        "required_evidence_dims":  [EV_IDENTITY, EV_HOST, EV_PROCESS],
        "candidate_action_ids":    [
            "REVOKE_CREDENTIAL",
            "COLLECT_FORENSIC_SNAPSHOT",
            "ADD_IOC_WATCHLIST",
            "SEARCH_ENVIRONMENT_FOR_INDICATOR",
        ],
        "framework_hint":          {"nist_ir": "CONTAINMENT_ERADICATION_RECOVERY"},
        "allow_exclusions":        False,
        "description":
            "Identify affected identity, revoke/reset credentials "
            "only when evidence supports it, investigate authentication "
            "activity, search for credential-access artefacts.",
    },
    # ── Infostealer family ─────────────────────────────────
    {
        "id":                      "INFOSTEALER_TRIAGE",
        "family":                  "INFOSTEALER",
        "objective":               CREDENTIAL_PROTECTION,
        "required_evidence_dims":  [EV_HOST, EV_PROCESS, EV_IDENTITY,
                                                EV_FILE, EV_NETWORK],
        "candidate_action_ids":    [
            "COLLECT_FORENSIC_SNAPSHOT",
            "REVOKE_CREDENTIAL",
            "BLOCK_OBSERVED_DOMAIN",
            "BLOCK_OBSERVED_IP",
            "ADD_IOC_WATCHLIST",
            "SEARCH_ENVIRONMENT_FOR_INDICATOR",
            "TERMINATE_PROCESS",
        ],
        "framework_hint":          {"nist_ir": "DETECTION_AND_ANALYSIS"},
        "allow_exclusions":        False,
        "description":
            "Identify affected endpoint/user, preserve evidence, "
            "assess credential/session exposure, revoke when "
            "justified, hunt related indicators.",
    },
    # ── C2 family ──────────────────────────────────────────
    {
        "id":                      "C2_CONTAINMENT",
        "family":                  "C2",
        "objective":               CONTAINMENT,
        "required_evidence_dims":  [EV_NETWORK, EV_HOST, EV_PROCESS],
        "candidate_action_ids":    [
            "BLOCK_OBSERVED_IP",
            "BLOCK_OBSERVED_DOMAIN",
            "ISOLATE_ENDPOINT",
            "ADD_IOC_WATCHLIST",
            "ENRICH_OBSERVED_IP",
            "ENRICH_OBSERVED_DOMAIN",
            "SEARCH_ENVIRONMENT_FOR_INDICATOR",
        ],
        "framework_hint":          {"nist_ir": "CONTAINMENT_ERADICATION_RECOVERY"},
        "allow_exclusions":        False,      # never allow-list C2
        "description":
            "Block observed C2 infrastructure, identify communicating "
            "process/device, isolate endpoint when warranted, add "
            "observed IOC to watchlist, enrich infrastructure.",
    },
    # ── Botnet / Loader family ─────────────────────────────
    {
        "id":                      "BOTNET_CONTAINMENT",
        "family":                  "BOTNET",
        "objective":               CONTAINMENT,
        "required_evidence_dims":  [EV_NETWORK, EV_HOST, EV_PROCESS],
        "candidate_action_ids":    [
            "BLOCK_OBSERVED_IP",
            "BLOCK_OBSERVED_DOMAIN",
            "ADD_IOC_WATCHLIST",
            "ENRICH_OBSERVED_IP",
            "SEARCH_ENVIRONMENT_FOR_INDICATOR",
        ],
        "framework_hint":          {"nist_ir": "CONTAINMENT_ERADICATION_RECOVERY"},
        "allow_exclusions":        False,
        "description":
            "Contain botnet participation: block infrastructure, "
            "watchlist IOCs, hunt for other participating hosts.",
    },
    {
        "id":                      "LOADER_TRIAGE",
        "family":                  "LOADER",
        "objective":               INVESTIGATION,
        "required_evidence_dims":  [EV_HOST, EV_PROCESS, EV_FILE,
                                                EV_NETWORK],
        "candidate_action_ids":    [
            "COLLECT_FORENSIC_SNAPSHOT",
            "TERMINATE_PROCESS",
            "BLOCK_OBSERVED_IP",
            "BLOCK_OBSERVED_DOMAIN",
            "SEARCH_ENVIRONMENT_FOR_INDICATOR",
            "ADD_IOC_WATCHLIST",
        ],
        "framework_hint":          {"nist_ir": "DETECTION_AND_ANALYSIS"},
        "allow_exclusions":        False,
        "description":
            "Loader / dropper triage: preserve evidence, contain "
            "further payload retrieval, hunt for secondary stages.",
    },
    # ── Persistence family ─────────────────────────────────
    {
        "id":                      "PERSISTENCE_ERADICATION",
        "family":                  "PERSISTENCE",
        "objective":               ERADICATION,
        "required_evidence_dims":  [EV_PERSISTENCE, EV_PROCESS, EV_HOST,
                                                EV_FILE],
        "candidate_action_ids":    [
            "REMOVE_STARTUP_PERSISTENCE",
            "COLLECT_FORENSIC_SNAPSHOT",
            "TERMINATE_PROCESS",
            "SEARCH_ENVIRONMENT_FOR_INDICATOR",
        ],
        "framework_hint":          {"nist_ir": "CONTAINMENT_ERADICATION_RECOVERY"},
        "allow_exclusions":        False,
        "description":
            "Remove observed persistence artefacts and hunt for "
            "similar entries across the estate.",
    },
    # ── Lateral movement family ────────────────────────────
    {
        "id":                      "LATERAL_MOVEMENT_CONTAINMENT",
        "family":                  "LATERAL_MOVEMENT",
        "objective":               CONTAINMENT,
        "required_evidence_dims":  [EV_IDENTITY, EV_HOST, EV_NETWORK],
        "candidate_action_ids":    [
            "ISOLATE_ENDPOINT",
            "REVOKE_CREDENTIAL",
            "COLLECT_FORENSIC_SNAPSHOT",
            "ADD_IOC_WATCHLIST",
            "SEARCH_ENVIRONMENT_FOR_INDICATOR",
            "ENRICH_OBSERVED_IP",
        ],
        "framework_hint":          {"nist_ir": "CONTAINMENT_ERADICATION_RECOVERY"},
        "allow_exclusions":        False,
        "description":
            "Identify source/destination entities, investigate "
            "authentication evidence, contain affected endpoints/"
            "accounts, hunt for additional movement.",
    },
    # ── Phishing family ────────────────────────────────────
    {
        "id":                      "PHISHING_TRIAGE",
        "family":                  "PHISHING",
        "objective":               INVESTIGATION,
        "required_evidence_dims":  [EV_IDENTITY, EV_NETWORK, EV_FILE],
        "candidate_action_ids":    [
            "BLOCK_OBSERVED_DOMAIN",
            "ADD_IOC_WATCHLIST",
            "ENRICH_OBSERVED_DOMAIN",
            "SEARCH_ENVIRONMENT_FOR_INDICATOR",
            "COLLECT_FORENSIC_SNAPSHOT",
        ],
        "framework_hint":          {"nist_ir": "DETECTION_AND_ANALYSIS"},
        "allow_exclusions":        False,
        "description":
            "Block observed phishing infrastructure, enrich "
            "reputation, hunt for other recipients, preserve "
            "artefacts.",
    },
    # ── Worm family ────────────────────────────────────────
    {
        "id":                      "WORM_CONTAINMENT",
        "family":                  "WORM",
        "objective":               CONTAINMENT,
        "required_evidence_dims":  [EV_HOST, EV_NETWORK, EV_PROCESS,
                                                EV_FILE],
        "candidate_action_ids":    [
            "ISOLATE_ENDPOINT",
            "BLOCK_OBSERVED_IP",
            "BLOCK_OBSERVED_DOMAIN",
            "COLLECT_FORENSIC_SNAPSHOT",
            "TERMINATE_PROCESS",
            "SEARCH_ENVIRONMENT_FOR_INDICATOR",
        ],
        "framework_hint":          {"nist_ir": "CONTAINMENT_ERADICATION_RECOVERY"},
        "allow_exclusions":        False,
        "description":
            "Contain worm propagation, block infrastructure, isolate "
            "affected hosts, hunt for spread.",
    },
    # ── Generic malware family ─────────────────────────────
    {
        "id":                      "MALWARE_ERADICATION",
        "family":                  "MALWARE",
        "objective":               ERADICATION,
        "required_evidence_dims":  [EV_HOST, EV_PROCESS, EV_FILE,
                                                EV_NETWORK],
        "candidate_action_ids":    [
            "COLLECT_FORENSIC_SNAPSHOT",
            "ISOLATE_ENDPOINT",
            "TERMINATE_PROCESS",
            "BLOCK_OBSERVED_IP",
            "BLOCK_OBSERVED_DOMAIN",
            "BLOCK_OBSERVED_HASH",
            "ADD_IOC_WATCHLIST",
            "SEARCH_ENVIRONMENT_FOR_INDICATOR",
        ],
        "framework_hint":          {"nist_ir": "CONTAINMENT_ERADICATION_RECOVERY"},
        "allow_exclusions":        False,
        "description":
            "Preserve forensics, contain the affected endpoint, "
            "eradicate malicious processes/files, spread IOCs.",
    },
    # ── UNKNOWN family — investigation only ────────────────
    {
        "id":                      "UNKNOWN_INVESTIGATION",
        "family":                  "UNKNOWN",
        "objective":               INVESTIGATION,
        "required_evidence_dims":  [EV_NETWORK, EV_HOST, EV_FILE,
                                                EV_PROCESS, EV_IDENTITY],
        "candidate_action_ids":    [
            "COLLECT_FORENSIC_SNAPSHOT",
            "ENRICH_OBSERVED_IP",
            "ENRICH_OBSERVED_DOMAIN",
            "SEARCH_ENVIRONMENT_FOR_INDICATOR",
            "ADD_IOC_WATCHLIST",
        ],
        "framework_hint":          {"nist_ir": "DETECTION_AND_ANALYSIS"},
        "allow_exclusions":        False,
        "description":
            "Investigate before eradicating — the family has not been "
            "confirmed and destructive actions are not yet justified.",
    },
]


# ── Public API ──────────────────────────────────────────────────

def strategies_for(family: str | None) -> list[dict]:
    """Return every strategy the given family activates.  Never
    fabricates — an unknown family returns the UNKNOWN_INVESTIGATION
    strategy (or an empty list if the caller filters it out)."""
    fam = family or "UNKNOWN"
    out = [dict(s) for s in _STRATEGIES if s["family"] == fam]
    return out


def all_strategies() -> list[dict]:
    """Introspection helper — returns every registered strategy."""
    return [dict(s) for s in _STRATEGIES]


def registry_summary() -> dict:
    return {
        "engine_id":      STRATEGY_ENGINE_ID,
        "engine_version": STRATEGY_VERSION,
        "role":           "KNOWLEDGE_LAYER",
        "not_an_engine":  True,
        "total":          len(_STRATEGIES),
        "objectives":     sorted({s["objective"] for s in _STRATEGIES}),
        "families":       sorted({s["family"] for s in _STRATEGIES}),
        "rule":
            "Threat family determines the response strategy; evidence "
            "determines which individual actions are applicable. This "
            "layer never emits recommendations directly, never "
            "overrides applicability/risk/framework/analyst decision, "
            "and never hardcodes malware-name playbooks.",
    }


def compose_candidate_set(family: str | None) -> dict[str, Any]:
    """
    Return the union of candidate action_ids activated by the strategies
    for a family, plus per-candidate strategy provenance so the
    synthesizer can label each emitted recommendation with the
    strategy that surfaced it.
    """
    strategies = strategies_for(family)
    by_candidate: dict[str, list[str]] = {}
    for s in strategies:
        for cid in s["candidate_action_ids"]:
            by_candidate.setdefault(cid, []).append(s["id"])
    return {
        "family":               family,
        "strategies":           strategies,
        "candidate_action_ids": list(by_candidate.keys()),
        "provenance_by_action": by_candidate,
    }
