"""
P0.2c · Implementation Capability Contracts
──────────────────────────────────────────

Every one of the 329 discovered NivXRay implementations receives a
machine-readable contract describing:

    consumes[]         — canonical evidence types the impl reads
    produces[]         — canonical evidence types / verdicts the impl emits
    execution.detection — TRUE only when the impl genuinely executes
                          detection logic against evidence (never TRUE
                          by default, never assigned by role name alone)
    execution.deterministic
    execution.side_effect_free
    requirements.evidence_types[]  — pre-conditions
    contract_status    — DISCOVERED · CONTRACT_PENDING · CONTRACT_DECLARED
                         · RUNTIME_VERIFIED · EXECUTION_VERIFIED

The status ladder is one-way and requires an actual verification
event to progress.  Nothing here promotes a module to
`DETECTION_ENGINE` — that classification lives in the Engine
Registry and remains 0 until the P0.2e Detection Execution Harness
proves a real detection path end-to-end.
"""
from __future__ import annotations
from enum import Enum
from typing import Any


COLLECTION = "xdr_capability_contracts"


class ContractStatus(str, Enum):
    DISCOVERED         = "DISCOVERED"
    CONTRACT_PENDING   = "CONTRACT_PENDING"
    CONTRACT_DECLARED  = "CONTRACT_DECLARED"
    RUNTIME_VERIFIED   = "RUNTIME_VERIFIED"
    EXECUTION_VERIFIED = "EXECUTION_VERIFIED"


# ── Role → default contract shape ───────────────────────────────
#
# These defaults are DECLARED, not verified.  Every field can be
# refined by the P0.2c/e verification passes, but the initial values
# are honest and role-truthful.  Detection is FALSE for every role
# by default — the sole way it becomes TRUE is via the Detection
# Execution Harness (P0.2e).
#
# Format:  role_key: {"consumes": [...], "produces": [...],
#                       "detection": bool, "deterministic": bool,
#                       "side_effect_free": bool,
#                       "evidence_types": [...]}
#
_ROLE_DEFAULTS: dict[str, dict[str, Any]] = {
    "ANALYZER": {
        "consumes": ["canonical.artifact", "canonical.evidence"],
        "produces": ["observation", "behavior.observation",
                      "attack.technique"],
        "detection": False,
        "deterministic": True,
        "side_effect_free": True,
        "evidence_types": ["artifact"],
    },
    "PARSER": {
        "consumes": ["raw.artifact"],
        "produces": ["canonical.evidence"],
        "detection": False,
        "deterministic": True,
        "side_effect_free": True,
        "evidence_types": ["raw_bytes"],
    },
    "NORMALIZER": {
        "consumes": ["parsed.evidence"],
        "produces": ["canonical.evidence"],
        "detection": False,
        "deterministic": True,
        "side_effect_free": True,
        "evidence_types": ["parsed_event"],
    },
    "DECODER": {
        "consumes": ["encoded.artifact", "command.line"],
        "produces": ["decoded.artifact", "canonical.evidence"],
        "detection": False,
        "deterministic": True,
        "side_effect_free": True,
        "evidence_types": ["command_line", "encoded_payload"],
    },
    "INTERPRETER": {
        "consumes": ["command.line", "script.artifact"],
        "produces": ["semantic.artifact", "canonical.evidence"],
        "detection": False,
        "deterministic": True,
        "side_effect_free": True,
        "evidence_types": ["script"],
    },
    "CORRELATION_ENGINE": {
        "consumes": ["canonical.evidence[]"],
        "produces": ["correlation.finding", "attack.chain"],
        "detection": False,
        "deterministic": True,
        "side_effect_free": True,
        "evidence_types": ["event_stream"],
    },
    "VERDICT_ENGINE": {
        "consumes": ["canonical.evidence[]", "correlation.finding[]"],
        "produces": ["verdict.record"],
        "detection": False,
        "deterministic": True,
        "side_effect_free": True,
        "evidence_types": ["evidence_bundle"],
    },
    "EVIDENCE_ENGINE": {
        "consumes": ["raw.artifact", "parsed.evidence"],
        "produces": ["canonical.evidence"],
        "detection": False,
        "deterministic": True,
        "side_effect_free": True,
        "evidence_types": ["raw_bytes"],
    },
    "GRAPH_ENGINE": {
        "consumes": ["canonical.evidence[]", "correlation.finding[]"],
        "produces": ["graph.node", "graph.edge", "attack.chain"],
        "detection": False,
        "deterministic": True,
        "side_effect_free": True,
        "evidence_types": ["evidence_bundle"],
    },
    "INTELLIGENCE_ENGINE": {
        "consumes": ["canonical.evidence", "external.feed"],
        "produces": ["intel.enrichment", "ioc.record",
                      "attack.technique"],
        "detection": False,
        "deterministic": True,
        "side_effect_free": True,
        "evidence_types": ["indicator"],
    },
    "ORCHESTRATOR": {
        "consumes": ["orchestration.request"],
        "produces": ["orchestration.result"],
        "detection": False,
        "deterministic": False,
        "side_effect_free": False,
        "evidence_types": [],
    },
    "PLANNER": {
        "consumes": ["planning.request"],
        "produces": ["planning.result"],
        "detection": False,
        "deterministic": True,
        "side_effect_free": True,
        "evidence_types": [],
    },
    "PROTOCOL": {
        "consumes": [],
        "produces": [],
        "detection": False,
        "deterministic": True,
        "side_effect_free": True,
        "evidence_types": [],
    },
    "UTILITY": {
        "consumes": [],
        "produces": [],
        "detection": False,
        "deterministic": True,
        "side_effect_free": True,
        "evidence_types": [],
    },
    "LIBRARY": {
        "consumes": [],
        "produces": [],
        "detection": False,
        "deterministic": True,
        "side_effect_free": True,
        "evidence_types": [],
    },
    "OTHER": {
        # Honest unknown — declared without pretending to know.
        "consumes": [],
        "produces": [],
        "detection": False,
        "deterministic": True,
        "side_effect_free": True,
        "evidence_types": [],
    },
    # NEVER used automatically.  Only set when P0.2e proves it.
    "DETECTION_ENGINE": {
        "consumes": ["canonical.evidence"],
        "produces": ["detection.finding"],
        "detection": True,
        "deterministic": True,
        "side_effect_free": True,
        "evidence_types": ["evidence_bundle"],
    },
}


def default_contract_for_role(role: str) -> dict[str, Any]:
    """
    Return a copy of the DECLARED contract defaults for the role.
    Missing roles fall back to OTHER (honest unknown).
    """
    d = _ROLE_DEFAULTS.get(role) or _ROLE_DEFAULTS["OTHER"]
    return {
        "consumes":  list(d["consumes"]),
        "produces":  list(d["produces"]),
        "execution": {
            "detection":         d["detection"],
            "deterministic":     d["deterministic"],
            "side_effect_free":  d["side_effect_free"],
        },
        "requirements": {
            "evidence_types": list(d["evidence_types"]),
        },
    }


def build_contract(engine_doc: dict) -> dict:
    """
    Build one CONTRACT_DECLARED record for a discovered engine.

    Guarantees (enforced by the P0.2c test-suite):
      • contract_status = CONTRACT_DECLARED
      • execution.detection preserves the role default — never
        auto-promoted to True.
      • provenance references the engine registry.
    """
    role = engine_doc.get("role", "OTHER")
    body = default_contract_for_role(role)
    return {
        "engine_id":        engine_doc["engine_id"],
        "implementation":   engine_doc.get("module"),
        "classification":   role,
        **body,
        "contract_status":  ContractStatus.CONTRACT_DECLARED.value,
        "status_history":   [ContractStatus.CONTRACT_DECLARED.value],
        "provenance": {
            "declared_by":   "detection_content.capability_contract",
            "engine_source": engine_doc.get("path"),
            "engine_scope":  engine_doc.get("scope"),
        },
    }
