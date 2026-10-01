"""
NivXRay Detection Content Supply Chain · canonical model.

Introduces the authoritative `detection_content` collection that
holds every piece of detection content from every source
(NIVXRAY_NATIVE, SIGMAHQ, SPLUNK, ELASTIC, COMMUNITY, CUSTOM)
under one lifecycle state machine.

This module intentionally does NOT touch any existing collection
(`xdr_detection_rules`, `xdr_correlation_rules`, etc.).  Those stay
authoritative for their own domains.  `detection_content` is the
new UNION model that answers the P0 supply-chain question:

    "Across every source we ingest, what content exists, in what
     lifecycle state, bound to which engine, ready to execute?"

Lifecycle states are ADDITIVE — a rule can accumulate multiple
milestones (e.g. VALID + SUPPORTED + ENGINE_BOUND + TEST_PASS)
before it ever reaches ENABLED/ACTIVE.  No milestone is set
speculatively.  ACTIVE ≠ "row exists".
"""
from __future__ import annotations

from enum import Enum
from typing import Optional


COLLECTION = "detection_content"


class ContentSource(str, Enum):
    NIVXRAY_NATIVE = "NIVXRAY_NATIVE"
    SIGMAHQ        = "SIGMAHQ"
    SPLUNK         = "SPLUNK"
    ELASTIC        = "ELASTIC"
    MICROSOFT      = "MICROSOFT"
    COMMUNITY      = "COMMUNITY"
    CUSTOM         = "CUSTOM"


class LifecycleState(str, Enum):
    # Discovery
    DISCOVERED             = "DISCOVERED"
    PARSED                 = "PARSED"
    # Validation
    VALID                  = "VALID"
    INVALID                = "INVALID"
    # Support / capability
    SUPPORTED              = "SUPPORTED"
    UNSUPPORTED            = "UNSUPPORTED"
    # Missing prerequisites
    DATA_SOURCE_MISSING    = "DATA_SOURCE_MISSING"
    FIELD_MAPPING_MISSING  = "FIELD_MAPPING_MISSING"
    ENGINE_UNBOUND         = "ENGINE_UNBOUND"
    # Legal
    LICENSE_RESTRICTED     = "LICENSE_RESTRICTED"
    # Testing
    TEST_REQUIRED          = "TEST_REQUIRED"
    TEST_PASSED            = "TEST_PASSED"
    TEST_FAILED            = "TEST_FAILED"
    # Terminal
    EXECUTION_READY        = "EXECUTION_READY"
    ENABLED                = "ENABLED"
    ACTIVE                 = "ACTIVE"
    DISABLED               = "DISABLED"
    DEPRECATED             = "DEPRECATED"


# Milestones an item MUST have accumulated before it can be ACTIVE.
# Trust guardrail: no piece of code should promote a document to
# ACTIVE unless all of these are present in `state_history`.
REQUIRED_FOR_ACTIVE = {
    LifecycleState.PARSED,
    LifecycleState.VALID,
    LifecycleState.SUPPORTED,
    LifecycleState.EXECUTION_READY,
    LifecycleState.ENABLED,
}


def can_promote_to_active(state_history: list[str]) -> tuple[bool, list[str]]:
    """
    Return (allowed, missing_milestones).  A caller MUST use this
    before writing ACTIVE — never set ACTIVE on a bare document.
    """
    have = set(state_history or [])
    need = {s.value for s in REQUIRED_FOR_ACTIVE}
    missing = sorted(need - have)
    return (len(missing) == 0, missing)


def new_content_doc(
    *,
    source: ContentSource,
    source_rule_id: str,
    title: str,
    rule_type: str,
    source_repository: Optional[str] = None,
    source_version: Optional[str] = None,
    license: Optional[str] = None,
    author: Optional[str] = None,
    description: Optional[str] = None,
    raw_body: Optional[str] = None,
    canonical_content_hash: Optional[str] = None,
) -> dict:
    """
    Build a fresh canonical document at the DISCOVERED milestone.
    Later stages append to `state_history` — never overwrite it.
    """
    return {
        "content_id":               f"{source.value}::{source_rule_id}",
        "source":                   source.value,
        "source_rule_id":           source_rule_id,
        "source_repository":        source_repository,
        "source_version":           source_version,
        "source_commit":            None,
        "source_hash":              canonical_content_hash,

        "title":                    title,
        "description":              description,
        "rule_type":                rule_type,
        "format":                   "sigma" if source is ContentSource.SIGMAHQ else rule_type,
        "license":                  license,
        "author":                   author,

        # Detection binding
        "data_sources":             [],
        "required_fields":          [],
        "field_mappings":           {},
        "log_sources":              [],
        "platform":                 [],
        "severity":                 None,
        "risk":                     None,
        "tags":                     [],
        "mitre_attack":             [],

        # Engine binding
        "engine_binding":           None,
        "engine_capabilities":      [],
        "engine_bound_at":          None,

        # Lifecycle
        "state_history":            [LifecycleState.DISCOVERED.value],
        "validation_state":         None,
        "test_state":               None,
        "execution_state":          None,
        "enabled":                  False,
        "active":                   False,
        "state_reason":             None,

        # Raw source
        "raw_body":                 raw_body,

        # Provenance
        "provenance": {
            "discovered_at":        None,
            "parsed_at":            None,
            "validated_at":         None,
            "engine_bound_at":      None,
            "enabled_at":           None,
        },
    }
