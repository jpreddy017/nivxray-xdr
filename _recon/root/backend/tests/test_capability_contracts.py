"""
P0.2c · Implementation Capability Contracts — pytest gate.

Invariants under test:
  1. Every EngineRole has a defined contract default.
  2. `execution.detection` is False for every role except
     DETECTION_ENGINE.
  3. build_contract() never mutates the module role.
  4. build_contract() produces contract_status = CONTRACT_DECLARED.
  5. build_contract() never sets execution.detection = True unless
     the engine's role is genuinely DETECTION_ENGINE (which is 0
     in production today).
"""
from __future__ import annotations
import pytest

from detection_content.capability_contract import (
    ContractStatus,
    build_contract,
    default_contract_for_role,
    _ROLE_DEFAULTS,
)
from detection_content.engine_registry import EngineRole


def test_every_role_has_default_contract():
    missing = [r.value for r in EngineRole
                       if r.value not in _ROLE_DEFAULTS]
    assert not missing, (
        "Every EngineRole must have a declared default contract. "
        f"Missing: {missing}"
    )


def test_detection_false_by_default_for_every_non_detection_role():
    for role in EngineRole:
        if role is EngineRole.DETECTION_ENGINE:
            continue
        d = default_contract_for_role(role.value)
        assert d["execution"]["detection"] is False, (
            f"Role {role.value} must NOT default to execution.detection=True. "
            "Detection capability requires the P0.2e execution harness "
            "to prove a real detection path."
        )


def test_detection_engine_default_permits_detection():
    d = default_contract_for_role("DETECTION_ENGINE")
    assert d["execution"]["detection"] is True


def test_build_contract_shape_and_status():
    doc = {
        "engine_id": "nivxray::services::verdict_engine",
        "module":    "services.verdict.verdict_engine",
        "role":      EngineRole.VERDICT_ENGINE.value,
        "path":      "services/verdict/verdict_engine.py",
        "scope":     "services",
    }
    c = build_contract(doc)
    assert c["engine_id"] == doc["engine_id"]
    assert c["classification"] == EngineRole.VERDICT_ENGINE.value
    assert c["contract_status"] == ContractStatus.CONTRACT_DECLARED.value
    assert c["execution"]["detection"] is False
    assert c["execution"]["deterministic"] is True
    assert "canonical.evidence[]" in c["consumes"]
    assert "verdict.record" in c["produces"]
    assert c["provenance"]["engine_source"] == doc["path"]


def test_analyzer_never_gets_detection_true():
    doc = {"engine_id": "e", "module": "m", "role": "ANALYZER",
              "path": "p", "scope": "s"}
    assert build_contract(doc)["execution"]["detection"] is False


def test_decoder_never_gets_detection_true():
    doc = {"engine_id": "e", "module": "m", "role": "DECODER",
              "path": "p", "scope": "s"}
    assert build_contract(doc)["execution"]["detection"] is False


def test_unknown_role_falls_back_to_other_shape():
    d = default_contract_for_role("__NOT_A_REAL_ROLE__")
    assert d["execution"]["detection"] is False
    assert d["consumes"] == []
    assert d["produces"] == []


def test_contract_status_ladder_is_declared_not_verified():
    """
    Ladder is one-way: DISCOVERED → CONTRACT_PENDING →
    CONTRACT_DECLARED → RUNTIME_VERIFIED → EXECUTION_VERIFIED.
    build_contract() lands at CONTRACT_DECLARED — never higher.
    """
    doc = {"engine_id": "e", "module": "m", "role": "ANALYZER",
              "path": "p", "scope": "s"}
    c = build_contract(doc)
    assert c["contract_status"] not in {
        ContractStatus.RUNTIME_VERIFIED.value,
        ContractStatus.EXECUTION_VERIFIED.value,
    }, "build_contract must not auto-promote to verified statuses."
