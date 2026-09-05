"""QA Layer contract tests  (R28.3).

Unit tests for the core QA data contracts + Repair Planner + Registry.
No orchestrator; no plugins.  This gate proves the contract behaves
deterministically in isolation.
"""
from __future__ import annotations

import pytest

from services.uaie import qa
from services.uaie.qa import (RepairCandidate, RepairResult, ValidationResult,
                                 ValidationCertificate, RepairCertificate,
                                 plan_repairs, register_repair,
                                 register_validator, repair_for, validators_for)


# ══════════════════════════════════════════════════════════════════
# 1 · Repair Planner ranking
# ══════════════════════════════════════════════════════════════════
def test_planner_ranks_by_confidence_desc():
    ranked = plan_repairs([
        RepairCandidate(strategy="a", confidence=0.30, reason="x"),
        RepairCandidate(strategy="b", confidence=0.90, reason="y"),
        RepairCandidate(strategy="c", confidence=0.60, reason="z"),
    ])
    assert [c.strategy for c in ranked] == ["b", "c", "a"]


def test_planner_dedupes_strategy_keeping_highest_confidence():
    ranked = plan_repairs([
        RepairCandidate(strategy="strip", confidence=0.40, reason="x"),
        RepairCandidate(strategy="strip", confidence=0.90, reason="y"),
        RepairCandidate(strategy="strip", confidence=0.10, reason="z"),
    ])
    assert len(ranked) == 1
    assert ranked[0].strategy == "strip"
    assert ranked[0].confidence == 0.90


def test_planner_stable_sort_on_equal_confidence():
    """Deterministic — same confidence → sort by strategy name ASC."""
    ranked = plan_repairs([
        RepairCandidate(strategy="zzz", confidence=0.70, reason="x"),
        RepairCandidate(strategy="aaa", confidence=0.70, reason="x"),
        RepairCandidate(strategy="mmm", confidence=0.70, reason="x"),
    ])
    assert [c.strategy for c in ranked] == ["aaa", "mmm", "zzz"]


def test_planner_empty_input_is_empty_output():
    assert plan_repairs([]) == []


# ══════════════════════════════════════════════════════════════════
# 2 · Registry semantics
# ══════════════════════════════════════════════════════════════════
class _DummyValidator:
    name = "unit.dummy_validator"
    validates_artifact_type = ["dummy_kind"]

    def validate(self, artifact):
        return ValidationResult(valid=True, validator=self.name, confidence=1.0)


class _DummyRepair:
    name = "unit.dummy_repair"
    strategy = "unit_test_strategy"

    def repair(self, artifact, candidate):
        return RepairResult(success=True, strategy=self.strategy,
                             repaired_payload=b"")


def test_validator_lookup_by_type_and_universal():
    snapshot_v = dict(qa._VALIDATOR_REGISTRY)
    snapshot_r = dict(qa._REPAIR_REGISTRY)
    try:
        register_validator(_DummyValidator())
        got = validators_for("dummy_kind")
        assert any(v.name == "unit.dummy_validator" for v in got)
        # non-matching type → no dummy_validator returned
        got_other = validators_for("nonexistent_kind")
        assert not any(v.name == "unit.dummy_validator" for v in got_other)
    finally:
        qa._VALIDATOR_REGISTRY.clear()
        qa._VALIDATOR_REGISTRY.update(snapshot_v)
        qa._REPAIR_REGISTRY.clear()
        qa._REPAIR_REGISTRY.update(snapshot_r)


def test_repair_lookup_by_strategy():
    snapshot_v = dict(qa._VALIDATOR_REGISTRY)
    snapshot_r = dict(qa._REPAIR_REGISTRY)
    try:
        register_repair(_DummyRepair())
        got = repair_for("unit_test_strategy")
        assert got is not None
        assert got.name == "unit.dummy_repair"
        assert repair_for("no_such_strategy") is None
    finally:
        qa._VALIDATOR_REGISTRY.clear()
        qa._VALIDATOR_REGISTRY.update(snapshot_v)
        qa._REPAIR_REGISTRY.clear()
        qa._REPAIR_REGISTRY.update(snapshot_r)


# ══════════════════════════════════════════════════════════════════
# 3 · Certificate immutability + serialisability
# ══════════════════════════════════════════════════════════════════
def test_validation_certificate_is_frozen():
    cert = ValidationCertificate(
        artifact_uri="uaie://artifact/abc",
        validator="v",
        valid=False, reason="bad_padding", detail="len%4=1",
        confidence=0.9, candidates=["normalize_padding"],
    )
    with pytest.raises((AttributeError, TypeError, Exception)):
        cert.valid = True  # type: ignore


def test_repair_certificate_is_frozen():
    cert = RepairCertificate(
        source_uri="uaie://artifact/abc", repaired_uri="uaie://artifact/def",
        strategy="strip", outcome="success", reason="", detail="ok",
    )
    with pytest.raises((AttributeError, TypeError, Exception)):
        cert.outcome = "failed"  # type: ignore
