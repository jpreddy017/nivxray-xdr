"""End-to-end QA-Layer integration tests  (R28.3).

These tests exercise the full loop:

    root artifact → capability → child artifact → QA validator →
    (invalid) → repair planner → repair capability → re-validation →
    (valid) → enqueued as REPAIRED  OR  (all fail) → UNREACHABLE

For each scenario we assert on:
    · orchestrator produces the right child artifact type
    · validation certificates + repair certificates are recorded
    · lifecycle state transitions are visible in ``result.states``
    · UNREACHABLE artifacts still surface as ``repair_failed`` evidence
"""
from __future__ import annotations

from services.uaie import qa
from services.uaie.artifact   import make_artifact
from services.uaie.capability import Capability, CapabilityResult, register as register_capability, clear as clear_caps
from services.uaie.orchestrator import Orchestrator
from services.uaie.qa import (RepairCandidate, RepairResult, ValidationResult,
                                 STATE_REPAIRED, STATE_UNREACHABLE, STATE_VALIDATED,
                                 register_repair, register_validator)
from services.uaie.recognizer import CERTAIN, Reason, Recognition


# ── Test scaffolding ────────────────────────────────────────────────
class _EmitChildRecognizer:
    """Recognizer that always claims the artifact as type
    ``needs_qa``.  Used to steer the orchestrator into invoking a
    single test capability without pulling in the whole plugin
    registry."""
    name = "test.emit_recognizer"

    def recognize(self, artifact):
        return [Recognition(artifact_type="needs_qa", confidence=CERTAIN,
                             reasons=[Reason("test", 1.0)],
                             recognizer=self.name)]


class _EmitChildCapability:
    """Emits ONE child artifact of a configurable type with a
    configurable payload — pure test scaffolding."""
    def __init__(self, child_type: str, child_payload: bytes,
                    name: str = "test.emit_capability") -> None:
        self.name = name
        self.requires_artifact_type = ["needs_qa"]
        self.requires_evidence      = []
        self._child_type = child_type
        self._child_payload = child_payload

    def execute(self, artifact) -> CapabilityResult:
        child = make_artifact(
            self._child_payload, self._child_type,
            parent_uri=artifact.uri, depth=artifact.depth + 1,
            discovered_by=self.name,
        )
        return CapabilityResult(evidence=[], child_artifacts=[child])


# ── State snapshotting so tests never leak into each other ─────────
def _snapshot_registries():
    return (
        dict(qa._VALIDATOR_REGISTRY),
        dict(qa._REPAIR_REGISTRY),
    )


def _restore_registries(snap):
    v, r = snap
    qa._VALIDATOR_REGISTRY.clear()
    qa._VALIDATOR_REGISTRY.update(v)
    qa._REPAIR_REGISTRY.clear()
    qa._REPAIR_REGISTRY.update(r)


# ══════════════════════════════════════════════════════════════════
# 1 · child validates cleanly → normal enqueue
# ══════════════════════════════════════════════════════════════════
def test_valid_child_flows_through_qa_and_is_enqueued(monkeypatch):
    snap = _snapshot_registries()
    from services.uaie import capability as cap_mod
    caps_snap = dict(cap_mod._REGISTRY)
    try:
        cap_mod._REGISTRY.clear()
        register_capability(_EmitChildCapability("clean_type", b"hello world"))

        class _AllGood:
            name = "test.validator.all_good"
            validates_artifact_type = ["clean_type"]
            def validate(self, artifact):
                return ValidationResult(valid=True, validator=self.name,
                                          confidence=0.99, detail="ok")

        register_validator(_AllGood())

        orch = Orchestrator(recognizers=[_EmitChildRecognizer()],
                             max_artifacts=8, max_depth=4)
        r = orch.run(b"root", root_type="unknown")

        # child must be present in artifacts + validated in states
        clean_uris = [u for u, a in r.artifacts.items() if a.artifact_type == "clean_type"]
        assert len(clean_uris) == 1
        assert r.states[clean_uris[0]] == STATE_VALIDATED
        # one validation certificate, no repair certificate
        assert len(r.validation_certificates) == 1
        assert r.validation_certificates[0].valid is True
        assert r.repair_certificates == []
    finally:
        cap_mod._REGISTRY.clear()
        cap_mod._REGISTRY.update(caps_snap)
        _restore_registries(snap)


# ══════════════════════════════════════════════════════════════════
# 2 · child fails validation, repair succeeds → REPAIRED + enqueued
# ══════════════════════════════════════════════════════════════════
def test_invalid_child_gets_repaired_and_reenqueued():
    snap = _snapshot_registries()
    from services.uaie import capability as cap_mod
    caps_snap = dict(cap_mod._REGISTRY)
    try:
        cap_mod._REGISTRY.clear()
        register_capability(_EmitChildCapability("dirty_kind", b"HELLO!!"))

        class _RejectUpper:
            name = "test.validator.reject_upper"
            validates_artifact_type = ["dirty_kind"]
            def validate(self, artifact):
                text = artifact.payload.decode("utf-8", errors="ignore")
                if text.upper() == text and any(c.isalpha() for c in text):
                    return ValidationResult(
                        valid=False, validator=self.name, confidence=0.9,
                        reason="uppercase", detail="artifact is SHOUTY",
                        repair_candidates=[RepairCandidate(
                            strategy="lowercase", confidence=0.95,
                            reason="uppercase", detail="just lowercase it",
                        )],
                    )
                return ValidationResult(valid=True, validator=self.name,
                                          confidence=0.99)

        class _LowerRepair:
            name = "test.repair.lowercase"
            strategy = "lowercase"
            def repair(self, artifact, candidate):
                cleaned = artifact.payload.decode("utf-8").lower().encode("utf-8")
                return RepairResult(success=True, strategy=self.strategy,
                                      repaired_payload=cleaned,
                                      detail="lowered")

        register_validator(_RejectUpper())
        register_repair(_LowerRepair())

        orch = Orchestrator(recognizers=[_EmitChildRecognizer()],
                             max_artifacts=8, max_depth=4)
        r = orch.run(b"root", root_type="unknown")

        # We should have BOTH: the original dirty child (state=REPAIR_PENDING
        # or absent) AND the repaired child (state=VALIDATED).
        dirty  = [u for u, a in r.artifacts.items()
                    if a.payload == b"HELLO!!" and a.artifact_type == "dirty_kind"]
        clean  = [u for u, a in r.artifacts.items()
                    if a.payload == b"hello!!" and a.artifact_type == "dirty_kind"]
        assert len(dirty) == 1 and len(clean) == 1
        assert r.states[dirty[0]] == STATE_REPAIRED
        assert r.states[clean[0]] == STATE_VALIDATED
        # Certificates
        assert any(c.outcome == "success" and c.strategy == "lowercase"
                     for c in r.repair_certificates)
        # Ledger contains repair_success action
        assert any(e.action == "repair_success"
                     for e in r.ledger.snapshot() and r.ledger)
    finally:
        cap_mod._REGISTRY.clear()
        cap_mod._REGISTRY.update(caps_snap)
        _restore_registries(snap)


# ══════════════════════════════════════════════════════════════════
# 3 · child fails validation, no strategies → UNREACHABLE + evidence
# ══════════════════════════════════════════════════════════════════
def test_invalid_child_with_no_repair_becomes_unreachable():
    snap = _snapshot_registries()
    from services.uaie import capability as cap_mod
    caps_snap = dict(cap_mod._REGISTRY)
    try:
        cap_mod._REGISTRY.clear()
        register_capability(_EmitChildCapability("bad_kind", b"\x00" * 32))

        class _AlwaysReject:
            name = "test.validator.always_reject"
            validates_artifact_type = ["bad_kind"]
            def validate(self, artifact):
                return ValidationResult(
                    valid=False, validator=self.name, confidence=0.99,
                    reason="unreachable_by_design",
                    detail="test scenario always rejects",
                    repair_candidates=[],  # NO repairs proposed
                )

        register_validator(_AlwaysReject())

        orch = Orchestrator(recognizers=[_EmitChildRecognizer()],
                             max_artifacts=8, max_depth=4)
        r = orch.run(b"root", root_type="unknown")

        bad = [u for u, a in r.artifacts.items() if a.artifact_type == "bad_kind"]
        assert len(bad) == 1
        assert r.states[bad[0]] == STATE_UNREACHABLE
        # An evidence record MUST be emitted so the analyst sees the failure
        rf = [e for e in r.evidence if e.kind == "repair_failed"]
        assert len(rf) == 1
        assert rf[0].value["reason"] == "no_strategies_left"
        assert rf[0].value["failure_codes"] == ["unreachable_by_design"]
    finally:
        cap_mod._REGISTRY.clear()
        cap_mod._REGISTRY.update(caps_snap)
        _restore_registries(snap)


# ══════════════════════════════════════════════════════════════════
# 4 · repair proposed but no capability registered → next strategy
# ══════════════════════════════════════════════════════════════════
def test_missing_repair_capability_falls_through_to_next_strategy():
    snap = _snapshot_registries()
    from services.uaie import capability as cap_mod
    caps_snap = dict(cap_mod._REGISTRY)
    try:
        cap_mod._REGISTRY.clear()
        register_capability(_EmitChildCapability("fallthru_kind", b"upper"))

        class _V:
            name = "test.validator.two_strategies"
            validates_artifact_type = ["fallthru_kind"]
            def validate(self, artifact):
                text = artifact.payload.decode("utf-8", errors="ignore")
                if text != text.upper() and text != text.lower():
                    return ValidationResult(valid=True, validator=self.name,
                                              confidence=0.9)
                if text == text.lower() and any(c.isalpha() for c in text):
                    return ValidationResult(valid=True, validator=self.name,
                                              confidence=0.9)
                return ValidationResult(
                    valid=False, validator=self.name, confidence=0.9,
                    reason="uppercase", detail="shouty",
                    repair_candidates=[
                        RepairCandidate(strategy="nonexistent_strategy",
                                          confidence=0.99, reason="uppercase"),
                        RepairCandidate(strategy="lowercase",
                                          confidence=0.50, reason="uppercase"),
                    ],
                )

        class _LowerRepair:
            name = "test.repair.lowercase"
            strategy = "lowercase"
            def repair(self, artifact, candidate):
                return RepairResult(success=True, strategy=self.strategy,
                                      repaired_payload=artifact.payload.lower())

        register_validator(_V())
        register_repair(_LowerRepair())

        orch = Orchestrator(recognizers=[_EmitChildRecognizer()],
                             max_artifacts=8, max_depth=4)
        # NOTE: input already lowercase → validator returns valid=True
        # So we need to send uppercase.  Rebuild capability.
        cap_mod._REGISTRY.clear()
        register_capability(_EmitChildCapability("fallthru_kind", b"HELLO"))
        r = orch.run(b"root", root_type="unknown")

        # First strategy has no capability → fail; second strategy runs.
        certs_ok = [c for c in r.repair_certificates
                     if c.outcome == "success" and c.strategy == "lowercase"]
        certs_missing = [c for c in r.repair_certificates
                           if c.outcome == "failed"
                           and c.strategy == "nonexistent_strategy"
                           and c.reason == "no_repair_capability"]
        assert len(certs_missing) == 1
        assert len(certs_ok) == 1
    finally:
        cap_mod._REGISTRY.clear()
        cap_mod._REGISTRY.update(caps_snap)
        _restore_registries(snap)


# ══════════════════════════════════════════════════════════════════
# 5 · Determinism — same input runs the same repair path twice
# ══════════════════════════════════════════════════════════════════
def test_qa_layer_is_deterministic():
    snap = _snapshot_registries()
    from services.uaie import capability as cap_mod
    caps_snap = dict(cap_mod._REGISTRY)
    try:
        cap_mod._REGISTRY.clear()
        register_capability(_EmitChildCapability("det_kind", b"UPPER"))

        class _V:
            name = "det.v"
            validates_artifact_type = ["det_kind"]
            def validate(self, artifact):
                text = artifact.payload.decode("utf-8", errors="ignore")
                if text == text.lower() and any(c.isalpha() for c in text):
                    return ValidationResult(valid=True, validator=self.name,
                                              confidence=0.9)
                return ValidationResult(
                    valid=False, validator=self.name, confidence=0.9,
                    reason="up", detail="",
                    repair_candidates=[RepairCandidate(
                        strategy="lc", confidence=0.9, reason="up")],
                )

        class _R:
            name = "det.r"
            strategy = "lc"
            def repair(self, artifact, candidate):
                return RepairResult(success=True, strategy=self.strategy,
                                      repaired_payload=artifact.payload.lower())

        register_validator(_V())
        register_repair(_R())

        orch = Orchestrator(recognizers=[_EmitChildRecognizer()],
                             max_artifacts=8, max_depth=4)
        r1 = orch.run(b"root", root_type="unknown")
        r2 = orch.run(b"root", root_type="unknown")

        # Same URIs, same strategies, same outcomes.
        def _fingerprint(r):
            return (
                sorted(r.artifacts.keys()),
                sorted((c.strategy, c.outcome) for c in r.repair_certificates),
                sorted((c.validator, c.valid) for c in r.validation_certificates),
            )
        assert _fingerprint(r1) == _fingerprint(r2)
    finally:
        cap_mod._REGISTRY.clear()
        cap_mod._REGISTRY.update(caps_snap)
        _restore_registries(snap)
