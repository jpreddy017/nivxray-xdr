"""Artifact Lifecycle State Machine tests  (R28.5).

Verifies:
    · every artifact receives a NEW transition when it enters the graph
    · monotonic progression through the DAG
    · UNREACHABLE branches close cleanly to DONE at fixed-point time
    · REPAIRED / REPAIR_PENDING transitions fire from the QA layer
    · the recorder rejects illegal transitions silently
    · SSOT projector surfaces the timeline under `lifecycle`
"""
from __future__ import annotations

from services.uaie import qa
from services.uaie.artifact   import make_artifact
from services.uaie.capability import CapabilityResult, register as register_capability
from services.uaie.capability import _REGISTRY as _CAP_REG
from services.uaie.evidence   import make_evidence
from services.uaie.lifecycle  import (LC_ANALYZED, LC_DONE, LC_EVIDENCE_COMPLETE,
                                        LC_EXECUTED, LC_FIXED_POINT, LC_NEW,
                                        LC_PLANNED, LC_RECOGNIZED, LC_REPAIRED,
                                        LC_REPAIR_PENDING, LC_UNREACHABLE,
                                        LC_VALIDATED, LIFECYCLE_ORDER,
                                        LifecycleRecorder, is_legal_transition)
from services.uaie.orchestrator import Orchestrator
from services.uaie.qa import (RepairCandidate, RepairResult, ValidationResult,
                                 register_repair, register_validator)
from services.uaie.recognizer import CERTAIN, Reason, Recognition
from services.uaie.ssot_projector import project


# ══════════════════════════════════════════════════════════════════
# Registry snapshot helpers
# ══════════════════════════════════════════════════════════════════
def _snapshot():
    return (dict(qa._VALIDATOR_REGISTRY), dict(qa._REPAIR_REGISTRY),
            dict(_CAP_REG))


def _restore(snap):
    v, r, c = snap
    qa._VALIDATOR_REGISTRY.clear(); qa._VALIDATOR_REGISTRY.update(v)
    qa._REPAIR_REGISTRY.clear();    qa._REPAIR_REGISTRY.update(r)
    _CAP_REG.clear();               _CAP_REG.update(c)


# ══════════════════════════════════════════════════════════════════
# 1 · Pure-function LifecycleRecorder unit tests
# ══════════════════════════════════════════════════════════════════
def test_is_legal_transition_monotonic():
    # Note: the "" → LC_NEW cold entry is handled inside the recorder;
    # the pure is_legal_transition function only validates transitions
    # between two known lifecycle states.
    assert is_legal_transition(LC_NEW, LC_RECOGNIZED)
    assert is_legal_transition(LC_RECOGNIZED, LC_PLANNED)
    assert is_legal_transition(LC_PLANNED, LC_EXECUTED)
    assert is_legal_transition(LC_EXECUTED, LC_ANALYZED)
    # backward moves are illegal
    assert not is_legal_transition(LC_EXECUTED, LC_RECOGNIZED)
    assert not is_legal_transition(LC_DONE, LC_NEW)


def test_is_legal_transition_unreachable_branch():
    # UNREACHABLE reachable from any non-terminal
    assert is_legal_transition(LC_VALIDATED, LC_UNREACHABLE)
    assert is_legal_transition(LC_REPAIR_PENDING, LC_UNREACHABLE)
    # only DONE closes UNREACHABLE
    assert is_legal_transition(LC_UNREACHABLE, LC_DONE)
    assert not is_legal_transition(LC_UNREACHABLE, LC_ANALYZED)


def test_recorder_rejects_illegal_transitions_silently():
    lc = LifecycleRecorder()
    assert lc.transition("art/1", LC_NEW, actor="t", reason="r") is True
    # illegal: NEW → DONE (skips DAG)
    assert lc.transition("art/1", LC_RECOGNIZED, actor="t", reason="r") is True
    # backwards move — must fail
    assert lc.transition("art/1", LC_NEW, actor="t", reason="r") is False
    assert lc.warnings, "warnings must be recorded for illegal moves"
    # timeline preserves what actually happened
    tl = lc.all_transitions_for("art/1")
    assert [t.next_state for t in tl] == [LC_NEW, LC_RECOGNIZED]


def test_recorder_leap_forward_is_legal():
    lc = LifecycleRecorder()
    lc.transition("art/1", LC_NEW, actor="t", reason="r")
    # Leap NEW → EXECUTED (recording engine may collapse micro-steps)
    assert lc.transition("art/1", LC_EXECUTED, actor="t", reason="r") is True


# ══════════════════════════════════════════════════════════════════
# 2 · Orchestrator emits full lifecycle for a happy-path artifact
# ══════════════════════════════════════════════════════════════════
class _R:
    name = "lc.recognizer"
    def recognize(self, artifact):
        return [Recognition(artifact_type="lc_kind", confidence=CERTAIN,
                             reasons=[Reason("t", 1.0)], recognizer=self.name)]


class _EmitEvidenceCap:
    name = "lc.emit_evidence"
    requires_artifact_type = ["lc_kind"]
    requires_evidence      = []
    def execute(self, artifact):
        ev = make_evidence(artifact_uri=artifact.uri, kind="test.finding",
                             value="ok", source_capability=self.name,
                             confidence=0.9)
        return CapabilityResult(evidence=[ev])


def test_happy_path_full_lifecycle():
    snap = _snapshot()
    try:
        _CAP_REG.clear()
        register_capability(_EmitEvidenceCap())
        orch = Orchestrator(recognizers=[_R()], max_artifacts=4, max_depth=2)
        r = orch.run(b"root", root_type="lc_kind")
        # Fetch the root's timeline
        root_uri = next(iter(r.artifacts))
        timeline = [t for t in r.state_transitions if t.artifact_uri == root_uri]
        states = [t.next_state for t in timeline]
        # Expected states in order (leaps allowed but must contain these)
        for expected in (LC_NEW, LC_RECOGNIZED, LC_PLANNED, LC_EXECUTED,
                          LC_ANALYZED, LC_EVIDENCE_COMPLETE, LC_FIXED_POINT,
                          LC_DONE):
            assert expected in states, f"missing {expected} in {states}"
        # Monotonic — every consecutive pair must satisfy is_legal_transition
        for prev_t, next_t in zip(timeline, timeline[1:]):
            assert is_legal_transition(prev_t.next_state, next_t.next_state), (
                f"illegal timeline hop {prev_t.next_state} → {next_t.next_state}"
            )
    finally:
        _restore(snap)


# ══════════════════════════════════════════════════════════════════
# 3 · QA-Repair path emits VALIDATED → REPAIR_PENDING → REPAIRED
# ══════════════════════════════════════════════════════════════════
class _EmitDirty:
    name = "lc.emit_dirty"
    requires_artifact_type = ["lc_kind"]
    requires_evidence      = []
    def execute(self, artifact):
        return CapabilityResult(child_artifacts=[
            make_artifact(b"UPPER", "dirty_lc_kind",
                            parent_uri=artifact.uri,
                            depth=artifact.depth + 1,
                            discovered_by=self.name),
        ])


class _V:
    name = "lc.v"
    validates_artifact_type = ["dirty_lc_kind"]
    def validate(self, artifact):
        t = artifact.payload.decode("utf-8", errors="ignore")
        if t == t.lower() and any(c.isalpha() for c in t):
            return ValidationResult(valid=True, validator=self.name, confidence=0.9)
        return ValidationResult(
            valid=False, validator=self.name, confidence=0.9,
            reason="uppercase",
            repair_candidates=[RepairCandidate(strategy="lc",
                                                 confidence=0.9,
                                                 reason="uppercase")],
        )


class _RLower:
    name = "lc.r"
    strategy = "lc"
    def repair(self, artifact, candidate):
        return RepairResult(success=True, strategy=self.strategy,
                              repaired_payload=artifact.payload.lower())


def test_repair_path_emits_full_qa_transitions():
    snap = _snapshot()
    try:
        _CAP_REG.clear()
        register_capability(_EmitDirty())
        register_validator(_V())
        register_repair(_RLower())

        orch = Orchestrator(recognizers=[_R()], max_artifacts=8, max_depth=4)
        r = orch.run(b"root", root_type="lc_kind")

        # Locate the dirty (source) and repaired child artifacts.
        dirty_uris = [u for u, a in r.artifacts.items()
                        if a.payload == b"UPPER" and a.artifact_type == "dirty_lc_kind"]
        clean_uris = [u for u, a in r.artifacts.items()
                        if a.payload == b"upper" and a.artifact_type == "dirty_lc_kind"]
        assert len(dirty_uris) == 1 and len(clean_uris) == 1

        # Dirty artifact should have: NEW → VALIDATED → REPAIR_PENDING → REPAIRED → DONE
        dirty_states = [t.next_state for t in r.state_transitions
                         if t.artifact_uri == dirty_uris[0]]
        for s in (LC_NEW, LC_VALIDATED, LC_REPAIR_PENDING, LC_REPAIRED):
            assert s in dirty_states, f"dirty artifact missing {s} in {dirty_states}"

        # Repaired artifact: NEW → VALIDATED
        clean_states = [t.next_state for t in r.state_transitions
                         if t.artifact_uri == clean_uris[0]]
        assert LC_NEW       in clean_states
        assert LC_VALIDATED in clean_states
    finally:
        _restore(snap)


# ══════════════════════════════════════════════════════════════════
# 4 · UNREACHABLE artifacts close to DONE at fixed-point time
# ══════════════════════════════════════════════════════════════════
def test_unreachable_closes_to_done():
    snap = _snapshot()

    class _EmitDead:
        name = "lc.emit_dead"
        requires_artifact_type = ["lc_kind"]
        requires_evidence      = []
        def execute(self, artifact):
            return CapabilityResult(child_artifacts=[
                make_artifact(b"\x00" * 16, "dead_lc_kind",
                                parent_uri=artifact.uri,
                                depth=artifact.depth + 1,
                                discovered_by=self.name),
            ])

    class _AlwaysDead:
        name = "lc.dead_v"
        validates_artifact_type = ["dead_lc_kind"]
        def validate(self, artifact):
            return ValidationResult(
                valid=False, validator=self.name, confidence=0.99,
                reason="dead", detail="", repair_candidates=[],
            )

    try:
        _CAP_REG.clear()
        register_capability(_EmitDead())
        register_validator(_AlwaysDead())
        orch = Orchestrator(recognizers=[_R()], max_artifacts=8, max_depth=4)
        r = orch.run(b"root", root_type="lc_kind")

        dead_uris = [u for u, a in r.artifacts.items() if a.artifact_type == "dead_lc_kind"]
        assert len(dead_uris) == 1
        dead_states = [t.next_state for t in r.state_transitions
                        if t.artifact_uri == dead_uris[0]]
        assert LC_UNREACHABLE in dead_states
        assert LC_DONE        in dead_states, (
            f"UNREACHABLE artifact must close to DONE; got {dead_states}"
        )
    finally:
        _restore(snap)


# ══════════════════════════════════════════════════════════════════
# 5 · Determinism · same input → same lifecycle timeline (structure)
# ══════════════════════════════════════════════════════════════════
def test_lifecycle_is_deterministic_across_runs():
    snap = _snapshot()
    try:
        _CAP_REG.clear()
        register_capability(_EmitEvidenceCap())
        orch = Orchestrator(recognizers=[_R()], max_artifacts=4, max_depth=2)
        r1 = orch.run(b"deterministic_root", root_type="lc_kind")
        r2 = orch.run(b"deterministic_root", root_type="lc_kind")

        def _fp(r):
            return [(t.artifact_uri, t.previous_state, t.next_state,
                      t.actor, t.reason) for t in r.state_transitions]

        assert _fp(r1) == _fp(r2)
    finally:
        _restore(snap)


# ══════════════════════════════════════════════════════════════════
# 6 · SSOT projector surfaces the lifecycle block
# ══════════════════════════════════════════════════════════════════
def test_ssot_project_includes_lifecycle_block():
    snap = _snapshot()
    try:
        _CAP_REG.clear()
        register_capability(_EmitEvidenceCap())
        orch = Orchestrator(recognizers=[_R()], max_artifacts=4, max_depth=2)
        r = orch.run(b"root", root_type="lc_kind")
        ssot = project(r, root_input="root", root_output="")
        lc = ssot["lifecycle"]
        assert set(lc.keys()) == {"transitions", "per_artifact",
                                     "current_state", "summary"}
        assert lc["summary"]["transition_count"] == len(r.state_transitions)
        # At least one artifact reached DONE
        assert lc["summary"]["states_by_kind"].get(LC_DONE, 0) >= 1
    finally:
        _restore(snap)


# ══════════════════════════════════════════════════════════════════
# 7 · Result.state_transitions is a list of StateTransition
# ══════════════════════════════════════════════════════════════════
def test_state_transitions_are_immutable_records():
    snap = _snapshot()
    try:
        _CAP_REG.clear()
        register_capability(_EmitEvidenceCap())
        orch = Orchestrator(recognizers=[_R()], max_artifacts=4, max_depth=2)
        r = orch.run(b"root", root_type="lc_kind")
        assert len(r.state_transitions) > 0
        first = r.state_transitions[0]
        # StateTransition is frozen — mutation must raise
        import pytest
        with pytest.raises((AttributeError, TypeError, Exception)):
            first.next_state = "HACKED"   # type: ignore
    finally:
        _restore(snap)
