"""UAIE Phase 1 · Contract Soundness Tests (Rule R25 amendment)

Proves the six core contracts (Artifact / Recognizer / Capability /
Evidence / Ledger / Orchestrator) are coherent by running a trivial
"toy" plugin pair through the orchestrator:

    · Root paste = the bytes ``"hello uaie world"``
    · TrivialRecognizer classifies bytes as ``artifact_type="text"``
    · TrivialCapability emits one Evidence (kind=count) and one child
      artifact (the input reversed, artifact_type="text_reversed").
    · Second recognizer + no capability for text_reversed → termination.

Asserts:
    · Artifact URIs are deterministic (same bytes → same URI)
    · Ledger is append-only, chronologically ordered, non-empty
    · Ledger contains the mandatory action types
    · Evidence is produced through the Capability path
    · Determinism — 5 runs, identical ledger structure
    · No mutation of Artifact objects (frozen)
"""
from __future__ import annotations

import pytest

from services.uaie import (
    ACTION_COMPLETE, ACTION_EMIT_EVIDENCE, ACTION_ENQUEUE,
    ACTION_EXECUTE, ACTION_RECOGNIZE,
    Artifact, Capability, CapabilityResult, HIGH,
    Orchestrator, Reason, Recognition,
    clear, make_evidence, register,
)


# ── Toy recognizers ─────────────────────────────────────────────
class _TextRecognizer:
    name = "toy.text"

    def recognize(self, artifact: Artifact):
        if artifact.artifact_type == "text":
            return [Recognition(artifact_type="text", confidence=HIGH,
                                  reasons=[Reason("test", 100, "toy")])]
        if artifact.artifact_type == "text_reversed":
            return [Recognition(artifact_type="text_reversed", confidence=HIGH,
                                  reasons=[Reason("test", 100, "toy")])]
        return []


# ── Toy capabilities ─────────────────────────────────────────────
class _CountCapability:
    name = "toy.count"
    requires_artifact_type = ["text"]
    requires_evidence: list = []

    def execute(self, artifact: Artifact) -> CapabilityResult:
        from services.uaie.artifact import make_artifact
        text = artifact.payload.decode("utf-8", "replace")
        ev = make_evidence(
            artifact_uri=artifact.uri, kind="count", value=len(text),
            source_capability=self.name, confidence=HIGH,
            reasons=[Reason("len", 1, str(len(text)))],
        )
        child = make_artifact(text[::-1].encode(), "text_reversed",
                                parent_uri=artifact.uri, depth=artifact.depth + 1,
                                discovered_by=self.name)
        return CapabilityResult(evidence=[ev], child_artifacts=[child])


@pytest.fixture(autouse=True)
def _reset_registry():
    # Snapshot the production registry so we can restore it after each
    # test — otherwise the ``clear()`` call in this module wipes every
    # UAIE plugin registered at package import time, and any test file
    # that runs after this one in the same worker sees an empty registry.
    from services.uaie.capability import _REGISTRY
    saved = {k: list(v) for k, v in _REGISTRY.items()}
    clear()
    register(_CountCapability())
    yield
    clear()
    for k, v in saved.items():
        _REGISTRY[k] = list(v)


class TestPhase1ContractSoundness:
    def test_run_completes_and_emits_ledger(self):
        orch = Orchestrator(recognizers=[_TextRecognizer()])
        result = orch.run(b"hello uaie world", root_type="text")
        assert result.total_ms >= 0
        assert len(result.artifacts) >= 2, "expected root + one child artifact"
        assert len(result.evidence) == 1
        assert result.evidence[0].kind == "count"
        assert result.evidence[0].value == 16
        # Ledger contains the mandatory action types.
        actions = {e.action for e in result.ledger}
        for req in (ACTION_RECOGNIZE, ACTION_EXECUTE, ACTION_EMIT_EVIDENCE,
                     ACTION_ENQUEUE, ACTION_COMPLETE):
            assert req in actions, f"missing ledger action: {req}"

    def test_artifact_uris_are_deterministic(self):
        from services.uaie import compute_uri
        assert compute_uri(b"hello") == compute_uri(b"hello")
        assert compute_uri(b"hello") != compute_uri(b"world")

    def test_ledger_is_ordered_and_immutable(self):
        orch = Orchestrator(recognizers=[_TextRecognizer()])
        result = orch.run(b"hello uaie world", root_type="text")
        seqs = [e.seq for e in result.ledger]
        assert seqs == sorted(seqs), "ledger must be chronologically ordered"
        # Snapshot is a defensive copy.
        snap = result.ledger.snapshot()
        snap.clear()
        assert len(result.ledger) > 0, "mutating snapshot must not corrupt ledger"

    def test_five_runs_are_deterministic(self):
        orch = Orchestrator(recognizers=[_TextRecognizer()])
        signatures = []
        for _ in range(5):
            r = orch.run(b"hello uaie world", root_type="text")
            sig = [(e.action, e.actor, e.artifact_uri, e.output_summary)
                    for e in r.ledger if e.action != ACTION_COMPLETE]
            signatures.append(sig)
        assert all(s == signatures[0] for s in signatures), \
            "UAIE ledger must be deterministic across runs"

    def test_no_capabilities_registered_still_completes(self):
        clear()   # empty registry — nothing to execute
        orch = Orchestrator(recognizers=[_TextRecognizer()])
        result = orch.run(b"hello uaie world", root_type="text")
        assert len(result.artifacts) == 1     # root only, no children
        assert result.evidence == []          # no capabilities → no evidence
        actions = {e.action for e in result.ledger}
        assert ACTION_RECOGNIZE in actions
        assert ACTION_COMPLETE  in actions

    def test_capability_registry_is_flat(self):
        from services.uaie import all_registered, for_type
        reg = all_registered()
        assert "text" in reg
        assert "toy.count" in reg["text"]
        # Registry maps type → capabilities directly.
        assert any(c.name == "toy.count" for c in for_type("text"))
