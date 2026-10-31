"""SSOT-level projection tests for the QA-Layer  (R28.3).

Proves ``quality_assurance`` sub-tree is emitted deterministically
with every projection and roll-up counts add up correctly.
"""
from __future__ import annotations

from services.uaie import qa
from services.uaie.artifact   import make_artifact
from services.uaie.capability import CapabilityResult, register as register_capability
from services.uaie.capability import _REGISTRY as _CAP_REG
from services.uaie.orchestrator import Orchestrator
from services.uaie.qa import (RepairCandidate, RepairResult, ValidationResult,
                                 register_repair, register_validator)
from services.uaie.recognizer import CERTAIN, Reason, Recognition
from services.uaie.ssot_projector import project


class _R:
    name = "test.r"
    def recognize(self, artifact):
        return [Recognition(artifact_type="qa_test", confidence=CERTAIN,
                             reasons=[Reason("t", 1.0)], recognizer=self.name)]


class _C:
    name = "test.emit"
    requires_artifact_type = ["qa_test"]
    requires_evidence      = []
    def execute(self, artifact):
        child = make_artifact(b"BAD_SHOUTY", "test_kind",
                                parent_uri=artifact.uri,
                                depth=artifact.depth + 1,
                                discovered_by=self.name)
        return CapabilityResult(child_artifacts=[child])


class _V:
    name = "test.v"
    validates_artifact_type = ["test_kind"]
    def validate(self, artifact):
        text = artifact.payload.decode("utf-8", errors="ignore")
        if text == text.lower() and any(c.isalpha() for c in text):
            return ValidationResult(valid=True, validator=self.name, confidence=0.9)
        return ValidationResult(
            valid=False, validator=self.name, confidence=0.9,
            reason="uppercase", detail="",
            repair_candidates=[RepairCandidate(strategy="lc", confidence=0.9,
                                                 reason="uppercase")],
        )


class _RepairLower:
    name = "test.repair.lc"
    strategy = "lc"
    def repair(self, artifact, candidate):
        return RepairResult(success=True, strategy=self.strategy,
                              repaired_payload=artifact.payload.lower())


def _snapshot():
    return (dict(qa._VALIDATOR_REGISTRY), dict(qa._REPAIR_REGISTRY),
            dict(_CAP_REG))


def _restore(snap):
    v, r, c = snap
    qa._VALIDATOR_REGISTRY.clear(); qa._VALIDATOR_REGISTRY.update(v)
    qa._REPAIR_REGISTRY.clear();    qa._REPAIR_REGISTRY.update(r)
    _CAP_REG.clear();               _CAP_REG.update(c)


def test_ssot_project_includes_quality_assurance_block():
    snap = _snapshot()
    try:
        _CAP_REG.clear()
        register_capability(_C())
        register_validator(_V())
        register_repair(_RepairLower())
        orch = Orchestrator(recognizers=[_R()], max_artifacts=8, max_depth=4)
        r = orch.run(b"root", root_type="unknown")

        ssot = project(r, root_input="root", root_output="")
        qa_block = ssot["quality_assurance"]
        # top-level shape
        assert set(qa_block.keys()) == {
            "validation_certificates", "repair_certificates", "states", "summary",
        }
        # a validator ran (twice: on invalid + on repaired child)
        outcomes = qa_block["summary"]["validators_by_outcome"]
        assert outcomes.get("invalid", 0) >= 1
        assert outcomes.get("valid",   0) >= 1
        # exactly one successful repair
        assert qa_block["summary"]["repairs_by_outcome"] == {"success": 1}
        # lifecycle states include REPAIRED and VALIDATED
        kinds = qa_block["summary"]["states_by_kind"]
        assert kinds.get("REPAIRED", 0) == 1
        assert kinds.get("VALIDATED", 0) >= 1
        # No unreachable in the happy path
        assert qa_block["summary"]["unreachable_uris"] == []
    finally:
        _restore(snap)


def test_ssot_project_surfaces_unreachable_artifacts():
    snap = _snapshot()

    class _C2:
        name = "test.emit2"
        requires_artifact_type = ["qa_test"]
        requires_evidence      = []
        def execute(self, artifact):
            child = make_artifact(b"\x00" * 32, "dead_kind",
                                    parent_uri=artifact.uri,
                                    depth=artifact.depth + 1,
                                    discovered_by=self.name)
            return CapabilityResult(child_artifacts=[child])

    class _V2:
        name = "test.v2"
        validates_artifact_type = ["dead_kind"]
        def validate(self, artifact):
            return ValidationResult(
                valid=False, validator=self.name, confidence=0.99,
                reason="dead", detail="always dead",
                repair_candidates=[],   # no repair proposed
            )

    try:
        _CAP_REG.clear()
        register_capability(_C2())
        register_validator(_V2())
        orch = Orchestrator(recognizers=[_R()], max_artifacts=8, max_depth=4)
        r = orch.run(b"root", root_type="unknown")

        ssot = project(r, root_input="root", root_output="")
        qa_block = ssot["quality_assurance"]
        assert len(qa_block["summary"]["unreachable_uris"]) == 1
        assert qa_block["summary"]["states_by_kind"].get("UNREACHABLE") == 1
    finally:
        _restore(snap)
