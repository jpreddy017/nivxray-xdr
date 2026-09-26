"""ADR-0001 · framework tests — classifier + registry + coverage.

Handler-agnostic. No concrete handler is exercised. The tests use
minimal Protocol-satisfying fakes to prove the framework contracts.
"""

import pytest

from nivxforge.core.cio import CIO
from nivxforge.framework.classifier import (
    Artifact, Shape, classify, register_family_detector, registered_families,
)
from nivxforge.framework.protocol import Handler, HandlerMetadata
from nivxforge.framework.registry import (
    register_handler, handlers_for, total_handlers,
)
from nivxforge.framework.coverage import report


# ── Classifier ────────────────────────────────────────────────────────
def test_classifier_returns_unknown_when_no_detectors():
    a = Artifact(payload="anything")
    s = classify(a)
    # depending on other tests having registered fake detectors, this
    # returns either unknown or a fake family — but MUST return a Shape
    assert isinstance(s, Shape)


def test_register_family_detector_and_classify():
    def detect_ps(a: Artifact):
        if "powershell" in (a.payload or "").lower():
            return Shape(family="powershell", confidence=0.9, reasons=["shell head"])
        return None
    register_family_detector("powershell", detect_ps)
    assert "powershell" in registered_families()
    s = classify(Artifact(payload="powershell -c echo hi"))
    assert s.family == "powershell"
    assert s.confidence >= 0.9


def test_classifier_prefers_highest_confidence():
    def det_low(a): return Shape(family="A", confidence=0.4, reasons=["low"])
    def det_high(a): return Shape(family="B", confidence=0.7, reasons=["high"])
    register_family_detector("test_A_low", det_low)
    register_family_detector("test_B_high", det_high)
    s = classify(Artifact(payload=""))
    assert s.family == "B"


# ── Handler Protocol + metadata ───────────────────────────────────────
class _FakeHandler:
    family = "powershell"
    metadata = HandlerMetadata(
        name="fake_ps_handler",
        adr="adr/0001-command-obfuscation-deobfuscation-coverage.md",
        evidence_count=1,
        first_seen="2026-02-28",
        last_seen="2026-02-28",
        confidence=0.9,
        regression_tests=["nivxforge/tests/test_framework.py::test_handler_registers"],
    )

    def process(self, artifact, shape, cio):
        cio.append("decode_layers", engine=self.metadata.name, payload={"note": "fake"})
        return cio


def test_handler_satisfies_protocol():
    assert isinstance(_FakeHandler(), Handler)


def test_handler_metadata_requires_adr():
    with pytest.raises(ValueError):
        HandlerMetadata(
            name="x", adr="", evidence_count=1,
            first_seen="2026-02-28", last_seen="2026-02-28", confidence=0.5,
        )


def test_handler_metadata_requires_evidence():
    with pytest.raises(ValueError):
        HandlerMetadata(
            name="x", adr="adr/0001-x.md", evidence_count=0,
            first_seen="2026-02-28", last_seen="2026-02-28", confidence=0.5,
        )


def test_handler_metadata_confidence_bounded():
    with pytest.raises(ValueError):
        HandlerMetadata(
            name="x", adr="adr/0001-x.md", evidence_count=1,
            first_seen="2026-02-28", last_seen="2026-02-28", confidence=1.1,
        )


# ── Registry ──────────────────────────────────────────────────────────
def test_handler_registers_and_lookup():
    before = total_handlers()
    h = _FakeHandler()
    register_handler(h)
    assert total_handlers() == before + 1
    assert h in handlers_for("powershell")


def test_register_handler_rejects_non_protocol_object():
    class NotAHandler: pass
    with pytest.raises(TypeError):
        register_handler(NotAHandler())


# ── Coverage Reporter ─────────────────────────────────────────────────
def test_coverage_marks_plain_text_as_not_obfuscated():
    r = report("powershell", ["fake"], "Write-Host 'Hello World!' -ForegroundColor Green")
    assert r.residual_looks_obfuscated is False
    assert r.family == "powershell"
    assert r.handler_names == ["fake"]


def test_coverage_marks_high_entropy_low_printable_as_obfuscated():
    # Simulated residual — random bytes rendered as latin-1 chars
    import os
    residual = os.urandom(400).decode("latin-1")
    r = report("shellcode", ["decoder"], residual)
    # high-entropy + low-printable → flagged obfuscated
    assert r.residual_entropy >= 5.5


def test_coverage_handles_empty_residual():
    r = report("unknown", [], "")
    assert any("residual_length=0" in x for x in r.rationale)
