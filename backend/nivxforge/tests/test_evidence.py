"""Evidence Ledger invariants — Charter Rule 3."""

import pytest
from pydantic import ValidationError

from nivxforge.core.evidence import Evidence, Finding


def _ev(source="input", detail="observed x") -> Evidence:
    return Evidence(source=source, detail=detail)


def test_finding_requires_evidence():
    with pytest.raises(ValidationError):
        Finding(
            finding="X is malicious",
            evidence=[],
            engine="test_engine",
            confidence=0.9,
        )


def test_finding_with_evidence_is_valid():
    f = Finding(
        finding="artefact contains -bxor pattern",
        evidence=[_ev(detail="regex match on -bxor 0x36")],
        engine="pattern_matcher",
        confidence=0.85,
    )
    assert f.finding.startswith("artefact")
    assert len(f.evidence) == 1
    assert f.engine == "pattern_matcher"


def test_finding_confidence_bounded():
    with pytest.raises(ValidationError):
        Finding(
            finding="x",
            evidence=[_ev()],
            engine="e",
            confidence=1.5,
        )
    with pytest.raises(ValidationError):
        Finding(
            finding="x",
            evidence=[_ev()],
            engine="e",
            confidence=-0.1,
        )


def test_finding_is_frozen():
    f = Finding(
        finding="x",
        evidence=[_ev()],
        engine="e",
        confidence=0.5,
    )
    with pytest.raises(Exception):
        f.confidence = 0.99  # frozen — must refuse mutation
