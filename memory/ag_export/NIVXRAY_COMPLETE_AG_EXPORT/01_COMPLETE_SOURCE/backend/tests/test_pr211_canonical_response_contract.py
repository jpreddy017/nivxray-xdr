"""PR-2.1.1 · Canonical Response Contract regression tests
(ARB Governance Rules 12, 14, 15).

Every visible verdict surface on the same investigation must render
the same verdict. This suite guards the invariant.
"""
from __future__ import annotations

import base64

from verdict_projection import (
    derive_risk_projection,
    ensure_canonical_response,
    promote_semantic_review_signal,
)


BENIGN_PAYLOAD = 'Write-Host "This comes from an encoded PS command!"'


def _b64(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode()


# ---------------------------------------------------------------------------
# derive_risk_projection · pure function
# ---------------------------------------------------------------------------


def test_derive_risk_projection_maps_partial_verdict():
    vc = {"verdict": "Partial", "risk_score": 25, "confidence": 25}
    p = derive_risk_projection(vc)
    assert p == {"verdict": "Partial", "level": "low", "score": 25}


def test_derive_risk_projection_maps_malicious_verdict():
    vc = {"verdict": "Malicious", "risk_score": 90, "confidence": 90}
    p = derive_risk_projection(vc)
    assert p == {"verdict": "Malicious", "level": "high", "score": 90}


def test_derive_risk_projection_maps_suspicious_verdict():
    vc = {"verdict": "Suspicious", "risk_score": 60}
    p = derive_risk_projection(vc)
    assert p == {"verdict": "Suspicious", "level": "medium", "score": 60}


def test_derive_risk_projection_returns_none_for_empty_card():
    assert derive_risk_projection(None) is None
    assert derive_risk_projection({}) is None
    assert derive_risk_projection({"other_field": "x"}) is None


def test_derive_risk_projection_maps_informational_verdict():
    vc = {"verdict": "Informational", "risk_score": 15}
    p = derive_risk_projection(vc)
    assert p["level"] == "safe"


def test_derive_risk_projection_from_confidence_ratio():
    """When only ``confidence`` is available (0..1 float), score = int(conf*100)."""
    vc = {"verdict": "Partial", "confidence": 0.25}
    p = derive_risk_projection(vc)
    assert p["score"] == 25


# ---------------------------------------------------------------------------
# ensure_canonical_response · idempotent projection
# ---------------------------------------------------------------------------


def test_ensure_canonical_response_overwrites_independent_risk():
    """A response with a mismatched legacy ``risk`` gets projected."""
    result = {
        "verdict_card": {"verdict": "Partial", "risk_score": 25},
        # Legacy independent decision — Rule 12 forbids using this.
        "risk": {"verdict": "Suspicious", "level": "medium", "score": 43},
    }
    ensure_canonical_response(result)
    assert result["risk"] == {"verdict": "Partial", "level": "low", "score": 25}


def test_ensure_canonical_response_idempotent():
    result = {"verdict_card": {"verdict": "Malicious", "risk_score": 90}}
    ensure_canonical_response(result)
    first = dict(result["risk"])
    ensure_canonical_response(result)
    assert result["risk"] == first


def test_ensure_canonical_response_noop_when_no_verdict_card():
    result = {"iocs": {"urls": ["x"]}}
    ensure_canonical_response(result)
    assert "risk" not in result


# ---------------------------------------------------------------------------
# promote_semantic_review_signal · disambiguation
# ---------------------------------------------------------------------------


def test_promote_semantic_review_signal_adds_new_field():
    result = {"semantic": {"verdict": "needs_review", "confidence": 99}}
    promote_semantic_review_signal(result)
    assert result["semantic"]["review_signal"] == "needs_review"
    # Legacy field preserved during transition
    assert result["semantic"]["verdict"] == "needs_review"


def test_promote_semantic_review_signal_noop_without_semantic():
    result = {"other": 1}
    promote_semantic_review_signal(result)
    assert "semantic" not in result


def test_promote_semantic_review_signal_does_not_clobber_existing():
    result = {"semantic": {"verdict": "x", "review_signal": "explicit"}}
    promote_semantic_review_signal(result)
    assert result["semantic"]["review_signal"] == "explicit"


# ---------------------------------------------------------------------------
# Rule 14 · Decode / Auto-Investigate equivalence contract
# ---------------------------------------------------------------------------


def test_rule14_projection_forces_agreement_across_consumers():
    """When any consumer reads either ``verdict_card`` or ``risk`` from
    a canonicalised response, they see the same verdict."""
    result = {
        "verdict_card": {"verdict": "Partial", "risk_score": 25},
        # Legacy risk drifts — simulate the pre-fix bug.
        "risk": {"verdict": "Suspicious", "score": 43},
    }
    ensure_canonical_response(result)
    # Every "consumer" of the response now sees the same verdict.
    vc_verdict = result["verdict_card"]["verdict"]
    risk_verdict = result["risk"]["verdict"]
    assert vc_verdict == risk_verdict == "Partial"

    # Score projection matches too.
    assert result["verdict_card"]["risk_score"] == result["risk"]["score"] == 25


def test_rule14_projection_from_malicious_case():
    result = {
        "verdict_card": {"verdict": "Malicious", "risk_score": 92, "confidence": 92},
        "risk": {"verdict": "Runtime Dependent", "score": 55},  # stale
    }
    ensure_canonical_response(result)
    assert result["risk"]["verdict"] == "Malicious"
    assert result["risk"]["level"] == "high"
    assert result["risk"]["score"] == 92
