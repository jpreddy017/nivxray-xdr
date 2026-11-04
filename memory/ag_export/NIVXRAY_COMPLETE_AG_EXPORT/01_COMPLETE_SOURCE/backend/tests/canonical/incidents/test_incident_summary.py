"""Incident Summary projection contract tests (Slice 2 · P1)."""
from __future__ import annotations

import sys
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[3]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from routers.incident_summary import _project_summary  # noqa: E402


def _case(**overrides):
    base = {
        "id": "case-sum-1",
        "user_email": "analyst@nivxray.com",
        "verdict_stage2": {
            "label": "malicious",
            "risk_score": 92,
            "confidence_bucket": "high",
            "evidence": [
                {"rule_id": "CMD-OBFUSCATION",       "weight": 30},
                {"rule_id": "MITRE-EXFILTRATION",   "weight": 20},
            ],
        },
        "iocs": {"hash": ["abc"], "domain": ["bad.example.com"]},
    }
    base.update(overrides)
    return base


def test_summary_shape():
    s = _project_summary(_case())
    for key in ("observed_facts", "suspicious_elements",
                  "evidence_relationships", "evidence_gaps",
                  "recommended_next", "deterministic_verdict", "sources"):
        assert key in s


def test_summary_suspicious_has_detected_by():
    s = _project_summary(_case())
    assert len(s["suspicious_elements"]) == 2
    for row in s["suspicious_elements"]:
        assert row["detected_by"] == "NivXRay Verdict Engine · Stage-2"
        assert row["provenance"] == "workspace_cases.verdict_stage2.evidence[]"


def test_summary_gaps_distinguish_four_states():
    s = _project_summary(_case())
    states = {g["state"] for g in s["evidence_gaps"]}
    # Must contain both no_matching_evidence AND not_connected — the
    # core distinction locked by the owner.
    assert "no_matching_evidence" in states
    assert "not_connected"        in states


def test_summary_gaps_include_not_available_when_stage2_missing():
    s = _project_summary({"id": "case-no-stage2"})
    states = {g["state"] for g in s["evidence_gaps"]}
    assert "not_available" in states


def test_summary_recommends_ioc_enrichment_when_iocs_present():
    s = _project_summary(_case())
    actions = [r["action"] for r in s["recommended_next"]]
    assert any("IOC Intelligence" in a for a in actions)


def test_summary_verdict_block_never_uses_llm():
    s = _project_summary(_case())
    v = s["deterministic_verdict"]
    assert v["engine"].startswith("NivXRay Deterministic Verdict Engine")
    assert v["provenance"] == "workspace_cases.verdict_stage2"


def test_summary_omits_verdict_when_stage2_absent():
    s = _project_summary({"id": "empty"})
    assert s["deterministic_verdict"] is None
