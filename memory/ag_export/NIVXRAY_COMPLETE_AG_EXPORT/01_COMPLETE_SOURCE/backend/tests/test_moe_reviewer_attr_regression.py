"""Regression — MoE panel synthesiser must NOT raise AttributeError.

Analyst reported the Threat Model page rendered
`'ReviewerReport' object has no attribute 'reviewer_name'`.

The synthesiser used `r.reviewer_name` on the dataclass which only has
`reviewer`. This suite pins the attribute + exercises the full
`_synthesise()` path with 2+ agreeing reviewers so the verdict-consensus
branch (where the typo lived) is actually taken.
"""
from __future__ import annotations

from reasoning.moe_panel import (
    ReviewerReport,
    Finding,
    _synthesise,
)


def _finding(severity: str, title: str = "t") -> Finding:
    return Finding(title=title, description="regression stub",
                   severity=severity, confidence=0.9)


def test_reviewer_report_has_reviewer_not_reviewer_name():
    r = ReviewerReport(reviewer="malware_analyst")
    assert hasattr(r, "reviewer")
    assert not hasattr(r, "reviewer_name")


def test_synthesise_with_two_agreeing_reviewers_no_attribute_error():
    reports = [
        ReviewerReport(reviewer="malware_analyst",
                       findings=[_finding("high", "Bad thing 1")]),
        ReviewerReport(reviewer="red_team",
                       findings=[_finding("high", "Bad thing 2")]),
        ReviewerReport(reviewer="defensive",
                       findings=[_finding("medium", "Meh")]),
    ]
    ev = {
        "iocs": ["evil.com"], "mitre": [], "lolbins": [],
        "chain": ["base64-decode"], "input_preview": "x",
        "aggregate_family": None, "yara": [],
    }
    # Must NOT raise
    out = _synthesise(reports, ev)
    assert isinstance(out, dict)
    assert "consensus" in out
    # verdict_consensus entry should mention agreeing reviewers by name
    vc = [c for c in out["consensus"] if c.get("kind") == "verdict_consensus"]
    if vc:
        revs = vc[0].get("reviewers") or []
        assert "malware_analyst" in revs and "red_team" in revs


def test_synthesise_single_reviewer_still_returns_shape():
    reports = [ReviewerReport(reviewer="malware_analyst",
                              findings=[_finding("info", "note")])]
    ev = {"iocs": [], "mitre": [], "lolbins": [], "chain": [],
          "input_preview": "", "aggregate_family": None, "yara": []}
    out = _synthesise(reports, ev)
    assert isinstance(out, dict)
