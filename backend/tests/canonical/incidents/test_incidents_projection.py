"""Incidents API projection & lifecycle contract tests.

Locks:
  - `workspace_cases` is projected into the Incident row/detail shape
    deterministically (same doc → same projection).
  - Lifecycle state machine allows only whitelisted transitions and
    persists a history entry per transition.
  - Priority derivation is evidence-backed (Stage-2 > v3.x > unknown).
"""
from __future__ import annotations

import sys
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[3]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from routers.incidents import (  # noqa: E402
    _project_row, _project_detail, _derive_priority,
    _derive_severity, _short_number,
    LIFECYCLE_STATES, LIFECYCLE_TRANSITIONS,
)


# ── Helpers ──────────────────────────────────────────────────────────
def _case(**overrides):
    base = {
        "id":         "case-abc-def-1234",
        "name":       "PrivacyBrowse",
        "user_email": "analyst@nivxray.com",
        "created_at": "2026-08-26T10:00:00+00:00",
        "updated_at": "2026-08-26T10:30:00+00:00",
        "input":      "powershell.exe -Enc SQBFAFg=",
    }
    base.update(overrides)
    return base


# ── Priority derivation ──────────────────────────────────────────────
def test_priority_from_stage2_malicious_high_risk():
    code, label = _derive_priority(
        {"label": "malicious", "risk_score": 95}, None,
    )
    assert code == "P1"
    assert label == "Critical"


def test_priority_from_stage2_malicious_medium_risk():
    code, _ = _derive_priority(
        {"label": "malicious", "risk_score": 55}, None,
    )
    assert code == "P2"


def test_priority_from_stage2_suspicious():
    code, _ = _derive_priority({"label": "suspicious", "risk_score": 40}, None)
    assert code == "P3"


def test_priority_from_stage2_benign():
    code, _ = _derive_priority({"label": "benign"}, None)
    assert code == "P4"


def test_priority_falls_back_to_verdict_card_when_stage2_absent():
    code, _ = _derive_priority(None, {"verdict": "Malicious", "confidence": 90})
    assert code == "P1"


def test_priority_unknown_when_no_verdict():
    code, label = _derive_priority(None, None)
    assert code == "P5"
    assert label == "Info"


# ── Severity ─────────────────────────────────────────────────────────
def test_severity_prefers_stage2_label():
    assert _derive_severity({"label": "malicious"},
                              {"verdict": "benign"}) == "malicious"


def test_severity_falls_back_to_verdict_card():
    assert _derive_severity(None, {"verdict": "Suspicious"}) == "suspicious"


def test_severity_unknown_by_default():
    assert _derive_severity(None, None) == "unknown"


# ── Number ───────────────────────────────────────────────────────────
def test_short_number_deterministic():
    n1 = _short_number("case-abc-def-1234")
    n2 = _short_number("case-abc-def-1234")
    assert n1 == n2
    assert n1.startswith("INC-")
    assert len(n1) == 10  # INC- + 6 hex chars


def test_short_number_when_id_missing():
    assert _short_number(None) == "INC-000000"


# ── Row projection ───────────────────────────────────────────────────
def test_row_projection_shape():
    row = _project_row(_case(
        verdict_stage2={"label": "malicious",
                          "confidence_bucket": "high",
                          "risk_score": 95},
    ))
    for key in ("id", "number", "name", "priority", "severity",
                  "verdict", "tenant", "assignee", "state",
                  "updated_at", "created_at"):
        assert key in row
    assert row["priority"]["code"] == "P1"
    assert row["severity"] == "malicious"
    assert row["state"] == "new"  # default
    assert row["assignee"] == "analyst@nivxray.com"  # falls back to user_email
    assert row["tenant"] == "analyst@nivxray.com"


def test_row_projection_respects_explicit_state_and_assignee():
    row = _project_row(_case(
        incident_state="in_progress",
        incident_assignee="soc-lead@nivxray.com",
    ))
    assert row["state"] == "in_progress"
    assert row["assignee"] == "soc-lead@nivxray.com"


# ── Detail projection ────────────────────────────────────────────────
def test_detail_projection_includes_evidence_pointers():
    detail = _project_detail(_case(
        verdict_stage2={"label": "malicious", "risk_score": 95,
                          "confidence_bucket": "high"},
    ))
    assert detail["number"].startswith("INC-")
    assert isinstance(detail["evidence_pointers"], list)
    # 9 canonical domains: edr · ndr · identity · cloud · email ·
    # app_api · data_security · ctem · ioc
    assert len(detail["evidence_pointers"]) == 9
    domains = {p["domain"] for p in detail["evidence_pointers"]}
    assert domains == {"edr", "ndr", "identity", "cloud", "email",
                          "app_api", "data_security", "ctem", "ioc"}
    # NivXForge EDR pointer resolves to the real trajectory page and
    # passes the incident context as URL params (navigation hints only).
    edr = next(p for p in detail["evidence_pointers"] if p["domain"] == "edr")
    assert edr["status"] == "available"
    assert edr["deep_link"].startswith("/edr/trajectory?")
    assert "incident_id=" in edr["deep_link"]
    # NDR / Identity / Cloud / Email / Application-API / Data Security
    # / CTEM are honestly reported as not_connected.
    for dom in ("ndr", "identity", "cloud", "email", "app_api",
                  "data_security", "ctem"):
        p = next(pt for pt in detail["evidence_pointers"] if pt["domain"] == dom)
        assert p["status"] == "not_connected"
        assert p["deep_link"] is None
        assert p["reason"]  # must have a human-readable reason


def test_detail_projection_never_leaks_ssot_bundle():
    detail = _project_detail(_case(ssot={"very": "large", "bundle": [1, 2, 3]}))
    assert "ssot" not in detail


def test_detail_state_history_defaults_to_empty():
    detail = _project_detail(_case())
    assert detail["state_history"] == []


# ── Lifecycle machine ────────────────────────────────────────────────
def test_lifecycle_states_are_exactly_five_and_deterministic():
    assert LIFECYCLE_STATES == (
        "new", "in_progress", "on_hold", "resolved", "closed",
    )


def test_lifecycle_transitions_new():
    assert set(LIFECYCLE_TRANSITIONS["new"]) == {"in_progress", "on_hold", "closed"}


def test_lifecycle_transitions_closed_is_terminal():
    assert LIFECYCLE_TRANSITIONS["closed"] == ()


def test_lifecycle_transitions_reject_new_to_resolved_directly():
    # An analyst must pass through in_progress before resolving.
    assert "resolved" not in LIFECYCLE_TRANSITIONS["new"]
