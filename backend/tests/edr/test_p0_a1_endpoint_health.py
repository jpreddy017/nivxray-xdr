"""P0-A.1 · Endpoint health — two dimensions, never collapsed.

The rule under test: NO TELEMETRY != NO ATTACK. Every assertion here exists
to stop a visibility gap being reported as an all-clear.
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from services.edr.endpoint_health import (  # noqa: E402
    LIFECYCLE, NEVER_MEANS_BENIGN, TELEMETRY_HEALTH,
    resolve_agent_lifecycle, resolve_endpoint_health, resolve_telemetry_health)

NOW = datetime(2026, 6, 12, 12, 0, 0, tzinfo=timezone.utc)


def _ago(seconds: int) -> str:
    return (NOW - timedelta(seconds=seconds)).isoformat()


def _agent(**kw):
    base = {"agent_id": "ag-1", "last_heartbeat_at": _ago(30),
            "lifecycle_reported": "CONNECTED"}
    base.update(kw)
    return base


# ── the enumerations are the owner-locked sets ────────────────────
def test_both_enumerations_are_the_locked_sets():
    assert LIFECYCLE == (
        "INITIALIZING", "PROVISIONING", "PROVISIONING_FAILED_RETRYING",
        "REGISTERING", "REGISTRATION_FAILED_RETRYING", "CONNECTING",
        "CONNECTION_FAILED_RETRYING", "CONNECTED", "DISABLED",
        "DISCONNECTED_RETRYING", "OFFLINE", "NO_AGENT")
    assert TELEMETRY_HEALTH == (
        "ONLINE", "DEGRADED", "STALE", "NO_TELEMETRY", "AGENT_ERROR",
        "PARSER_ERROR", "ISOLATED", "UNENROLLED", "NEVER_ENROLLED")


# ── dimension A · agent lifecycle ─────────────────────────────────
def test_no_agent_is_not_offline():
    """OFFLINE claims an agent exists and is unreachable. With no agent
    record that is a stronger claim than the evidence supports."""
    a = resolve_agent_lifecycle(None, now=NOW)
    assert a["state"] == "NO_AGENT"
    assert a["state"] != "OFFLINE"


def test_lifecycle_transitions_on_heartbeat_age():
    assert resolve_agent_lifecycle(_agent(last_heartbeat_at=_ago(30)),
                                    now=NOW)["state"] == "CONNECTED"
    assert resolve_agent_lifecycle(_agent(last_heartbeat_at=_ago(600)),
                                    now=NOW)["state"] == "DISCONNECTED_RETRYING"
    assert resolve_agent_lifecycle(_agent(last_heartbeat_at=_ago(7200)),
                                    now=NOW)["state"] == "OFFLINE"
    assert resolve_agent_lifecycle(_agent(last_heartbeat_at=None),
                                    now=NOW)["state"] == "REGISTERING"


def test_agent_self_reported_state_wins():
    for reported in ("DISABLED", "PROVISIONING_FAILED_RETRYING",
                      "REGISTRATION_FAILED_RETRYING", "CONNECTING"):
        a = resolve_agent_lifecycle(
            _agent(lifecycle_reported=reported, last_heartbeat_at=_ago(9999)),
            now=NOW)
        assert a["state"] == reported, reported


# ── dimension B · telemetry health ────────────────────────────────
def test_connected_agent_that_sends_nothing_is_no_telemetry():
    """The exact case a single collapsed status field would hide."""
    h = resolve_endpoint_health(agent=_agent(), last_telemetry_at=None,
                                observation_count=0, now=NOW)
    assert h["agent_lifecycle"]["state"] == "CONNECTED"
    assert h["telemetry_health"]["state"] == "NO_TELEMETRY"
    assert h["visibility"]["state"] == "NONE"


def test_offline_agent_can_still_have_historic_evidence():
    h = resolve_endpoint_health(agent=_agent(last_heartbeat_at=_ago(7200)),
                                last_telemetry_at=_ago(60),
                                observation_count=42, now=NOW)
    assert h["agent_lifecycle"]["state"] == "OFFLINE"
    assert h["telemetry_health"]["state"] == "ONLINE"


def test_precedence_of_the_consequential_unknowns():
    def s(**kw):
        return resolve_telemetry_health(now=NOW, **kw)["state"]

    assert s(agent=None, last_telemetry_at=None) == "NEVER_ENROLLED"
    assert s(agent=_agent(revoked_at=_ago(10)),
             last_telemetry_at=_ago(10)) == "UNENROLLED"
    assert s(agent=_agent(), last_telemetry_at=_ago(10),
             isolated=True) == "ISOLATED"
    assert s(agent=_agent(agent_error="sensor load failed"),
             last_telemetry_at=_ago(10)) == "AGENT_ERROR"
    assert s(agent=_agent(), last_telemetry_at=None,
             parser_failures=5) == "PARSER_ERROR"
    assert s(agent=_agent(), last_telemetry_at=_ago(10),
             parser_failures=3, observation_count=2) == "PARSER_ERROR"
    assert s(agent=_agent(), last_telemetry_at=_ago(7200),
             observation_count=2) == "STALE"
    assert s(agent=_agent(), last_telemetry_at=_ago(1200),
             observation_count=2) == "DEGRADED"
    assert s(agent=_agent(), last_telemetry_at=_ago(10),
             dropped_events=4, observation_count=2) == "DEGRADED"
    assert s(agent=_agent(), last_telemetry_at=_ago(10),
             observation_count=2) == "ONLINE"


def test_isolation_is_not_reported_as_a_fault():
    h = resolve_telemetry_health(agent=_agent(), last_telemetry_at=_ago(10),
                                  isolated=True, now=NOW)
    assert h["state"] == "ISOLATED"
    assert "not a fault" in h["reason"]


def test_parser_failure_states_raw_evidence_is_retained():
    h = resolve_telemetry_health(agent=_agent(), last_telemetry_at=None,
                                  parser_failures=7, now=NOW)
    assert "retained and replayable" in h["reason"]


# ── the frozen rule ───────────────────────────────────────────────
def test_no_telemetry_never_reads_as_benign():
    for state, kw in (
        ("NEVER_ENROLLED", {"agent": None, "last_telemetry_at": None}),
        ("NO_TELEMETRY", {"agent": _agent(), "last_telemetry_at": None}),
        ("STALE", {"agent": _agent(), "last_telemetry_at": _ago(7200),
                    "observation_count": 1}),
    ):
        h = resolve_telemetry_health(now=NOW, **kw)
        assert h["state"] == state
        assert h["note"] == NEVER_MEANS_BENIGN
        assert "not evidence that nothing happened" in h["note"]
        assert "security verdict is unchanged" in h["note"]


def test_evidence_sufficiency_is_independent_of_verdict():
    h = resolve_telemetry_health(agent=_agent(), last_telemetry_at=None,
                                  now=NOW)
    assert h["evidence_sufficiency"] == "INSUFFICIENT"
    # This module must not express a security opinion at all.
    assert "verdict" not in h
    assert "malicious" not in str(h).lower()
    assert "benign" not in str(h["state"]).lower()


def test_visibility_none_names_what_is_affected():
    h = resolve_endpoint_health(agent=None, last_telemetry_at=None, now=NOW)
    v = h["visibility"]
    assert v["state"] == "NONE"
    assert "visibility gap" in v["statement"]
    assert "process ancestry" in v["affects"]
    assert "file hashes" in v["affects"]


def test_dimensions_are_declared_independent_and_thresholds_are_stated():
    h = resolve_endpoint_health(agent=_agent(), last_telemetry_at=_ago(10),
                                observation_count=1, now=NOW)
    assert "never collapsed" in h["dimensions_note"]
    assert h["thresholds"] == {"heartbeat_grace_s": 300, "offline_s": 1800,
                                "telemetry_degraded_s": 900,
                                "telemetry_stale_s": 3600}
