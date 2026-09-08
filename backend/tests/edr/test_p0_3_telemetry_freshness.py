"""P0-3 regression guard · blindness/staleness derivation.

These pin the DERIVATION, not the wiring — the wiring is proven live by
`scripts/p0_3_sensor_recovery_proof.py`. What must never silently change:

  * thresholds come from the sensor's own cadence, never a constant;
  * `DELIVERING` / `STALE` / `BLIND_NO_DELIVERY` boundaries;
  * a live link and a lost link are distinguishable while both are STALE;
  * never-delivered, delivery-ceased and revoked are three different facts;
  * a heartbeat is never allowed to become evidence;
  * re-enrolment never resets the delivery record.
"""
from __future__ import annotations

import inspect
from datetime import datetime, timedelta, timezone

from edr_plane.enrollment import store
from edr_plane.enrollment.identity import EndpointRecord
from services.edr import endpoint_health as h

NOW = datetime(2026, 9, 8, 12, 0, 0, tzinfo=timezone.utc)


def _at(seconds_ago: float) -> str:
    return (NOW - timedelta(seconds=seconds_ago)).isoformat()


def _fresh(**kw):
    kw.setdefault("last_telemetry_at", _at(1))
    kw.setdefault("report_interval_seconds", 15)
    kw.setdefault("now", NOW)
    return h.resolve_delivery_freshness(**kw)


def test_thresholds_are_derived_from_the_declared_cadence():
    slow = h.delivery_thresholds(600)
    assert slow["cadence_basis"] == h.CADENCE_DECLARED
    assert slow["stale_after_s"] == 600 * h.MISSED_CYCLES_STALE
    assert slow["blind_after_s"] == 600 * h.MISSED_CYCLES_BLIND
    fast = h.delivery_thresholds(1)
    # Floors, so a very fast sensor cannot make the console flap.
    assert fast["stale_after_s"] == h.MIN_STALE_S
    assert fast["blind_after_s"] == h.MIN_BLIND_S


def test_an_undeclared_cadence_says_so_and_never_pretends_to_be_measured():
    t = h.delivery_thresholds(None)
    assert t["cadence_basis"] == h.CADENCE_NOT_DECLARED
    assert t["report_interval_s"] == h.POLICY_FALLBACK_INTERVAL_S


def test_the_formula_travels_with_every_answer():
    assert "max(report_interval_s" in _fresh()["thresholds"]["formula"]


def test_delivering_stale_blind_boundaries():
    t = h.delivery_thresholds(15)
    assert _fresh(last_telemetry_at=_at(t["stale_after_s"]))["state"] \
        == "DELIVERING"
    assert _fresh(last_telemetry_at=_at(t["stale_after_s"] + 1))["state"] \
        == "STALE"
    assert _fresh(last_telemetry_at=_at(t["blind_after_s"]))["state"] \
        == "STALE"
    assert _fresh(last_telemetry_at=_at(t["blind_after_s"] + 1))["state"] \
        == "BLIND_NO_DELIVERY"


def test_a_live_link_and_a_lost_link_are_distinguishable_while_both_stale():
    late = _at(200)
    alive = _fresh(last_telemetry_at=late, last_heartbeat_at=_at(5))
    gone = _fresh(last_telemetry_at=late, last_heartbeat_at=_at(5000))
    assert alive["state"] == gone["state"] == "STALE"
    assert alive["basis"] == "LINK_ALIVE_NO_NEW_EVIDENCE"
    assert alive["link_confirmed"] is True
    assert gone["basis"] == "DELIVERY_LATE_LINK_UNCONFIRMED"
    assert gone["link_confirmed"] is False


def test_a_sensor_that_is_alive_and_behind_is_backlogged_not_silent():
    """A backlog is not an absence of evidence, and saying "no new
    evidence" about a sensor that is still sending would be false."""
    behind = _fresh(last_telemetry_at=_at(200), last_heartbeat_at=_at(5),
                    queue_depth=412)
    assert behind["state"] == "STALE"
    assert behind["basis"] == "DELIVERY_BACKLOGGED_AT_SENSOR"
    assert behind["queue_depth"] == 412
    assert "DELAYED, not absent" in behind["statement"]
    # An empty queue on a live link is genuinely "no new evidence".
    assert _fresh(last_telemetry_at=_at(200), last_heartbeat_at=_at(5),
                  queue_depth=0)["basis"] == "LINK_ALIVE_NO_NEW_EVIDENCE"
    # A backlog reported by a sensor whose link is NOT confirmed cannot
    # soften the answer.
    assert _fresh(last_telemetry_at=_at(200), last_heartbeat_at=_at(5000),
                  queue_depth=412)["basis"] \
        == "DELIVERY_LATE_LINK_UNCONFIRMED"


def test_the_heartbeat_is_sent_before_the_drain():
    """Liveness must not depend on evidence throughput. Sending the
    heartbeat after the drain meant a large backlog delayed the sensor's
    own liveness signal past the staleness threshold."""
    import pathlib
    src = pathlib.Path(
        "/app/agents/nivxforge-linux/nivxforge_sensor.py").read_text()
    loop = src.split("    while True:")[1]
    assert loop.index("_heartbeat(") < loop.index("_drain("), (
        "the heartbeat must be sent BEFORE the drain")


def test_never_delivered_is_not_the_same_fact_as_delivery_ceased():
    never = _fresh(last_telemetry_at=None)
    ceased = _fresh(last_telemetry_at=_at(100000))
    assert never["state"] == ceased["state"] == "BLIND_NO_DELIVERY"
    assert never["basis"] == "NEVER_DELIVERED"
    assert ceased["basis"] == "DELIVERY_CEASED"


def test_a_revoked_credential_is_stated_as_such_not_as_a_fault():
    r = _fresh(last_telemetry_at=_at(1), revoked_at=_at(10))
    assert r["state"] == "BLIND_NO_DELIVERY"
    assert r["basis"] == "CREDENTIAL_REVOKED"


def test_blindness_is_never_presented_as_an_all_clear():
    for kw in ({"last_telemetry_at": None},
               {"last_telemetry_at": _at(200)},
               {"last_telemetry_at": _at(100000)}):
        assert "NOT a statement that nothing is happening" in _fresh(**kw)["note"]
    assert _fresh()["note"] is None


def test_every_state_token_is_declared():
    assert set(h.DELIVERY_STATES) == {"DELIVERING", "STALE",
                                      "BLIND_NO_DELIVERY"}
    for kw in ({}, {"last_telemetry_at": None},
               {"last_telemetry_at": _at(200)}):
        assert _fresh(**kw)["state"] in h.DELIVERY_STATES


def test_a_heartbeat_may_never_become_evidence():
    src = inspect.getsource(store.mark_heartbeat)
    # The docstring legitimately NAMES what it must not do, so only the
    # executable body is checked.
    body = src.split('"""')[2]
    # Only a WRITE is forbidden — the honest note legitimately names the
    # fields it does not touch.
    for forbidden in ('"last_telemetry_at":', '"event_count":', "$inc"):
        assert forbidden not in body, (
            f"mark_heartbeat touches {forbidden}: a heartbeat that counted "
            f"as delivery would make a silent endpoint look healthy")


def test_reenrolment_never_resets_the_delivery_record():
    src = inspect.getsource(store.enroll)
    assert "$setOnInsert" in src
    for field in ("sensor_state", "last_telemetry_at", "event_count",
                  "last_heartbeat_at", "report_interval_seconds",
                  "cadence_basis", "lifecycle_reported"):
        assert field in src, f"{field} must be partitioned out of $set"
        assert field in EndpointRecord.model_fields


def test_the_freshness_projection_delegates_and_invents_nothing():
    from services.edr import telemetry_freshness as tf
    src = inspect.getsource(tf)
    assert "resolve_delivery_freshness" in src
    # No second threshold policy may exist in the projection layer.
    for token in ("stale_after", "blind_after", "MISSED_CYCLES"):
        assert f"{token} =" not in src
