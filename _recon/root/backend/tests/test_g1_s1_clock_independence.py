"""G1/S1 · the three transport clocks must stay three clocks.

The defect this suite pins: `transport_stamps()` derived
`sensor_observed_at` from `envelope.source_timestamp` alone. For the native
Windows Event Log adapter that field carries the event's OWN instant
(`EventData.UtcTime` / `System.TimeCreated`), so ACTIVITY and SENSOR
OBSERVATION became one value wearing two labels — and because
`ingest_provenance.apply()` only ever *improves* a boundary, nothing
downstream could ever correct it.

The contract now:

    activity_occurred_at   when Windows says it happened      (DSM owns)
    sensor_observed_at     when NivXForge observed/acquired it (declared)
    nivx_received_at       when NivXRay accepted it            (HTTP receipt)

A missing sensor observation stays unavailable. It is never back-filled
from the activity clock, because two clocks that are the same value are not
two clocks.

TEST/SYNTHETIC — every envelope here is constructed. No live Windows host is
connected and nothing here touches production.
"""
from __future__ import annotations

from services import ingest_provenance as ing
from services import provenance_timestamps as pts

ACTIVITY = "2026-06-01T09:59:58.120000+00:00"
SENSOR = "2026-06-01T10:00:01.000000+00:00"
NIVX_RECV = "2026-06-01T10:00:03.500000+00:00"


def windows_envelope(**over):
    """The envelope the native adapter actually builds
    (`framework/windows_eventlog.py` :: collect)."""
    env = {
        "tenant_id": "t-s1", "collector_id": "col_s1",
        "collection_method": "windows-eventlog",
        "source": "sysmon", "declared_source": "sysmon",
        "source_timestamp": ACTIVITY,          # the ACTIVITY clock
        "collection_timestamp": SENSOR,        # the SENSOR clock
        "raw": {"xml": "<Event/>", "channel": "Microsoft-Windows-Sysmon/Operational"},
        "canonical": {
            "activity_occurred_at": ACTIVITY,
            "activity_time_source": "EventData.UtcTime",
            "sensor_observed_at": SENSOR,
        },
    }
    env.update(over)
    return env


def stamps(env):
    return ing.transport_stamps(env, nivx_received_at=NIVX_RECV)


# ── 1 · activity != sensor observation ───────────────────────────────
def test_activity_clock_never_becomes_the_sensor_observation():
    s = stamps(windows_envelope())
    assert s["sensor_observed_at"]["status"] == pts.AVAILABLE
    assert s["sensor_observed_at"]["value"] == SENSOR
    assert s["sensor_observed_at"]["value"] != ACTIVITY
    assert s["sensor_observed_at"]["source"] == (
        "collector:envelope.canonical.sensor_observed_at")


# ── 2 · sensor observation != ingest ─────────────────────────────────
def test_sensor_observation_and_ingest_receipt_stay_distinct():
    s = stamps(windows_envelope())
    assert s["nivx_received_at"]["value"] == NIVX_RECV
    assert s["sensor_observed_at"]["value"] != s["nivx_received_at"]["value"]
    assert s["nivx_received_at"]["source"] == (
        "ingest:http receipt POST /api/xdr/ingest/telemetry")
    # three boundaries, three different values — the whole point
    assert len({s["sensor_observed_at"]["value"],
                s["collector_received_at"]["value"],
                s["nivx_received_at"]["value"]}) >= 2
    assert ACTIVITY not in {s["sensor_observed_at"]["value"],
                            s["nivx_received_at"]["value"]}


# ── 3 · a declared sensor observation survives provenance processing ─
def test_declared_sensor_observation_survives_apply():
    canonical: dict = {}
    ing.apply(canonical, stamps(windows_envelope()))
    ts = canonical["provenance"]["timestamps"]
    assert ts["sensor_observed_at"]["value"] == SENSOR
    # a later producer offering the activity value cannot demote or
    # overwrite a measured observation
    ing.apply(canonical, {"sensor_observed_at": pts.stamp(
        ACTIVITY, source="dsm:guess")})
    assert canonical["provenance"]["timestamps"][
        "sensor_observed_at"]["value"] == SENSOR


# ── 4 · activity may not silently populate the sensor boundary ───────
def test_activity_declaration_without_sensor_stays_unavailable():
    env = windows_envelope()
    env["canonical"].pop("sensor_observed_at")
    s = stamps(env)
    assert s["sensor_observed_at"]["status"] == pts.NOT_OBSERVED
    assert s["sensor_observed_at"]["value"] is None
    assert "activity clock" in s["sensor_observed_at"]["reason"]
    assert "activity_time_source" in s["sensor_observed_at"]["reason"]


def test_activity_equality_alone_also_blocks_the_substitution():
    """Even with no `activity_time_source`, an envelope whose
    `activity_occurred_at` IS its `source_timestamp` has declared that field
    to be the activity clock."""
    env = windows_envelope()
    env["canonical"].pop("sensor_observed_at")
    env["canonical"].pop("activity_time_source")
    s = stamps(env)
    assert s["sensor_observed_at"]["status"] == pts.NOT_OBSERVED
    assert "activity_occurred_at" in s["sensor_observed_at"]["reason"]


# ── 5 · missing sensor observation remains truthfully unavailable ────
def test_no_clock_at_all_is_not_invented():
    s = stamps({"tenant_id": "t-s1", "collector_id": "col_s1",
                "collection_method": "windows-eventlog", "raw": {}})
    assert s["sensor_observed_at"]["status"] == pts.NOT_OBSERVED
    assert s["collector_received_at"]["status"] == pts.NOT_OBSERVED
    assert s["nivx_received_at"]["status"] == pts.AVAILABLE


def test_unusable_declared_sensor_is_missing_and_names_its_field():
    env = windows_envelope()
    env["canonical"]["sensor_observed_at"] = "not-a-time"
    s = stamps(env)
    assert s["sensor_observed_at"]["status"] == pts.MISSING
    assert s["sensor_observed_at"]["source"] == (
        "collector:envelope.canonical.sensor_observed_at")
    # and it still does not fall back to the activity clock
    assert s["sensor_observed_at"]["value"] is None


# ── 6 · non-Windows producers are unchanged ──────────────────────────
def test_generic_collector_still_reads_source_timestamp_as_the_sensor():
    """syslog / webhook / REST producers do not know the difference between
    the two clocks and declare neither. For them `source_timestamp` remains
    the source's observation, exactly as before S1."""
    s = stamps({"tenant_id": "t-s1", "collector_id": "col_s1",
                "collection_method": "syslog",
                "source_timestamp": SENSOR,
                "received_at": NIVX_RECV, "raw": {"line": "x"}})
    assert s["sensor_observed_at"]["status"] == pts.AVAILABLE
    assert s["sensor_observed_at"]["value"] == SENSOR
    assert s["sensor_observed_at"]["source"] == (
        "collector:envelope.source_timestamp")


def test_declared_activity_clock_helper_is_explicit():
    assert ing.declared_activity_clock(windows_envelope()) == (
        "canonical.activity_time_source")
    assert ing.declared_activity_clock(
        {"source_timestamp": SENSOR, "canonical": {}}) is None
    assert ing.declared_activity_clock({}) is None
