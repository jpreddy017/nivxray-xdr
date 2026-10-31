"""B5-GAP-1 GATE C · ACQUISITION INTEGRITY, as platform-held evidence.

Why a separate contract rather than extra heartbeat fields
----------------------------------------------------------
`HeartbeatBody` and `TelemetryBody` are both `extra="forbid"`. Injecting
integrity fields into either would return 422 for every production sensor
still running the previous build. So this is its OWN versioned report with
its own model, and every existing payload shape is untouched.

What it is for
--------------
Before this, the platform could not tell these apart:

    "this endpoint observed no activity in that interval"
    "this endpoint failed to observe part of the source stream"

The first is evidence. The second is a hole. Treating them alike is how
B5-GAP-1 stayed invisible for weeks while the sensor reported healthy.

What it must never do
---------------------
An acquisition gap is a SOURCE CONTINUITY FACT. It is not a detection, it
is not benign, and it is not malicious. The stored classification stays
`SOURCE_RECORD_DISCONTINUITY` and the stored cause stays `NOT_PROVEN`
unless some other evidence independently proves a cause; this module
refuses any other value rather than accepting a sensor's claim.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

CONTRACT = "nivxforge.acquisition_integrity"
CONTRACT_VERSION = 1

REPORTS = "edr_acquisition_integrity"
GAPS = "edr_acquisition_gaps"

#: The ONLY classification this surface stores for a RecordID discontinuity.
DISCONTINUITY = "SOURCE_RECORD_DISCONTINUITY"
#: The ONLY cause a SENSOR may assert. A cause is an analytic conclusion and
#: a sensor is not in a position to reach one: it saw an absence, not a
#: reason. Anything else presented here is refused and rewritten to this.
CAUSE_NOT_PROVEN = "NOT_PROVEN"

#: Health vocabulary the console may render. Kept as a closed set so a
#: sensor cannot invent a reassuring state.
HEALTH_STATES = (
    "HEALTHY", "DEGRADED", "ACQUISITION_LAGGING", "ACQUISITION_GAP",
    "ACQUISITION_HALTED_JOURNAL_FULL", "JOURNAL_PRESSURE",
    "JOURNAL_CRITICAL", "JOURNAL_CORRUPT", "DELIVERY_BACKLOG",
    "BACKEND_UNREACHABLE", "CHANNEL_UNAVAILABLE", "SOURCE_ROLLOVER_RISK",
)

#: Absence semantics, stored ALONGSIDE every gap so no later reader has to
#: remember them. Directive §13 / negative-evidence invariants.
SEMANTICS = {
    "no_event_observed_is_not_event_did_not_occur": True,
    "acquisition_gap_is_not_benign": True,
    "acquisition_gap_is_not_malicious": True,
    "acquisition_gap_is_not_a_detection": True,
    "note": ("A source RecordID discontinuity proves that part of the "
             "source stream was not observed. It does not prove that every "
             "missing RecordID carried a security event, and it does not "
             "prove a cause."),
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def normalise_gap(gap: dict, *, tenant_id: str, endpoint_id: str) -> dict:
    """Server-side truth for one declared gap.

    Every analytic field is set HERE, from the closed vocabulary, never
    copied from the sensor's request. `missing_record_id_count` is
    RECOMPUTED from the two RecordIDs so a sensor cannot overstate a hole.
    """
    expected = _int(gap.get("expected_next_record_id"))
    first = _int(gap.get("first_observed_record_id"))
    count = (first - expected) if (expected is not None
                                   and first is not None
                                   and first > expected) else 0
    return {
        "contract": CONTRACT,
        "contract_version": CONTRACT_VERSION,
        "tenant_id": tenant_id,
        "endpoint_id": endpoint_id,
        "channel": str(gap.get("channel") or "")[:200],
        "position": ("INTERIOR" if str(gap.get("position")).upper()
                     == "INTERIOR" else "LEADING"),
        "expected_next_record_id": expected,
        "first_observed_record_id": first,
        "missing_start_record_id": expected,
        "missing_end_record_id": (first - 1) if first is not None else None,
        "missing_record_id_count": count,
        "detected_at": str(gap.get("detected_at") or _now())[:64],
        # Server-asserted, never sensor-asserted.
        "classification": DISCONTINUITY,
        "cause": CAUSE_NOT_PROVEN,
        "is_detection": False,
        "semantics": SEMANTICS,
        "recorded_at": _now(),
    }


def _states(raw_states: Any) -> list[str]:
    if not isinstance(raw_states, list):
        return []
    return [s for s in (str(x) for x in raw_states) if s in HEALTH_STATES]


async def record(db: Any, *, tenant_id: str, endpoint_id: str,
                 sensor_version: str | None, report: dict) -> dict:
    """Store one integrity report and any gaps it declares.

    The report is the LATEST per (tenant, endpoint, channel): it is a gauge,
    so keeping every sample would be noise. The GAPS are append-only,
    because each one is a distinct, permanent statement about evidence that
    was never acquired.
    """
    now = _now()
    channels = report.get("channels") or {}
    stored_channels = []
    for name, ch in channels.items():
        doc = {
            "contract": CONTRACT,
            "contract_version": CONTRACT_VERSION,
            "tenant_id": tenant_id,
            "endpoint_id": endpoint_id,
            "channel": str(name)[:200],
            "sensor_version": sensor_version,
            "reported_at": str(report.get("at") or now)[:64],
            "received_at": now,
            "last_record_id_read": _int(ch.get("last_record_id_read")),
            "last_record_id_journaled": _int(
                ch.get("last_record_id_journaled")),
            "last_cursor_committed": _int(ch.get("last_cursor_committed")),
            "records_read": _int(ch.get("records_read")),
            "records_journaled": _int(ch.get("records_journaled")),
            "query_failures": _int(ch.get("query_failures")),
            "query_timeouts": _int(ch.get("query_timeouts")),
            "query_ms_last": _int(ch.get("query_ms_last")),
            "acquisition_lag_records": _int(
                ch.get("acquisition_lag_records")),
            "source_oldest_record_id": _int(
                ch.get("source_oldest_record_id")),
            "source_newest_record_id": _int(
                ch.get("source_newest_record_id")),
            "caught_up": (bool(ch.get("caught_up"))
                          if ch.get("caught_up") is not None else None),
            "unavailable_reason": (str(ch["unavailable_reason"])[:300]
                                   if ch.get("unavailable_reason") else None),
            # endpoint-wide, repeated per channel row so one query answers
            # "was this interval trustworthy for this channel?"
            "acquisition_gap_count": _int(report.get(
                "acquisition_gap_count")),
            "journal_depth": _int(report.get("journal_depth")),
            "journal_bytes": _int(report.get("journal_bytes")),
            "journal_live_bytes": _int(report.get("journal_live_bytes")),
            "delivery_backlog": _int(report.get("delivery_backlog")),
            "health_states": _states(report.get("health_states")),
            #: A SENSOR CLAIM about its own acquisition, never a server
            #: measurement and never an evidence authority.
            "claim_basis": "SENSOR_REPORTED",
        }
        await db[REPORTS].update_one(
            {"tenant_id": tenant_id, "endpoint_id": endpoint_id,
             "channel": doc["channel"]},
            {"$set": doc}, upsert=True)
        stored_channels.append(doc["channel"])

    gaps = [g for g in (report.get("acquisition_gaps") or [])
            if isinstance(g, dict)]
    recorded = 0
    for gap in gaps:
        doc = normalise_gap(gap, tenant_id=tenant_id, endpoint_id=endpoint_id)
        if doc["missing_record_id_count"] <= 0:
            continue                       # nothing is missing; not a gap
        # Idempotent: the same declared discontinuity re-sent after a
        # delivery retry must not become two holes in the record.
        result = await db[GAPS].update_one(
            {"tenant_id": tenant_id, "endpoint_id": endpoint_id,
             "channel": doc["channel"],
             "expected_next_record_id": doc["expected_next_record_id"],
             "first_observed_record_id": doc["first_observed_record_id"]},
            {"$setOnInsert": doc}, upsert=True)
        recorded += 1 if result.upserted_id else 0
    return {"channels_recorded": stored_channels,
            "gaps_declared": len(gaps), "gaps_newly_recorded": recorded,
            "contract": CONTRACT, "contract_version": CONTRACT_VERSION}


async def list_reports(db: Any, *, tenant_id: str,
                       endpoint_id: str | None = None,
                       limit: int = 200) -> list[dict]:
    query: dict = {"tenant_id": tenant_id}
    if endpoint_id:
        query["endpoint_id"] = endpoint_id
    return await db[REPORTS].find(query, {"_id": 0}).sort(
        "received_at", -1).to_list(int(limit))


async def list_gaps(db: Any, *, tenant_id: str,
                    endpoint_id: str | None = None,
                    limit: int = 200) -> list[dict]:
    query: dict = {"tenant_id": tenant_id}
    if endpoint_id:
        query["endpoint_id"] = endpoint_id
    return await db[GAPS].find(query, {"_id": 0}).sort(
        "detected_at", -1).to_list(int(limit))
