"""B5-GAP-1 GATE B/C · batch ingest + acquisition integrity BACKEND contract.

Two things must hold at once here: the new surfaces must work, and every
existing sensor payload shape must keep working byte-for-byte. A backend
that gains batching by breaking `TelemetryBody` would take the fleet
offline, which is why backward compatibility is asserted first.

EVIDENCE LABELLING — TEST/SYNTHETIC. No live telemetry, no production
query, no endpoint contact.
"""
from __future__ import annotations

import json

import pytest
from edr_plane import acquisition_integrity as acq
from fastapi import HTTPException
from pydantic import ValidationError
from routers import edr_enrollment as e
from routers.edr_tenancy import ROUTE_CLASSIFICATION, SENSOR_SCOPED

SYSMON = "Microsoft-Windows-Sysmon/Operational"


def _payload(record_id: int, event_id: int = 1) -> str:
    return json.dumps({
        "observed_at": "2026-06-01T10:05:00+00:00",
        "kind": "WINDOWS_EVENT_LOG",
        "winlog": {"channel": SYSMON, "record_id": record_id,
                   "event_id": str(event_id),
                   "provider": "Microsoft-Windows-Sysmon",
                   "computer": "NIVX-TEST", "xml": "<Event/>"},
    }, separators=(",", ":"))


# ═══════════ BACKWARD COMPATIBILITY — asserted FIRST ══════════════
def test_single_event_contract_is_unchanged():
    body = e.TelemetryBody(payload=_payload(1), source_kind="sensor",
                           sensor_version="0.2.0-windows",
                           report_interval_seconds=30.0)
    assert body.payload == _payload(1)
    assert set(e.TelemetryBody.model_fields) == {
        "payload", "event_time", "source_kind", "sensor_version",
        "report_interval_seconds"}, (
        "a field added here would change what every deployed sensor sends")


def test_unknown_fields_are_still_refused_on_both_surfaces():
    """`extra="forbid"` is the reason integrity could NOT be bolted onto the
    heartbeat. It must stay that way, on purpose."""
    with pytest.raises(ValidationError):
        e.TelemetryBody(payload="x", acquisition_gaps=[])
    with pytest.raises(ValidationError):
        e.HeartbeatBody(queue_depth=1, acquisition_gap_count=3)
    with pytest.raises(ValidationError):
        e.TelemetryBatchBody(events=[{"payload": "x"}], nonsense=True)
    with pytest.raises(ValidationError):
        e.AcquisitionIntegrityBody(channels={}, nonsense=True)


def test_new_routes_are_classified_for_tenant_authorization():
    """An unclassified route is a route the authorization matrix never
    probes — exactly how eight operations once drifted."""
    assert ROUTE_CLASSIFICATION[
        ("POST", "/api/edr/agent/telemetry/batch")] == SENSOR_SCOPED
    assert ROUTE_CLASSIFICATION[
        ("POST", "/api/edr/agent/acquisition-integrity")] == SENSOR_SCOPED
    assert ("GET", "/api/edr/enrollment/acquisition-integrity") \
        in ROUTE_CLASSIFICATION


def test_batch_body_carries_no_tenant_or_endpoint():
    """Identity comes from the authenticated session. A batch must not be
    able to attribute evidence to anyone else."""
    fields = set(e.TelemetryBatchBody.model_fields)
    assert "tenant_id" not in fields and "endpoint_id" not in fields


# ═══════════════════ GATE B · BATCH BOUNDS ════════════════════════
def test_batch_is_bounded():
    assert e.MAX_BATCH_EVENTS == 100
    with pytest.raises(ValidationError):
        e.TelemetryBatchBody(events=[])
    with pytest.raises(ValidationError):
        e.TelemetryBatchBody(
            events=[{"payload": "x"}] * (e.MAX_BATCH_EVENTS + 1))


@pytest.mark.asyncio
async def test_oversized_batch_refuses_everything_and_ingests_nothing(
        monkeypatch):
    """A 413 must leave the endpoint owning every event. A partial ingest
    with a whole-batch refusal would silently duplicate on retry."""
    ingested = []
    monkeypatch.setattr(e, "_ingest_one",
                        lambda **kw: ingested.append(kw))
    body = e.TelemetryBatchBody(events=[{"payload": "x" * 100_000}] * 50)
    with pytest.raises(HTTPException) as err:
        await e.ingest_batch(body, request=object(), who=object())
    assert err.value.status_code == 413
    assert err.value.detail["error"] == "BATCH_TOO_LARGE"
    assert ingested == [], "nothing may be ingested from a refused batch"


@pytest.mark.asyncio
async def test_batch_acceptance_is_per_event_and_ordered(monkeypatch):
    """The invariant batching is allowed under: one bad event does not
    release the others, and does not withhold them either."""
    calls = []

    async def _one(**kw):
        calls.append(kw["payload"])
        if "record_id\": 2" in kw["payload"].replace('"record_id":',
                                                     '"record_id": '):
            raise RuntimeError("mongo write failed")
        return {"stored": True, "duplicate": False,
                "raw_id": f"raw_{len(calls)}",
                "canonical": {"canonicalized": True}}

    reported = []
    monkeypatch.setattr(e, "_ingest_one", _one)

    async def _mark(*a, **k):
        reported.append(True)

    monkeypatch.setattr(e.store, "mark_reported", _mark)
    body = e.TelemetryBatchBody(
        events=[{"payload": _payload(i)} for i in (1, 2, 3)],
        batch_id="b-1")

    class _Who:
        tenant_id, endpoint_id, auth_method = "t", "ep", "session"

    out = await e.ingest_batch(body, request=object(), who=_Who())
    assert out["count"] == 3
    assert out["accepted"] == 2 and out["refused"] == 1
    assert [r["index"] for r in out["results"]] == [0, 1, 2], "ordered"
    assert out["results"][0]["accepted"] is True
    assert out["results"][1]["accepted"] is False
    assert out["results"][1]["error"] == "RuntimeError"
    assert out["results"][2]["accepted"] is True
    assert out["batch_id"] == "b-1"


@pytest.mark.asyncio
async def test_liveness_is_recorded_once_per_batch_not_per_event(monkeypatch):
    reported = []

    async def _one(**kw):
        return {"stored": True, "raw_id": "r", "canonical": {}}

    monkeypatch.setattr(e, "_ingest_one", _one)

    async def _mark(*a, **k):
        reported.append(k)

    monkeypatch.setattr(e.store, "mark_reported", _mark)

    class _Who:
        tenant_id, endpoint_id, auth_method = "t", "ep", "session"

    await e.ingest_batch(
        e.TelemetryBatchBody(events=[{"payload": _payload(i)}
                                     for i in range(10)]),
        request=object(), who=_Who())
    assert len(reported) == 1, (
        "ten events must not cause ten endpoint-liveness writes")


@pytest.mark.asyncio
async def test_nothing_accepted_still_writes_no_liveness(monkeypatch):
    async def _one(**kw):
        raise RuntimeError("down")

    marked = []
    monkeypatch.setattr(e, "_ingest_one", _one)
    monkeypatch.setattr(e.store, "mark_reported",
                        lambda *a, **k: marked.append(1))

    class _Who:
        tenant_id, endpoint_id, auth_method = "t", "ep", "session"

    out = await e.ingest_batch(
        e.TelemetryBatchBody(events=[{"payload": _payload(1)}]),
        request=object(), who=_Who())
    assert out["accepted"] == 0
    assert marked == [], "a batch that accepted nothing is not a report"


def test_single_and_batch_share_one_ingest_path():
    """Batching must not become a second set of semantics."""
    import inspect
    source = inspect.getsource(e.ingest)
    assert "_ingest_one(" in source
    assert "raw.RawEndpointEvent.build" not in source, (
        "the single-event route must delegate, not duplicate, the ingest")
    assert "_ingest_one(" in inspect.getsource(e.ingest_batch)


# ═══════════ GATE C · ACQUISITION INTEGRITY CONTRACT ══════════════
def test_server_asserts_classification_and_cause_not_the_sensor():
    gap = acq.normalise_gap(
        {"channel": SYSMON, "expected_next_record_id": 8470186,
         "first_observed_record_id": 8496595, "position": "LEADING",
         # A sensor trying to assert a conclusion it cannot reach.
         "classification": "MALWARE_EVASION", "cause": "LOG_ROLLOVER",
         "missing_record_id_count": 999999},
        tenant_id="t", endpoint_id="ep")
    assert gap["classification"] == "SOURCE_RECORD_DISCONTINUITY"
    assert gap["cause"] == "NOT_PROVEN"
    assert gap["is_detection"] is False
    assert gap["missing_record_id_count"] == 26409, (
        "the count is RECOMPUTED, so a sensor cannot overstate a hole")
    assert gap["missing_start_record_id"] == 8470186
    assert gap["missing_end_record_id"] == 8496594


def test_gap_carries_absence_semantics_with_it():
    gap = acq.normalise_gap(
        {"channel": SYSMON, "expected_next_record_id": 101,
         "first_observed_record_id": 105}, tenant_id="t", endpoint_id="ep")
    s = gap["semantics"]
    assert s["no_event_observed_is_not_event_did_not_occur"] is True
    assert s["acquisition_gap_is_not_benign"] is True
    assert s["acquisition_gap_is_not_malicious"] is True
    assert s["acquisition_gap_is_not_a_detection"] is True


def test_health_state_vocabulary_is_closed():
    required = {"HEALTHY", "DEGRADED", "ACQUISITION_LAGGING",
                "ACQUISITION_GAP", "JOURNAL_PRESSURE", "DELIVERY_BACKLOG",
                "BACKEND_UNREACHABLE"}
    assert required <= set(acq.HEALTH_STATES)
    assert acq._states(["HEALTHY", "TOTALLY_FINE", 7]) == ["HEALTHY"], (
        "a sensor must not be able to invent a reassuring state")


class _FakeCollection:
    def __init__(self):
        self.docs = []
        self.upserts = 0

    async def update_one(self, query, update, upsert=False):
        for doc in self.docs:
            if all(doc.get(k) == v for k, v in query.items()):
                doc.update(update.get("$set") or {})
                return type("R", (), {"upserted_id": None})()
        if upsert:
            doc = {**query, **(update.get("$set") or {}),
                   **(update.get("$setOnInsert") or {})}
            self.docs.append(doc)
            self.upserts += 1
            return type("R", (), {"upserted_id": "x"})()
        return type("R", (), {"upserted_id": None})()


class _FakeDb:
    def __init__(self):
        self.cols = {}

    def __getitem__(self, name):
        return self.cols.setdefault(name, _FakeCollection())


@pytest.mark.asyncio
async def test_report_stores_channels_and_gaps():
    db = _FakeDb()
    out = await acq.record(
        db, tenant_id="t", endpoint_id="ep", sensor_version="0.3.0-windows",
        report={"at": "2026-09-29T15:07:00+00:00",
                "channels": {SYSMON: {"last_cursor_committed": 8496694,
                                      "records_read": 100,
                                      "records_journaled": 100,
                                      "acquisition_lag_records": 0,
                                      "source_oldest_record_id": 8470086,
                                      "source_newest_record_id": 8496694,
                                      "caught_up": True}},
                "acquisition_gaps": [
                    {"channel": SYSMON, "expected_next_record_id": 8470186,
                     "first_observed_record_id": 8496595,
                     "position": "LEADING"}],
                "acquisition_gap_count": 1, "journal_depth": 42,
                "delivery_backlog": 42,
                "health_states": ["ACQUISITION_GAP", "DELIVERY_BACKLOG"]})
    assert out["channels_recorded"] == [SYSMON]
    assert out["gaps_newly_recorded"] == 1
    row = db[acq.REPORTS].docs[0]
    assert row["last_cursor_committed"] == 8496694
    assert row["health_states"] == ["ACQUISITION_GAP", "DELIVERY_BACKLOG"]
    assert row["claim_basis"] == "SENSOR_REPORTED", (
        "acquisition integrity is a sensor CLAIM, never a server "
        "measurement and never an evidence authority")
    gap = db[acq.GAPS].docs[0]
    assert gap["missing_record_id_count"] == 26409
    assert gap["cause"] == "NOT_PROVEN"


@pytest.mark.asyncio
async def test_the_same_declared_gap_is_recorded_once():
    """A retried integrity report must not turn one hole into two."""
    db = _FakeDb()
    report = {"channels": {}, "acquisition_gaps": [
        {"channel": SYSMON, "expected_next_record_id": 101,
         "first_observed_record_id": 105}]}
    first = await acq.record(db, tenant_id="t", endpoint_id="ep",
                             sensor_version="x", report=report)
    second = await acq.record(db, tenant_id="t", endpoint_id="ep",
                              sensor_version="x", report=report)
    assert first["gaps_newly_recorded"] == 1
    assert second["gaps_newly_recorded"] == 0
    assert len(db[acq.GAPS].docs) == 1


@pytest.mark.asyncio
async def test_a_zero_length_gap_is_not_a_gap():
    db = _FakeDb()
    out = await acq.record(db, tenant_id="t", endpoint_id="ep",
                           sensor_version="x",
                           report={"channels": {}, "acquisition_gaps": [
                               {"channel": SYSMON,
                                "expected_next_record_id": 101,
                                "first_observed_record_id": 101}]})
    assert out["gaps_newly_recorded"] == 0
    assert db[acq.GAPS].docs == []
