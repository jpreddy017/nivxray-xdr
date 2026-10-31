"""P0 · The reconciler owns declared contracts, not the historical corpus.

What this suite is defending against, stated plainly:

The durable-ACK branch shipped a reconciler that ran a `$lookup` anti-join
over the ENTIRE `edr_raw_events` collection every 60 seconds, on every pod,
and sorted the result. On the production corpus that is a multi-hundred-MB
blocking scan plus a sort that exceeds Mongo's in-memory sort limit — i.e.
the repair mechanism was the outage.

The fix is NOT "scan less recently". A time window alone is wrong, because
during a rolling deployment an old pod and a new pod serve traffic
simultaneously: any recent-time rule would make the new pod claim
ownership of evidence the old pod accepted under the previous contract.

So ownership is declared at creation, by an immutable provenance marker on
the raw evidence itself (`processing_contract = "durable_queue_v1"`). The
15-minute window is a read bound only. These tests assert exactly that
split, and assert that adding the marker did not disturb event identity.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from edr_plane import processing_queue as q
from edr_plane import raw_events


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# A raw-evidence fake that actually HONOURS the query it is handed.
#
# This matters: a fake that ignores the filter would let a full-corpus
# reconciler pass these tests. This one evaluates the operators the
# reconciler is permitted to use, and deliberately exposes no `aggregate`,
# so the historical scan path cannot come back unnoticed.
# ---------------------------------------------------------------------------
class _RawEvidence:
    def __init__(self, docs):
        self._docs = list(docs)
        self.queries: list[dict] = []
        self.sorts: list[tuple] = []
        self.limits: list[int] = []

    @staticmethod
    def _matches(doc, query) -> bool:
        for field, cond in query.items():
            value = doc.get(field)
            if isinstance(cond, dict):
                for op, operand in cond.items():
                    if op == "$gte":
                        if value is None or not value >= operand:
                            return False
                    elif op == "$lte":
                        if value is None or not value <= operand:
                            return False
                    elif op == "$exists":
                        if (field in doc) is not operand:
                            return False
                    else:  # pragma: no cover - guard
                        raise AssertionError(
                            f"reconciler used unsupported operator {op}")
            elif value != cond:
                return False
        return True

    def find(self, query, projection=None):
        self.queries.append(query)
        self._selected = [d for d in self._docs if self._matches(d, query)]
        return self

    def sort(self, field, direction=1):
        self.sorts.append((field, direction))
        self._selected.sort(
            key=lambda d: d.get(field) or "", reverse=(direction == -1))
        return self

    def limit(self, n):
        self.limits.append(n)
        self._selected = self._selected[:n]
        return self

    def __aiter__(self):
        self._iter = iter(self._selected)
        return self

    async def __anext__(self):
        try:
            return next(self._iter)
        except StopIteration:
            raise StopAsyncIteration


class _QueueCollection:
    """Records every write attempted directly against the queue."""

    def __init__(self):
        self.direct_calls: list[str] = []

    def __getattr__(self, name):
        def _recorder(*_a, **_k):
            self.direct_calls.append(name)
            raise AssertionError(
                "reconcile_missing_jobs touched the queue collection "
                f"directly via .{name}(); enqueue() must remain the single "
                "idempotent authority")

        return _recorder


class _DB(dict):
    pass


def _db_with(docs):
    db = _DB()
    raw = _RawEvidence(docs)
    db[raw_events.COLLECTION] = raw
    db[q.COLLECTION] = _QueueCollection()
    return db, raw


def _enqueue_spy(created=True):
    calls: list[dict] = []

    async def _enqueue(_db, *, tenant_id, raw_id):
        calls.append({"tenant_id": tenant_id, "raw_id": raw_id})
        return {"tenant_id": tenant_id, "raw_id": raw_id,
                "created": created}

    return _enqueue, calls


# ---------------------------------------------------------------------------
# 1 · Raw-evidence integrity. The marker is additive provenance and MUST NOT
#     perturb event identity in any way.
# ---------------------------------------------------------------------------
IDENTITY_FIELDS = ("raw_id", "payload", "payload_sha256", "dedup_key")


def test_marker_does_not_change_event_identity():
    payload = '{"channel":"Microsoft-Windows-Sysmon/Operational","id":1}'
    kwargs = dict(tenant_id="t_1", source="ep_1", payload=payload,
                  source_kind="sensor", sensor_version="1.2.3",
                  endpoint_ref="ep_1", event_time="2026-06-01T00:00:00+00:00",
                  trust_state="AUTHENTICATED")

    legacy = raw_events.RawEndpointEvent.build(**kwargs)
    marked = raw_events.RawEndpointEvent.build(
        **kwargs, processing_contract=q.PROCESSING_CONTRACT)

    for field in IDENTITY_FIELDS:
        assert getattr(legacy, field) == getattr(marked, field), field

    assert marked.processing_contract == "durable_queue_v1"
    assert legacy.processing_contract is None


def test_dedup_key_is_independent_of_the_contract():
    """A replay of the same bytes across a deployment boundary must still
    deduplicate. If the marker leaked into the digest, the same telemetry
    would be retained twice — inflating the corpus and the counters."""
    payload = "same-bytes"
    a = raw_events.RawEndpointEvent.build(
        tenant_id="t", source="ep", payload=payload)
    b = raw_events.RawEndpointEvent.build(
        tenant_id="t", source="ep", payload=payload,
        processing_contract=q.PROCESSING_CONTRACT)

    assert a.dedup_key == b.dedup_key == raw_events.RawEndpointEvent.digest(
        "t", "ep", payload)
    assert a.raw_id == b.raw_id


def test_payload_bytes_are_untouched_by_the_marker():
    payload = '{"unicode":"ü","trailing_space":"x "}'
    ev = raw_events.RawEndpointEvent.build(
        tenant_id="t", source="ep", payload=payload,
        processing_contract=q.PROCESSING_CONTRACT)

    assert ev.payload == payload
    import hashlib
    assert ev.payload_sha256 == hashlib.sha256(payload.encode()).hexdigest()


def test_default_is_unmarked_so_the_marker_is_never_implicit():
    """Nothing may acquire the contract by accident. Only an explicit
    caller — the durable-ACK ingest path — may stamp it."""
    ev = raw_events.RawEndpointEvent.build(
        tenant_id="t", source="ep", payload="p")
    assert ev.processing_contract is None


@pytest.mark.asyncio
async def test_append_never_retrofits_the_marker_onto_existing_evidence():
    """A re-delivery of historical bytes increments duplicate_count. It must
    NOT upgrade the stored record's contract: provenance is a statement
    about what created the evidence, and is not revisable."""
    updates: list[dict] = []

    class _Coll:
        async def find_one_and_update(self, flt, update, projection=None):
            updates.append(update)
            return {"raw_id": "raw_old", "duplicate_count": 3}

        async def insert_one(self, doc):  # pragma: no cover
            raise AssertionError("duplicate must not insert")

    db = _DB()
    db[raw_events.COLLECTION] = _Coll()

    ev = raw_events.RawEndpointEvent.build(
        tenant_id="t", source="ep", payload="p",
        processing_contract=q.PROCESSING_CONTRACT)
    out = await raw_events.append(db, ev)

    assert out["stored"] is False and out["duplicate"] is True
    assert updates == [{"$inc": {"duplicate_count": 1}}]
    flattened = str(updates)
    assert "$set" not in flattened
    assert "processing_contract" not in flattened


# ---------------------------------------------------------------------------
# 2 · Reconciler authority is the marker.
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_reconciler_queries_on_contract_and_authentication(monkeypatch):
    db, raw = _db_with([])
    enqueue, _ = _enqueue_spy()
    monkeypatch.setattr(q, "enqueue", enqueue)

    await q.reconcile_missing_jobs(db)

    assert len(raw.queries) == 1
    query = raw.queries[0]
    assert query["processing_contract"] == "durable_queue_v1"
    assert query["trust_state"] == "AUTHENTICATED"
    assert set(query["ingest_time"]) == {"$gte"}
    assert raw.sorts == [("ingest_time", 1)]
    assert raw.limits == [500]


@pytest.mark.asyncio
async def test_unmarked_historical_evidence_is_never_reconciled(monkeypatch):
    """The corpus here is overwhelmingly historical and recent. Under a
    time-only rule every one of these rows would be enqueued. Under the
    contract rule, none are."""
    now = _now()
    docs = [
        {"tenant_id": "t", "raw_id": f"raw_hist_{i}",
         "trust_state": "AUTHENTICATED",
         "ingest_time": _iso(now - timedelta(seconds=i))}
        for i in range(50)
    ]
    db, _ = _db_with(docs)
    enqueue, calls = _enqueue_spy()
    monkeypatch.setattr(q, "enqueue", enqueue)

    out = await q.reconcile_missing_jobs(db)

    assert calls == []
    assert out == {"scanned": 0, "created": 0, "already_present": 0}


@pytest.mark.asyncio
async def test_rolling_deployment_overlap_only_new_contract_is_owned(
        monkeypatch):
    """THE rolling-deployment test.

    Both pods are serving at the same instant. The old pod's events are
    unmarked; the new pod's are marked. Both are ACKed and both are
    retained — but the new build may only reconcile what it declared.
    """
    now = _now()
    docs = [
        # old pod, previous contract, accepted 1s ago
        {"tenant_id": "t", "raw_id": "raw_oldpod_1",
         "trust_state": "AUTHENTICATED",
         "ingest_time": _iso(now - timedelta(seconds=1))},
        {"tenant_id": "t", "raw_id": "raw_oldpod_2",
         "trust_state": "AUTHENTICATED",
         "ingest_time": _iso(now - timedelta(seconds=2))},
        # new pod, durable-ACK contract, interleaved in time
        {"tenant_id": "t", "raw_id": "raw_newpod_1",
         "trust_state": "AUTHENTICATED",
         "processing_contract": "durable_queue_v1",
         "ingest_time": _iso(now - timedelta(seconds=3))},
        {"tenant_id": "t", "raw_id": "raw_newpod_2",
         "trust_state": "AUTHENTICATED",
         "processing_contract": "durable_queue_v1",
         "ingest_time": _iso(now - timedelta(seconds=1, milliseconds=500))},
    ]
    db, _ = _db_with(docs)
    enqueue, calls = _enqueue_spy()
    monkeypatch.setattr(q, "enqueue", enqueue)

    out = await q.reconcile_missing_jobs(db)

    assert [c["raw_id"] for c in calls] == ["raw_newpod_1", "raw_newpod_2"]
    assert out["scanned"] == 2 and out["created"] == 2


@pytest.mark.asyncio
async def test_rejected_evidence_is_never_reconciled(monkeypatch):
    """A REJECTED payload is a security signal, not endpoint evidence. Even
    carrying the marker it must not enter the authoritative pipeline."""
    docs = [{
        "tenant_id": "t", "raw_id": "raw_rejected",
        "trust_state": "REJECTED",
        "processing_contract": "durable_queue_v1",
        "ingest_time": _iso(_now()),
    }]
    db, _ = _db_with(docs)
    enqueue, calls = _enqueue_spy()
    monkeypatch.setattr(q, "enqueue", enqueue)

    out = await q.reconcile_missing_jobs(db)

    assert calls == []
    assert out["scanned"] == 0


@pytest.mark.asyncio
async def test_a_future_contract_version_is_not_claimed(monkeypatch):
    docs = [{
        "tenant_id": "t", "raw_id": "raw_v2",
        "trust_state": "AUTHENTICATED",
        "processing_contract": "durable_queue_v2",
        "ingest_time": _iso(_now()),
    }]
    db, _ = _db_with(docs)
    enqueue, calls = _enqueue_spy()
    monkeypatch.setattr(q, "enqueue", enqueue)

    assert (await q.reconcile_missing_jobs(db))["scanned"] == 0
    assert calls == []


# ---------------------------------------------------------------------------
# 3 · The window is a performance bound, nothing more.
# ---------------------------------------------------------------------------
def test_window_default_is_fifteen_minutes():
    assert q.RECONCILE_WINDOW_SECONDS == 15 * 60


@pytest.mark.asyncio
async def test_window_bounds_the_read_but_grants_no_ownership(monkeypatch):
    now = _now()
    docs = [
        {"tenant_id": "t", "raw_id": "raw_inside",
         "trust_state": "AUTHENTICATED",
         "processing_contract": "durable_queue_v1",
         "ingest_time": _iso(now - timedelta(minutes=5))},
        {"tenant_id": "t", "raw_id": "raw_outside",
         "trust_state": "AUTHENTICATED",
         "processing_contract": "durable_queue_v1",
         "ingest_time": _iso(now - timedelta(hours=9))},
        # Inside the window but UNMARKED — proves the window is not the
        # thing deciding ownership.
        {"tenant_id": "t", "raw_id": "raw_inside_unmarked",
         "trust_state": "AUTHENTICATED",
         "ingest_time": _iso(now - timedelta(minutes=5))},
    ]
    db, _ = _db_with(docs)
    enqueue, calls = _enqueue_spy()
    monkeypatch.setattr(q, "enqueue", enqueue)

    await q.reconcile_missing_jobs(db)

    assert [c["raw_id"] for c in calls] == ["raw_inside"]


@pytest.mark.asyncio
async def test_window_is_widenable_without_changing_authority(monkeypatch):
    now = _now()
    docs = [
        {"tenant_id": "t", "raw_id": "raw_old_marked",
         "trust_state": "AUTHENTICATED",
         "processing_contract": "durable_queue_v1",
         "ingest_time": _iso(now - timedelta(hours=9))},
        {"tenant_id": "t", "raw_id": "raw_old_unmarked",
         "trust_state": "AUTHENTICATED",
         "ingest_time": _iso(now - timedelta(hours=9))},
    ]
    db, _ = _db_with(docs)
    enqueue, calls = _enqueue_spy()
    monkeypatch.setattr(q, "enqueue", enqueue)

    await q.reconcile_missing_jobs(db, window_seconds=86400)

    assert [c["raw_id"] for c in calls] == ["raw_old_marked"]


@pytest.mark.asyncio
async def test_limit_is_clamped_so_one_pass_can_never_be_unbounded(
        monkeypatch):
    db, raw = _db_with([])
    enqueue, _ = _enqueue_spy()
    monkeypatch.setattr(q, "enqueue", enqueue)

    await q.reconcile_missing_jobs(db, limit=10 ** 9)
    await q.reconcile_missing_jobs(db, limit=0)

    assert raw.limits == [5000, 1]


# ---------------------------------------------------------------------------
# 4 · The historical full-corpus path is GONE, not merely unused.
# ---------------------------------------------------------------------------
def test_no_lookup_or_aggregation_remains_in_the_reconciler():
    src = Path(q.__file__).read_text()
    for forbidden in ("$lookup", "aggregate(", "_processing_job"):
        assert forbidden not in src, (
            f"{forbidden} reappeared in processing_queue.py — the "
            "full-corpus reconciliation scan must stay deleted")


@pytest.mark.asyncio
async def test_reconciler_never_touches_the_queue_collection_directly(
        monkeypatch):
    docs = [{
        "tenant_id": "t", "raw_id": "raw_1",
        "trust_state": "AUTHENTICATED",
        "processing_contract": "durable_queue_v1",
        "ingest_time": _iso(_now()),
    }]
    db, _ = _db_with(docs)
    enqueue, calls = _enqueue_spy()
    monkeypatch.setattr(q, "enqueue", enqueue)

    await q.reconcile_missing_jobs(db)

    assert db[q.COLLECTION].direct_calls == []
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_enqueue_remains_the_idempotent_authority(monkeypatch):
    """The reconciler does not pre-check. It re-asserts the obligation and
    lets enqueue() decide, so a concurrent repair is simply not-created."""
    docs = [{
        "tenant_id": "t", "raw_id": "raw_already",
        "trust_state": "AUTHENTICATED",
        "processing_contract": "durable_queue_v1",
        "ingest_time": _iso(_now()),
    }]
    db, _ = _db_with(docs)
    enqueue, calls = _enqueue_spy(created=False)
    monkeypatch.setattr(q, "enqueue", enqueue)

    out = await q.reconcile_missing_jobs(db)

    assert len(calls) == 1
    assert out == {"scanned": 1, "created": 0, "already_present": 1}


@pytest.mark.asyncio
async def test_malformed_rows_are_skipped_not_fatal(monkeypatch):
    docs = [
        {"tenant_id": "t", "trust_state": "AUTHENTICATED",
         "processing_contract": "durable_queue_v1",
         "ingest_time": _iso(_now())},
        {"raw_id": "raw_no_tenant", "trust_state": "AUTHENTICATED",
         "processing_contract": "durable_queue_v1",
         "ingest_time": _iso(_now())},
        {"tenant_id": "t", "raw_id": "raw_ok",
         "trust_state": "AUTHENTICATED",
         "processing_contract": "durable_queue_v1",
         "ingest_time": _iso(_now())},
    ]
    db, _ = _db_with(docs)
    enqueue, calls = _enqueue_spy()
    monkeypatch.setattr(q, "enqueue", enqueue)

    out = await q.reconcile_missing_jobs(db)

    assert [c["raw_id"] for c in calls] == ["raw_ok"]
    assert out["scanned"] == 1


# ---------------------------------------------------------------------------
# 5 · Reconciliation failure is observable, and rate-controlled.
# ---------------------------------------------------------------------------
def test_reconcile_failures_log_on_onset_then_every_tenth(caplog):
    q._reconcile_consecutive_failures = 0
    exc = RuntimeError("mongo unavailable")

    with caplog.at_level(logging.WARNING,
                         logger="edr_plane.processing_queue"):
        logged = [q._note_reconcile_failure(exc) for _ in range(1, 22)]

    assert logged[0] is True                      # onset
    assert logged[1:9] == [False] * 8             # suppressed
    assert logged[9] is True                      # 10th
    assert logged[19] is True                     # 20th
    assert q.reconcile_failure_count() == 21

    warnings = [r.getMessage() for r in caplog.records]
    assert len(warnings) == 3
    assert "consecutive=1" in warnings[0]
    assert "mongo unavailable" in warnings[0]
    assert "consecutive=10" in warnings[1]

    q._reconcile_consecutive_failures = 0


def test_reconcile_recovery_is_logged_and_resets_the_counter(caplog):
    q._reconcile_consecutive_failures = 0
    q._note_reconcile_failure(RuntimeError("boom"))
    q._note_reconcile_failure(RuntimeError("boom"))

    with caplog.at_level(logging.WARNING,
                         logger="edr_plane.processing_queue"):
        q._note_reconcile_success()

    assert q.reconcile_failure_count() == 0
    assert any("RECOVERED after 2" in r.getMessage()
               for r in caplog.records)


def test_a_clean_run_logs_nothing(caplog):
    q._reconcile_consecutive_failures = 0
    with caplog.at_level(logging.WARNING,
                         logger="edr_plane.processing_queue"):
        q._note_reconcile_success()
    assert caplog.records == []


@pytest.mark.asyncio
async def test_supervisor_survives_a_failing_reconciler_and_reports_it(
        caplog, monkeypatch):
    import asyncio

    q._reconcile_consecutive_failures = 0

    async def _boom(*_a, **_k):
        raise RuntimeError("reconcile exploded")

    async def _idle_worker(*_a, **_k):
        assert q._stop_event is not None
        await q._stop_event.wait()

    monkeypatch.setattr(q, "reconcile_missing_jobs", _boom)
    monkeypatch.setattr(q, "_worker_loop", _idle_worker)

    with caplog.at_level(logging.WARNING,
                         logger="edr_plane.processing_queue"):
        assert await q.start_workers(object(), worker_count=1,
                                     reconcile_interval_seconds=5) is True
        await asyncio.sleep(0.05)
        assert q._supervisor_task is not None
        assert not q._supervisor_task.done()
        await q.stop_workers()

    assert q.reconcile_failure_count() >= 1
    assert any("reconcile exploded" in r.getMessage()
               for r in caplog.records)

    q._reconcile_consecutive_failures = 0


# ---------------------------------------------------------------------------
# 6 · Deployment posture: one worker per process, and an index that makes
#     the bounded read cheap.
# ---------------------------------------------------------------------------
def test_start_workers_defaults_to_a_single_worker():
    import inspect
    sig = inspect.signature(q.start_workers)
    assert sig.parameters["worker_count"].default == 1


def test_server_startup_requests_exactly_one_worker():
    src = (Path(__file__).resolve().parents[2] / "server.py").read_text()
    assert re.search(r"_start_edr_workers\(\s*\n\s*_edr_worker_db,\s*\n"
                     r"\s*worker_count=1,", src), (
        "server.py must start the EDR durable processing supervisor with "
        "worker_count=1 per pod")


@pytest.mark.asyncio
async def test_reconciliation_index_is_created_and_is_partial():
    created: list[dict] = []

    class _Coll:
        async def create_index(self, keys, **kwargs):
            created.append({"keys": keys, **kwargs})

    db = _DB()
    db[raw_events.COLLECTION] = _Coll()

    await raw_events.ensure_indexes(db)

    idx = next((c for c in created
                if c.get("name") == "reconcile_contract_window"), None)
    assert idx is not None, "reconciliation index missing"
    assert idx["keys"] == [("processing_contract", 1), ("ingest_time", 1)]
    # Partial, not sparse: a compound sparse index still indexes every
    # document that has `ingest_time` — i.e. the whole corpus — which would
    # defeat the point.
    assert idx["partialFilterExpression"] == {
        "processing_contract": {"$exists": True}}
    assert "sparse" not in idx


def test_ingest_path_stamps_the_contract_marker():
    src = (Path(__file__).resolve().parents[2]
           / "routers" / "edr_enrollment.py").read_text()
    assert "processing_contract=processing_queue.PROCESSING_CONTRACT" in src
    assert q.PROCESSING_CONTRACT == "durable_queue_v1"
