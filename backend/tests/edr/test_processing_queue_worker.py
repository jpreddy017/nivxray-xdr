from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest

from edr_plane import processing_queue as q


@pytest.mark.asyncio
async def test_worker_no_work(monkeypatch):
    async def _claim(*a, **k):
        return None

    monkeypatch.setattr(q, "claim", _claim)

    out = await q.process_one(object())

    assert out == {"processed": False, "reason": "no_work"}


@pytest.mark.asyncio
async def test_worker_success_marks_done(monkeypatch):
    from edr_plane import raw_events
    from edr_plane import canonical_bridge

    async def _claim(*a, **k):
        return {
            "tenant_id": "t",
            "raw_id": "raw_1",
            "state": q.PROCESSING,
            "attempts": 1,
            "lease_until": q._now() + timedelta(seconds=600),
        }

    async def _get(*a, **k):
        return {
            "tenant_id": "t",
            "raw_id": "raw_1",
            "payload": '{"event":"x"}',
            "endpoint_ref": "ep_1",
            "source_kind": "sensor",
            "sensor_version": "test",
            "ingest_time": "2026-10-01T00:00:00+00:00",
            "authentication": {
                "endpoint_id": "ep_1",
                "hostname": "KUSHU",
                "auth_method": "session",
            },
        }

    async def _bridge(*a, **k):
        return {"canonicalized": True, "parser_state": "OK", "detection": {
            "evaluated": True, "finding_plane": {"evaluation_state": "EVALUATED_NO_FINDING"},
            "stage_results": [{"stage": "detection", "status": "EXECUTED"}]}}

    done = []

    async def _done(*a, **k):
        done.append(k)
        return True

    monkeypatch.setattr(q, "claim", _claim)
    monkeypatch.setattr(raw_events, "get", _get)
    monkeypatch.setattr(canonical_bridge, "bridge", _bridge)
    monkeypatch.setattr(q, "mark_done", _done)

    out = await q.process_one(object())

    assert out["processed"] is True
    assert out["state"] == q.DONE
    assert len(done) == 1
    timing = done[0].pop("timings")
    assert done == [{"tenant_id": "t", "raw_id": "raw_1", "attempts": 1}]
    assert timing["attempt"] == 1
    assert timing["contract"] == "edr.processing_timings.v1"
    stage = timing["stages"]["canonical_bridge"]
    assert stage["state"] == "COMPLETED"
    assert stage["duration_ms"] >= 0
    assert stage["ended_at"] >= stage["started_at"]


@pytest.mark.asyncio
async def test_worker_bridge_failure_records_retry(monkeypatch):
    from edr_plane import raw_events
    from edr_plane import canonical_bridge

    async def _claim(*a, **k):
        return {
            "tenant_id": "t",
            "raw_id": "raw_2",
            "state": q.PROCESSING,
            "attempts": 1,
            "lease_until": q._now() + timedelta(seconds=600),
        }

    async def _get(*a, **k):
        return {
            "tenant_id": "t",
            "raw_id": "raw_2",
            "payload": '{"event":"x"}',
            "endpoint_ref": "ep_1",
            "source_kind": "sensor",
            "sensor_version": "test",
            "ingest_time": "2026-10-01T00:00:00+00:00",
            "authentication": {"endpoint_id": "ep_1"},
        }

    async def _bridge(*a, **k):
        raise RuntimeError("bridge failed")

    retries = []

    async def _retry(*a, **k):
        retries.append(k)
        return True

    monkeypatch.setattr(q, "claim", _claim)
    monkeypatch.setattr(raw_events, "get", _get)
    monkeypatch.setattr(canonical_bridge, "bridge", _bridge)
    monkeypatch.setattr(q, "mark_retry", _retry)

    out = await q.process_one(object(), retry_after_seconds=17)

    assert out["processed"] is False
    assert out["state"] == q.RETRY
    assert out["retry_recorded"] is True
    assert retries[0]["attempts"] == 1
    assert "bridge failed" in out["error"]
    assert retries[0]["tenant_id"] == "t"
    assert retries[0]["raw_id"] == "raw_2"
    assert retries[0]["retry_after_seconds"] == 17
    assert retries[0]["attempts"] == 1


@pytest.mark.asyncio
async def test_worker_missing_raw_records_retry(monkeypatch):
    from edr_plane import raw_events

    async def _claim(*a, **k):
        return {
            "tenant_id": "t",
            "raw_id": "raw_missing",
            "state": q.PROCESSING,
            "attempts": 1,
            "lease_until": q._now() + timedelta(seconds=600),
        }

    async def _get(*a, **k):
        return None

    retries = []

    async def _retry(*a, **k):
        retries.append(k)
        return True

    monkeypatch.setattr(q, "claim", _claim)
    monkeypatch.setattr(raw_events, "get", _get)
    monkeypatch.setattr(q, "mark_retry", _retry)

    out = await q.process_one(object())

    assert out["processed"] is False
    assert out["state"] == q.RETRY
    assert out["retry_recorded"] is True
    assert retries[0]["attempts"] == 1
    assert "raw evidence missing" in out["error"]
    assert retries[0]["raw_id"] == "raw_missing"


class _FakeRawCursor:
    """Raw-evidence collection fake for the contract-scoped reconciler.

    The reconciler now issues an index-covered `find` scoped by the
    `processing_contract` provenance marker instead of a full-corpus
    `$lookup` anti-join, so the fake records the query it was given and
    there is NO `aggregate` here at all — a reappearance of the historical
    scan would fail with AttributeError rather than silently pass.
    """

    def __init__(self, docs):
        self.docs = [dict(doc, _id=i + 1) for i, doc in enumerate(docs)]
        self.query = None
        self.projection = None
        self.sort_spec = None
        self.limit_value = None

    async def find_one(self, query, projection=None, sort=None):
        assert query["processing_contract"] == q.PROCESSING_CONTRACT
        assert query["trust_state"] == "AUTHENTICATED"
        return self.docs[-1] if self.docs else None

    def find(self, query, projection=None):
        assert query["processing_contract"] == q.PROCESSING_CONTRACT
        assert query["trust_state"] == "AUTHENTICATED"
        self.query = query
        self.projection = projection
        bounds = query["_id"]
        self._selected = [d for d in self.docs
                          if d["_id"] <= bounds["$lte"]
                          and d["_id"] > bounds.get("$gt", 0)]
        return self

    def sort(self, field, direction=1):
        self.sort_spec = (field, direction)
        return self

    def limit(self, n):
        self.limit_value = n
        self._selected = self._selected[:n]
        return self

    def __aiter__(self):
        self._iter = iter(getattr(self, "_selected", self.docs))
        return self

    async def __anext__(self):
        try:
            return next(self._iter)
        except StopIteration:
            raise StopAsyncIteration


class _FakeCursorState:
    def __init__(self):
        self.doc = None

    async def update_one(self, query, update, upsert=False):
        from types import SimpleNamespace
        if self.doc is None and upsert:
            self.doc = {**query, **update["$setOnInsert"]}
            return SimpleNamespace(modified_count=0)
        if self.doc is None or any(self.doc.get(k) != v for k, v in query.items()):
            return SimpleNamespace(modified_count=0)
        self.doc.update(update.get("$set", {}))
        for k, v in update.get("$inc", {}).items():
            self.doc[k] = self.doc.get(k, 0) + v
        return SimpleNamespace(modified_count=1)

    async def find_one(self, query):
        return dict(self.doc) if self.doc else None


class _FakeDB(dict):
    def __init__(self):
        super().__init__()
        from edr_plane.reconciliation import CURSORS
        self[CURSORS] = _FakeCursorState()


@pytest.mark.asyncio
async def test_reconciler_creates_missing_processing_jobs(monkeypatch):
    from edr_plane import raw_events

    db = _FakeDB()
    db[raw_events.COLLECTION] = _FakeRawCursor([
        {"tenant_id": "t", "raw_id": "raw_1"},
        {"tenant_id": "t", "raw_id": "raw_2"},
    ])

    calls = []

    async def _enqueue(*a, **k):
        calls.append(k)
        return {
            "tenant_id": k["tenant_id"],
            "raw_id": k["raw_id"],
            "created": True,
        }

    monkeypatch.setattr(q, "enqueue", _enqueue)

    out = await q.reconcile_missing_jobs(db)

    assert out == {
        "scanned": 2,
        "created": 2,
        "already_present": 0,
    }
    assert calls == [
        {"tenant_id": "t", "raw_id": "raw_1"},
        {"tenant_id": "t", "raw_id": "raw_2"},
    ]


@pytest.mark.asyncio
async def test_reconciler_is_idempotent_for_existing_jobs(monkeypatch):
    from edr_plane import raw_events

    db = _FakeDB()
    db[raw_events.COLLECTION] = _FakeRawCursor([
        {"tenant_id": "t", "raw_id": "raw_existing"},
    ])

    async def _enqueue(*a, **k):
        return {
            "tenant_id": k["tenant_id"],
            "raw_id": k["raw_id"],
            "created": False,
        }

    monkeypatch.setattr(q, "enqueue", _enqueue)

    out = await q.reconcile_missing_jobs(db)

    assert out == {
        "scanned": 1,
        "created": 0,
        "already_present": 1,
    }


@pytest.mark.asyncio
async def test_worker_lifecycle_start_stop(monkeypatch):
    import asyncio

    # Keep the supervisor alive without touching Mongo or processing events.
    async def _reconcile(*a, **k):
        return {
            "scanned": 0,
            "created": 0,
            "already_present": 0,
        }

    async def _process(*a, **k):
        return {"processed": False, "reason": "no_work"}

    monkeypatch.setattr(q, "reconcile_missing_jobs", _reconcile)
    monkeypatch.setattr(q, "process_one", _process)

    # Defensive reset in case another test left module state behind.
    await q.stop_workers()

    started = await q.start_workers(
        object(),
        worker_count=2,
        reconcile_interval_seconds=5,
    )
    assert started is True

    duplicate_start = await q.start_workers(
        object(),
        worker_count=2,
        reconcile_interval_seconds=5,
    )
    assert duplicate_start is False

    await asyncio.sleep(0.05)

    assert q._supervisor_task is not None
    assert not q._supervisor_task.done()

    await q.stop_workers()

    assert q._supervisor_task is None
    assert q._stop_event is None


@pytest.mark.asyncio
async def test_worker_loop_survives_transient_process_one_exception(monkeypatch):
    """A transient claim/DB failure must not permanently kill the worker."""
    from edr_plane import processing_queue as pq

    calls = 0

    async def fake_process_one(*args, **kwargs):
        nonlocal calls
        calls += 1

        if calls == 1:
            raise RuntimeError("transient mongo failure")

        pq._stop_event.set()
        return {
            "processed": False,
            "reason": "no_work",
        }

    monkeypatch.setattr(pq, "process_one", fake_process_one)

    pq._stop_event = asyncio.Event()

    try:
        await asyncio.wait_for(
            pq._worker_loop(object(), idle_seconds=0.01),
            timeout=1.0,
        )
    finally:
        pq._stop_event = None

    assert calls == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["canonical", "parser", "evaluation", "finding", "stages", "failed_stage"])
async def test_incomplete_processing_never_marks_done(monkeypatch, failure):
    from edr_plane import raw_events, canonical_bridge
    result = {"canonicalized": True, "parser_state": "OK", "detection": {
        "evaluated": True, "finding_plane": {"evaluation_state": "EVALUATED_NO_FINDING"},
        "stage_results": [{"stage": "detection", "status": "EXECUTED"}]}}
    if failure == "canonical": result["canonicalized"] = False
    if failure == "parser": result["parser_state"] = "FAILED"
    if failure == "evaluation": result["detection"]["evaluated"] = False
    if failure == "finding": result["detection"]["finding_plane"]["evaluation_state"] = "EVALUATION_FAILED"
    if failure == "stages": result["detection"]["stage_results"] = []
    if failure == "failed_stage": result["detection"]["stage_results"][0]["status"] = "FAILED"
    async def claim(*a, **k): return {"tenant_id": "t", "raw_id": "r", "attempts": 3, "lease_until": q._now() + timedelta(seconds=600)}
    async def raw(*a, **k): return {"payload": "{}", "endpoint_ref": "ep", "source_kind": "sensor", "authentication": {"endpoint_id": "ep", "auth_method": "session"}}
    async def bridge(*a, **k): return result
    async def done(*a, **k): pytest.fail("incomplete processing reached DONE")
    retries = []
    async def retry(*a, **k):
        retries.append(k)
        return True
    monkeypatch.setattr(q, "claim", claim)
    monkeypatch.setattr(raw_events, "get", raw)
    monkeypatch.setattr(canonical_bridge, "bridge", bridge)
    monkeypatch.setattr(q, "mark_done", done)
    monkeypatch.setattr(q, "mark_retry", retry)
    out = await q.process_one(object())
    assert out["retry_recorded"] is True
    assert retries[0]["attempts"] == 3
    assert "refusing DONE" in retries[0]["error"]


@pytest.mark.asyncio
async def test_worker_alternates_live_and_recovery_under_backlog(monkeypatch):
    turns = []
    q._stop_event = asyncio.Event()

    async def process(*args, **kwargs):
        turns.append(kwargs["newest_first"])
        if len(turns) == 6:
            q._stop_event.set()
        return {"processed": True, "state": q.DONE}

    monkeypatch.setattr(q, "process_one", process)
    try:
        await asyncio.wait_for(q._worker_loop(object()), timeout=1)
    finally:
        q._stop_event = None
    assert turns == [True, False, True, False, True, False]

