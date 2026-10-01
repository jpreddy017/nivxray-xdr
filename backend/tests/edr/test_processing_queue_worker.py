from __future__ import annotations

import asyncio

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
        return {"canonicalized": True}

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
    assert done == [{"tenant_id": "t", "raw_id": "raw_1"}]


@pytest.mark.asyncio
async def test_worker_bridge_failure_records_retry(monkeypatch):
    from edr_plane import raw_events
    from edr_plane import canonical_bridge

    async def _claim(*a, **k):
        return {
            "tenant_id": "t",
            "raw_id": "raw_2",
            "state": q.PROCESSING,
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
    assert "bridge failed" in out["error"]
    assert retries[0]["tenant_id"] == "t"
    assert retries[0]["raw_id"] == "raw_2"
    assert retries[0]["retry_after_seconds"] == 17


@pytest.mark.asyncio
async def test_worker_missing_raw_records_retry(monkeypatch):
    from edr_plane import raw_events

    async def _claim(*a, **k):
        return {
            "tenant_id": "t",
            "raw_id": "raw_missing",
            "state": q.PROCESSING,
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
        self.docs = docs
        self.query = None
        self.projection = None
        self.sort_spec = None
        self.limit_value = None

    def find(self, query, projection=None):
        self.query = query
        self.projection = projection
        self._selected = list(self.docs)
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


class _FakeDB(dict):
    pass


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
