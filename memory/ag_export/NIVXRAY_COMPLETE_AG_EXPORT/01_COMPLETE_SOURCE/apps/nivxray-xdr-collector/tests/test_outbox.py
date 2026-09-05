"""
Phase B.5 · Durable outbox tests.

Covers: enqueue, idempotency dedupe, delivery success (2xx), 4xx
fatal → DEAD_LETTER, 5xx retryable → RETRYING with backoff, timeout
retryable, restart recovery (DELIVERING → QUEUED on __init__), max
attempts → DEAD_LETTER, replay-dead requeues, missing ingest URL
does not lose events, per-connector metrics.
"""
from __future__ import annotations

import os
import tempfile

import httpx
import pytest

from framework.base            import Envelope
from framework.delivery        import IngestClient
from framework.delivery_worker import DeliveryWorker
from framework.outbox          import Outbox, OutboxStatus


def _env(tid="acme", cid="conn-1", eid="e1", source="test"):
    return Envelope(
        tenant_id="acme" if tid is None else tid,
        source=source,
        source_event_id=eid,
        connector_id=cid,
        collector_id="collector-local",
        collection_method="test",
        parser_version="test-1",
        source_timestamp=None,
        collection_timestamp="2026-01-01T00:00:00+00:00",
        event_type="rest",
        raw={"payload": 1},
        canonical={},
    )


def _mock_ingest(monkeypatch, handler):
    transport   = httpx.MockTransport(handler)
    orig_client = httpx.AsyncClient
    def _c(*a, **kw):
        kw["transport"] = transport
        return orig_client(*a, **kw)
    monkeypatch.setattr(httpx, "AsyncClient", _c)


def _configured_ingest(monkeypatch, handler):
    monkeypatch.setenv("NIVX_INGEST_URL",   "https://ingest.example/api/xdr/ingest")
    monkeypatch.setenv("NIVX_INGEST_TOKEN", "test-token")
    _mock_ingest(monkeypatch, handler)
    return IngestClient()


# ── 1 · basic enqueue ─────────────────────────────────────────
def test_outbox_records_envelope_as_queued():
    ob = Outbox()
    rid, status = ob.record(_env())
    assert status == OutboxStatus.QUEUED
    assert ob.by_id(rid).status == OutboxStatus.QUEUED


# ── 2 · idempotency ───────────────────────────────────────────
def test_outbox_deduplicates_same_event_id():
    ob = Outbox()
    r1, _ = ob.record(_env(eid="dup-1"))
    r2, _ = ob.record(_env(eid="dup-1"))
    assert r1 == r2                              # same row returned
    assert ob.counts()[OutboxStatus.QUEUED] == 1


def test_outbox_allows_same_event_id_across_connectors():
    ob = Outbox()
    ob.record(_env(cid="a", eid="e1"))
    ob.record(_env(cid="b", eid="e1"))
    assert ob.counts()[OutboxStatus.QUEUED] == 2


# ── 3 · successful delivery ───────────────────────────────────
@pytest.mark.asyncio
async def test_successful_delivery_marks_delivered(monkeypatch):
    def handler(request):
        return httpx.Response(202, json={"ok": True})
    ingest = _configured_ingest(monkeypatch, handler)
    ob = Outbox()
    rid, _ = ob.record(_env(eid="ok-1"))
    worker = DeliveryWorker(ob, ingest, poll_interval_seconds=0.01)
    result = await worker.tick_once()
    assert result["delivered"] == 1
    assert ob.by_id(rid).status == OutboxStatus.DELIVERED
    assert ingest.delivered == 1


# ── 4 · 5xx retryable ─────────────────────────────────────────
@pytest.mark.asyncio
async def test_5xx_marks_retrying_with_backoff(monkeypatch):
    def handler(request):
        return httpx.Response(503, text="upstream unavailable")
    ingest = _configured_ingest(monkeypatch, handler)
    ob = Outbox()
    rid, _ = ob.record(_env(eid="retry-1"))
    worker = DeliveryWorker(ob, ingest)
    result = await worker.tick_once()
    assert result["retrying"] == 1
    row = ob.by_id(rid)
    assert row.status == OutboxStatus.RETRYING
    assert row.attempts == 1
    assert "503" in (row.last_error or "")
    # No new batch immediately — next_attempt_at is in the future.
    result2 = await worker.tick_once()
    assert result2["drained"] == 0


# ── 5 · 4xx (non-408/429) fatal ───────────────────────────────
@pytest.mark.asyncio
async def test_4xx_marks_dead_letter(monkeypatch):
    def handler(request):
        return httpx.Response(400, text="bad envelope")
    ingest = _configured_ingest(monkeypatch, handler)
    ob = Outbox()
    rid, _ = ob.record(_env(eid="fatal-1"))
    worker = DeliveryWorker(ob, ingest)
    result = await worker.tick_once()
    assert result["dead"] == 1
    row = ob.by_id(rid)
    assert row.status == OutboxStatus.DEAD_LETTER


@pytest.mark.asyncio
async def test_429_marks_retryable_not_fatal(monkeypatch):
    def handler(request):
        return httpx.Response(429)
    ingest = _configured_ingest(monkeypatch, handler)
    ob = Outbox()
    rid, _ = ob.record(_env(eid="rl-1"))
    worker = DeliveryWorker(ob, ingest)
    r = await worker.tick_once()
    assert r["retrying"] == 1
    assert ob.by_id(rid).status == OutboxStatus.RETRYING


# ── 6 · timeout / transport failure retryable ─────────────────
@pytest.mark.asyncio
async def test_timeout_marks_retryable(monkeypatch):
    def handler(request):
        raise httpx.TimeoutException("boom")
    ingest = _configured_ingest(monkeypatch, handler)
    ob = Outbox()
    rid, _ = ob.record(_env(eid="tmo-1"))
    worker = DeliveryWorker(ob, ingest)
    r = await worker.tick_once()
    assert r["retrying"] == 1
    assert ob.by_id(rid).status == OutboxStatus.RETRYING


# ── 7 · missing ingest URL keeps events in outbox ─────────────
@pytest.mark.asyncio
async def test_missing_ingest_url_keeps_events_queued(monkeypatch):
    monkeypatch.delenv("NIVX_INGEST_URL", raising=False)
    ingest = IngestClient()
    assert ingest.configured() is False
    ob = Outbox()
    rid, _ = ob.record(_env(eid="noingest-1"))
    worker = DeliveryWorker(ob, ingest)
    r = await worker.tick_once()
    # RETRYABLE — event NOT lost, sitting in RETRYING for later drain
    row = ob.by_id(rid)
    assert row.status == OutboxStatus.RETRYING
    assert "ingest_not_configured" in (row.last_error or "")
    assert ingest.status()["state"] == "not_configured"


# ── 8 · max attempts → DEAD_LETTER ────────────────────────────
def test_mark_retry_exhausts_to_dead_letter():
    ob = Outbox(max_attempts=3, backoff_seconds=(0, 0, 0))
    rid, _ = ob.record(_env(eid="ex-1"))
    for _ in range(3):
        status = ob.mark_retry(rid, "err")
    assert status == OutboxStatus.DEAD_LETTER
    assert ob.by_id(rid).status == OutboxStatus.DEAD_LETTER


# ── 9 · restart recovery ──────────────────────────────────────
def test_restart_recovery_resets_delivering_to_queued():
    tmp = tempfile.mkdtemp()
    ob1 = Outbox(path=tmp)
    rid, _ = ob1.record(_env(eid="rr-1"))
    ob1.mark_delivering([rid])
    assert ob1.by_id(rid).status == OutboxStatus.DELIVERING
    ob1.close()
    # simulate restart
    ob2 = Outbox(path=tmp)
    row = ob2.by_id(rid)
    assert row is not None
    assert row.status == OutboxStatus.QUEUED
    ob2.close()


# ── 10 · replay-dead ──────────────────────────────────────────
def test_replay_dead_requeues_row():
    ob = Outbox(max_attempts=1, backoff_seconds=(0,))
    rid, _ = ob.record(_env(eid="rp-1"))
    ob.mark_retry(rid, "boom")  # attempts=1 → DEAD_LETTER
    assert ob.by_id(rid).status == OutboxStatus.DEAD_LETTER
    assert ob.replay_dead(rid) is True
    assert ob.by_id(rid).status == OutboxStatus.QUEUED
    assert ob.by_id(rid).attempts == 0
    # replay a non-dead row returns False
    ob2, _ = ob.record(_env(eid="rp-2")), None
    assert ob.replay_dead("not-a-row") is False


# ── 11 · concurrent delivery of a batch ───────────────────────
@pytest.mark.asyncio
async def test_batch_delivery_all_marked(monkeypatch):
    def handler(request):
        return httpx.Response(200, json={"ok": True})
    ingest = _configured_ingest(monkeypatch, handler)
    ob = Outbox()
    ids = [ob.record(_env(eid=f"b{i}"))[0] for i in range(10)]
    worker = DeliveryWorker(ob, ingest, batch_size=10)
    r = await worker.tick_once()
    assert r["delivered"] == 10
    for i in ids:
        assert ob.by_id(i).status == OutboxStatus.DELIVERED


# ── 12 · per-connector metrics ────────────────────────────────
def test_metrics_scope_by_connector():
    ob = Outbox()
    ob.record(_env(cid="a", eid="a1"))
    ob.record(_env(cid="a", eid="a2"))
    ob.record(_env(cid="b", eid="b1"))
    ma = ob.metrics(connector_id="a")
    mb = ob.metrics(connector_id="b")
    assert ma["counts"][OutboxStatus.QUEUED] == 2
    assert mb["counts"][OutboxStatus.QUEUED] == 1
    assert ma["queue_depth"] == 2
