"""G1-R1 · Retry classification correctness.

The G1 proof run destroyed 14,868 acquired events because infrastructure in
front of the application answered HTTP 404 for ~5h46m while the backend was not
running, and the delivery path treated every non-408/429 4xx as fatal on the
FIRST attempt. Those responses never reached the application, so they were
never refusals.

The invariant proved here:

    a response is NOT permanently terminal merely because its status is 4xx.

Terminality requires an application-attributable refusal. Attribution is the
``X-Request-ID`` header, which the NivXRay application stamps on every response
(success and error alike) and which an infrastructure response produced with no
backend listening does not carry. The test is conservative by design: it can
only withhold terminality, never manufacture it.

Security semantics stay fail-closed: an attributed refusal is still terminal, a
refusal is never laundered into success, retries stay bounded, and exhaustion
is reported as its own truthful disposition.
"""
from __future__ import annotations

import httpx
import pytest

from framework.base            import Envelope
from framework.delivery        import (APP_ATTRIBUTION_HEADER,
                                       DeliveryClassification, IngestClient,
                                       IngestOutcome)
from framework.delivery_worker import DeliveryWorker
from framework.outbox          import Outbox, OutboxStatus

RID_HEADER = {APP_ATTRIBUTION_HEADER: "nvx-r1-test"}


def _env(eid="r1-1"):
    return Envelope(
        tenant_id="ten_f1a5479243e901cf159e230fa0",
        source="windows_sysmon",
        source_event_id=eid,
        connector_id="windows-eventlog-g1proof01",
        collector_id="col_d6b0b9e8172246f29be9",
        collection_method="windows-eventlog",
        parser_version="sysmon-1",
        source_timestamp="2026-09-22T15:43:31.770+00:00",
        collection_timestamp="2026-09-22T16:43:27.799946+00:00",
        event_type="registry_event",
        raw={"xml": "<Event/>"},
        canonical={},
    )


def _ingest(monkeypatch, handler):
    monkeypatch.setenv("NIVX_INGEST_URL", "https://ingest.example/api/xdr/ingest/telemetry")
    monkeypatch.setenv("NIVX_INGEST_TOKEN", "test-token")
    transport = httpx.MockTransport(handler)
    orig = httpx.AsyncClient

    def _c(*a, **kw):
        kw["transport"] = transport
        return orig(*a, **kw)

    monkeypatch.setattr(httpx, "AsyncClient", _c)
    return IngestClient()


def _responder(status, headers=None, calls=None):
    def handler(request):
        if calls is not None:
            calls.append(request)
        return httpx.Response(status, headers=headers or {})
    return handler


# ── 1 · THE EXACT G1 FAILURE SHAPE ────────────────────────────────────
# Infrastructure 404, no application attribution: must NOT be dead-lettered.
@pytest.mark.asyncio
async def test_bare_404_is_not_immediate_dead_letter(monkeypatch):
    ingest = _ingest(monkeypatch, _responder(404))          # no X-Request-ID
    ob = Outbox()
    rid, _ = ob.record(_env("g1-shape-1"))
    result = await DeliveryWorker(ob, ingest).tick_once()

    row = ob.by_id(rid)
    assert row.status != OutboxStatus.DEAD_LETTER, (
        "the exact G1 failure shape must never destroy an event on attempt one")
    assert row.status == OutboxStatus.RETRYING
    assert result["dead"] == 0
    assert result["retrying"] == 1


@pytest.mark.asyncio
async def test_queued_cannot_transition_directly_to_dead_letter_on_first_404(monkeypatch):
    """Regression lock on the transition itself, not just the end state."""
    ingest = _ingest(monkeypatch, _responder(404))
    ob = Outbox()
    rid, status = ob.record(_env("g1-shape-2"))
    assert status == OutboxStatus.QUEUED

    await DeliveryWorker(ob, ingest).tick_once()
    row = ob.by_id(rid)
    assert (row.status, row.attempts) == (OutboxStatus.RETRYING, 1)
    assert "UNATTRIBUTED_FAILURE" in (row.last_error or "")


@pytest.mark.asyncio
async def test_unattributed_404_classification_is_explicit(monkeypatch):
    ingest = _ingest(monkeypatch, _responder(404))
    out = await ingest.deliver([_env("g1-shape-3")])
    assert out["outcome"] == IngestOutcome.RETRYABLE
    assert out["classification"] == DeliveryClassification.UNATTRIBUTED_FAILURE
    assert out["app_attributed"] is False
    assert ingest.failed_unattributed == 1
    assert ingest.failed_fatal == 0


# ── 2 · an ATTRIBUTED 404 is still not terminal ───────────────────────
# The application's only ingest 404 is "collector not found", which a later
# enrolment legitimately resolves.
@pytest.mark.asyncio
async def test_attributed_404_is_still_retryable(monkeypatch):
    ingest = _ingest(monkeypatch, _responder(404, RID_HEADER))
    ob = Outbox()
    rid, _ = ob.record(_env("attr-404"))
    await DeliveryWorker(ob, ingest).tick_once()
    assert ob.by_id(rid).status == OutboxStatus.RETRYING
    assert ingest.last_classification == DeliveryClassification.UNATTRIBUTED_FAILURE


# ── 3 · retry accounting advances, then exhausts truthfully ───────────
@pytest.mark.asyncio
async def test_retry_attempts_advance_and_exhaust_explicitly(monkeypatch):
    ingest = _ingest(monkeypatch, _responder(404))
    ob = Outbox(max_attempts=3, backoff_seconds=(0, 0, 0))
    rid, _ = ob.record(_env("exhaust-1"))
    worker = DeliveryWorker(ob, ingest)

    await worker.tick_once()
    assert (ob.by_id(rid).status, ob.by_id(rid).attempts) == (OutboxStatus.RETRYING, 1)
    await worker.tick_once()
    assert (ob.by_id(rid).status, ob.by_id(rid).attempts) == (OutboxStatus.RETRYING, 2)
    result = await worker.tick_once()

    row = ob.by_id(rid)
    assert row.status == OutboxStatus.DEAD_LETTER       # bounded, never infinite
    assert row.attempts == 3
    assert result["dead"] == 1
    # Exhaustion is its own truthful disposition, distinct from a refusal.
    assert "retries exhausted" in (row.last_error or "")
    assert "AUTHORITATIVE_TERMINAL" not in (row.last_error or "")


# ── 4 · existing retryable contract is unchanged ──────────────────────
@pytest.mark.parametrize("status", [408, 429, 500, 502, 503, 504])
@pytest.mark.asyncio
async def test_known_retryable_statuses_stay_retryable(monkeypatch, status):
    ingest = _ingest(monkeypatch, _responder(status, RID_HEADER))
    ob = Outbox()
    rid, _ = ob.record(_env(f"retry-{status}"))
    await DeliveryWorker(ob, ingest).tick_once()
    assert ob.by_id(rid).status == OutboxStatus.RETRYING
    assert ingest.last_classification == DeliveryClassification.RETRYABLE


# ── 5 · attributed refusals remain fail-closed and terminal ───────────
@pytest.mark.parametrize("status", [400, 401, 403, 409, 413, 422])
@pytest.mark.asyncio
async def test_app_attributed_refusal_is_terminal(monkeypatch, status):
    ingest = _ingest(monkeypatch, _responder(status, RID_HEADER))
    ob = Outbox()
    rid, _ = ob.record(_env(f"refusal-{status}"))
    result = await DeliveryWorker(ob, ingest).tick_once()

    row = ob.by_id(rid)
    assert row.status == OutboxStatus.DEAD_LETTER
    assert result["dead"] == 1
    assert ingest.last_classification == DeliveryClassification.AUTHORITATIVE_TERMINAL
    assert ingest.failed_fatal == 1


@pytest.mark.parametrize("status", [400, 401, 403, 409, 422])
@pytest.mark.asyncio
async def test_unattributed_4xx_is_retried_not_destroyed(monkeypatch, status):
    """Without attribution even these are only ever bounded-retried."""
    ingest = _ingest(monkeypatch, _responder(status))
    ob = Outbox()
    rid, _ = ob.record(_env(f"unattr-{status}"))
    await DeliveryWorker(ob, ingest).tick_once()
    assert ob.by_id(rid).status == OutboxStatus.RETRYING
    assert ingest.failed_fatal == 0


# ── 6 · a refusal is NEVER laundered into success ─────────────────────
@pytest.mark.parametrize("status,headers", [(403, RID_HEADER), (403, {}),
                                            (401, RID_HEADER), (404, {})])
@pytest.mark.asyncio
async def test_auth_and_tenant_rejection_never_becomes_delivered(monkeypatch,
                                                                 status, headers):
    ingest = _ingest(monkeypatch, _responder(status, headers))
    ob = Outbox()
    rid, _ = ob.record(_env(f"never-ok-{status}-{len(headers)}"))
    result = await DeliveryWorker(ob, ingest).tick_once()
    assert ob.by_id(rid).status != OutboxStatus.DELIVERED
    assert result["delivered"] == 0
    assert ingest.delivered == 0


# ── 7 · acceptance still means accepted ───────────────────────────────
@pytest.mark.asyncio
async def test_2xx_still_delivers(monkeypatch):
    ingest = _ingest(monkeypatch, _responder(200, RID_HEADER))
    ob = Outbox()
    rid, _ = ob.record(_env("ok-1"))
    result = await DeliveryWorker(ob, ingest).tick_once()
    assert ob.by_id(rid).status == OutboxStatus.DELIVERED
    assert result["delivered"] == 1
    assert ingest.last_classification == DeliveryClassification.ACCEPTED
    assert ob.by_id(rid).last_error is None


# ── 8 · transport failure contract unchanged ──────────────────────────
@pytest.mark.asyncio
async def test_transport_error_stays_retryable(monkeypatch):
    def handler(request):
        raise httpx.ConnectError("connection refused")
    ingest = _ingest(monkeypatch, handler)
    ob = Outbox()
    rid, _ = ob.record(_env("transport-1"))
    await DeliveryWorker(ob, ingest).tick_once()
    assert ob.by_id(rid).status == OutboxStatus.RETRYING
    assert ingest.last_classification == DeliveryClassification.RETRYABLE


# ── 9 · durability / idempotency unaffected ───────────────────────────
@pytest.mark.asyncio
async def test_idempotency_and_durability_unaffected_by_404(monkeypatch):
    ingest = _ingest(monkeypatch, _responder(404))
    ob = Outbox()
    r1, s1 = ob.record(_env("dur-1"))
    r2, s2 = ob.record(_env("dur-1"))          # same identity
    assert r1 == r2                            # one durable row, not two

    await DeliveryWorker(ob, ingest).tick_once()
    # The row survives with its payload intact — recovery stays possible.
    row = ob.by_id(r1)
    assert row.status == OutboxStatus.RETRYING
    assert row.to_envelope().raw == {"xml": "<Event/>"}
    assert ob.counts().get("delivered", 0) == 0


# ── 10 · a 404 outage must not consume acquisition progress ───────────
@pytest.mark.asyncio
async def test_404_does_not_acknowledge_or_drop_the_row(monkeypatch):
    """Bookmark advancement is driven by delivery acknowledgement; a 404 must
    neither acknowledge nor discard, so acquisition progress is untouched."""
    ingest = _ingest(monkeypatch, _responder(404))
    ob = Outbox()
    rid, _ = ob.record(_env("bookmark-1"))
    before = ob.counts()
    await DeliveryWorker(ob, ingest).tick_once()
    after = ob.counts()
    assert after.get("delivered", 0) == before.get("delivered", 0) == 0
    assert ob.by_id(rid) is not None
    assert sum(after.values()) == sum(before.values())   # nothing lost
