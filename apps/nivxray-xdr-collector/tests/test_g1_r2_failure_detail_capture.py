"""G1-R2 · Failure detail capture.

R1 stopped an unattributed 404 from destroying an event. R2 makes the *next*
incident diagnosable without a forensic expedition.

The G1 loss of 14,868 events cost days of analysis because the only thing
preserved about each failure was the literal string ``"HTTP 404"``. Everything
that distinguishes an infrastructure refusal from an authoritative application
refusal — the ``X-Request-ID`` stamp, the content type, the body, the resolved
URL — was read and thrown away before the terminal decision was written.

What R2 guarantees:

    every failed delivery attempt durably records, on the row itself, what the
    far side actually said and whether it was the authoritative application

and what it must never become:

    a payload store, or a place a credential can leak.

So the capture is bounded (300-char body excerpt) and redacted.
"""
from __future__ import annotations

import json
import sqlite3
import tempfile

import httpx
import pytest

from framework.base            import Envelope
from framework.delivery        import (APP_ATTRIBUTION_HEADER,
                                       FAILURE_BODY_EXCERPT_CHARS,
                                       DeliveryClassification, IngestClient)
from framework.delivery_worker import DeliveryWorker
from framework.outbox          import Outbox, OutboxStatus

URL = "https://ingest.example/api/xdr/ingest/telemetry"
RID = "nvx-r2-0123456789ab"


def _env(eid="r2-1"):
    return Envelope(
        tenant_id="ten_f1a5479243e901cf159e230fa0",
        source="windows_powershell",
        source_event_id=("ten_f1a5479243e901cf159e230fa0|DESKTOP-A9HGFJJ|"
                         "Microsoft-Windows-PowerShell/Operational|510"),
        connector_id="windows-eventlog-g1proof01",
        collector_id="col_d6b0b9e8172246f29be9",
        collection_method="windows-eventlog",
        parser_version="powershell-1",
        source_timestamp="2026-09-22T17:50:00+00:00",
        collection_timestamp="2026-09-22T17:50:01+00:00",
        event_type="script_block",
        raw={"xml": "<Event/>"},
        canonical={},
        declared_source="windows-powershell-evd",
    )


def _ingest(monkeypatch, handler):
    monkeypatch.setenv("NIVX_INGEST_URL", URL)
    monkeypatch.setenv("NIVX_INGEST_TOKEN", "nvx_62373180secretsuffix")
    transport = httpx.MockTransport(handler)
    orig = httpx.AsyncClient

    def _c(*a, **kw):
        kw["transport"] = transport
        return orig(*a, **kw)

    monkeypatch.setattr(httpx, "AsyncClient", _c)
    return IngestClient()


def _responder(status, headers=None, text=""):
    def handler(request):
        return httpx.Response(status, headers=headers or {}, text=text)
    return handler


# ── 1 · THE G1 SHAPE IS NOW SELF-EXPLAINING ───────────────────────────
@pytest.mark.asyncio
async def test_infrastructure_404_records_absence_of_attribution(monkeypatch):
    """An edge 404: no X-Request-ID, an HTML-ish body, no app content type."""
    ingest = _ingest(monkeypatch, _responder(
        404, {"content-type": "text/html", "server": "edge-proxy"},
        "<html><body>404 Not Found</body></html>"))
    ob = Outbox()
    rid, _ = ob.record(_env("edge-404"))
    await DeliveryWorker(ob, ingest).tick_once()

    d = ob.by_id(rid).failure_detail
    assert d is not None, "the failure must be self-explaining on the row"
    assert d["classification"] == DeliveryClassification.UNATTRIBUTED_FAILURE
    assert d["status_code"] == 404
    assert d["app_attributed"] is False
    assert d["request_id"] is None          # the decisive discriminator
    assert d["content_type"] == "text/html"
    assert d["server"] == "edge-proxy"
    assert "404 Not Found" in d["body_excerpt"]
    assert d["url"] == URL
    assert d["attempted_at"]


@pytest.mark.asyncio
async def test_application_404_is_distinguishable_from_infrastructure_404(monkeypatch):
    """Same status code, opposite meaning — the record must separate them."""
    ingest = _ingest(monkeypatch, _responder(
        404, {APP_ATTRIBUTION_HEADER: RID, "content-type": "application/json"},
        '{"detail":"collector not found"}'))
    ob = Outbox()
    rid, _ = ob.record(_env("app-404"))
    await DeliveryWorker(ob, ingest).tick_once()

    d = ob.by_id(rid).failure_detail
    assert d["status_code"] == 404
    assert d["app_attributed"] is True
    assert d["request_id"] == RID
    assert d["content_type"] == "application/json"
    assert "collector not found" in d["body_excerpt"]
    # Still not terminal (R1 contract preserved).
    assert ob.by_id(rid).status == OutboxStatus.RETRYING


# ── 2 · bounded, and never a payload store ────────────────────────────
@pytest.mark.asyncio
async def test_body_excerpt_is_bounded_and_flagged_truncated(monkeypatch):
    big = "X" * 5000
    ingest = _ingest(monkeypatch, _responder(
        400, {APP_ATTRIBUTION_HEADER: RID}, big))
    ob = Outbox()
    rid, _ = ob.record(_env("bounded-1"))
    await DeliveryWorker(ob, ingest).tick_once()

    d = ob.by_id(rid).failure_detail
    assert len(d["body_excerpt"]) == FAILURE_BODY_EXCERPT_CHARS
    assert d["body_bytes"] == 5000
    assert d["body_truncated"] is True


# ── 3 · a failure record must never leak the credential ───────────────
@pytest.mark.asyncio
async def test_credential_is_redacted_from_failure_detail(monkeypatch):
    """Even if the far side echoes the key back at us, it must not land."""
    leak = ('{"detail":"bad key nvx_62373180secretsuffix",'
            '"authorization":"Bearer eyJhbGciOi.payload.sig",'
            '"api_key":"nvx_deadbeefcafe"}')
    ingest = _ingest(monkeypatch, _responder(
        403, {APP_ATTRIBUTION_HEADER: RID}, leak))
    ob = Outbox()
    rid, _ = ob.record(_env("redact-1"))
    await DeliveryWorker(ob, ingest).tick_once()

    blob = json.dumps(ob.by_id(rid).failure_detail)
    assert "nvx_62373180secretsuffix" not in blob
    assert "nvx_deadbeefcafe" not in blob
    assert "eyJhbGciOi.payload.sig" not in blob
    assert "nvx_<redacted>" in blob
    assert "Bearer <redacted>" in blob


# ── 4 · every failure class carries a record ──────────────────────────
@pytest.mark.parametrize("status,headers,expected", [
    (404, {},                              DeliveryClassification.UNATTRIBUTED_FAILURE),
    (403, {},                              DeliveryClassification.UNATTRIBUTED_FAILURE),
    (403, {APP_ATTRIBUTION_HEADER: RID},   DeliveryClassification.AUTHORITATIVE_TERMINAL),
    (429, {APP_ATTRIBUTION_HEADER: RID},   DeliveryClassification.RETRYABLE),
    (503, {APP_ATTRIBUTION_HEADER: RID},   DeliveryClassification.RETRYABLE),
])
@pytest.mark.asyncio
async def test_all_failure_classes_persist_detail(monkeypatch, status, headers,
                                                  expected):
    ingest = _ingest(monkeypatch, _responder(status, headers, "body"))
    ob = Outbox()
    rid, _ = ob.record(_env(f"cls-{status}-{len(headers)}"))
    await DeliveryWorker(ob, ingest).tick_once()

    d = ob.by_id(rid).failure_detail
    assert d is not None
    assert d["classification"] == expected
    assert d["status_code"] == status
    assert d["reason"]


@pytest.mark.asyncio
async def test_transport_failure_records_detail_without_a_response(monkeypatch):
    def handler(request):
        raise httpx.ConnectError("connection refused")
    ingest = _ingest(monkeypatch, handler)
    ob = Outbox()
    rid, _ = ob.record(_env("transport-r2"))
    await DeliveryWorker(ob, ingest).tick_once()

    d = ob.by_id(rid).failure_detail
    assert d["classification"] == DeliveryClassification.RETRYABLE
    assert d["status_code"] is None
    assert d["transport_error"] == "ConnectError"
    assert d["request_id"] is None
    assert d["url"] == URL


@pytest.mark.asyncio
async def test_not_configured_records_detail(monkeypatch):
    monkeypatch.delenv("NIVX_INGEST_URL", raising=False)
    ingest = IngestClient()
    ob = Outbox()
    rid, _ = ob.record(_env("notcfg-1"))
    await DeliveryWorker(ob, ingest).tick_once()

    d = ob.by_id(rid).failure_detail
    assert d["reason"] == "ingest_not_configured"
    assert d["url"] is None


# ── 5 · exhaustion is recorded as its own disposition ─────────────────
@pytest.mark.asyncio
async def test_exhaustion_disposition_is_recorded(monkeypatch):
    ingest = _ingest(monkeypatch, _responder(404, {}, "edge 404"))
    ob = Outbox(max_attempts=2, backoff_seconds=(0, 0))
    rid, _ = ob.record(_env("exhaust-r2"))
    worker = DeliveryWorker(ob, ingest)
    await worker.tick_once()
    assert ob.by_id(rid).failure_detail.get("disposition") is None
    await worker.tick_once()

    row = ob.by_id(rid)
    assert row.status == OutboxStatus.DEAD_LETTER
    d = row.failure_detail
    assert d["disposition"] == "RETRIES_EXHAUSTED"
    assert d["app_attributed"] is False
    assert d["classification"] == DeliveryClassification.UNATTRIBUTED_FAILURE


# ── 6 · the record is refreshed per attempt, not accumulated ──────────
@pytest.mark.asyncio
async def test_detail_reflects_the_latest_attempt(monkeypatch):
    seq = [(503, {APP_ATTRIBUTION_HEADER: RID}), (404, {})]

    def handler(request):
        status, headers = seq.pop(0) if seq else (404, {})
        return httpx.Response(status, headers=headers, text="x")

    ingest = _ingest(monkeypatch, handler)
    ob = Outbox(max_attempts=5, backoff_seconds=(0, 0, 0, 0, 0))
    rid, _ = ob.record(_env("latest-1"))
    worker = DeliveryWorker(ob, ingest)

    await worker.tick_once()
    assert ob.by_id(rid).failure_detail["status_code"] == 503
    await worker.tick_once()
    d = ob.by_id(rid).failure_detail
    assert d["status_code"] == 404
    assert d["app_attributed"] is False


# ── 7 · durability: it survives a restart, and migrates additively ────
def test_failure_detail_persists_across_reopen():
    with tempfile.TemporaryDirectory() as tmp:
        ob = Outbox(path=tmp)
        rid, _ = ob.record(_env("persist-1"))
        ob.mark_retry(rid, error="HTTP 404 | UNATTRIBUTED_FAILURE",
                      detail={"classification": "UNATTRIBUTED_FAILURE",
                              "status_code": 404, "request_id": None})
        ob.close()

        reopened = Outbox(path=tmp)
        d = reopened.by_id(rid).failure_detail
        assert d["status_code"] == 404
        assert d["classification"] == "UNATTRIBUTED_FAILURE"
        reopened.close()


def test_additive_migration_on_a_pre_r2_database():
    """A database written before R2 must open, not crash, and read back None."""
    with tempfile.TemporaryDirectory() as tmp:
        legacy = Outbox(path=tmp)
        rid, _ = legacy.record(_env("legacy-1"))
        legacy.close()
        # Simulate the pre-R2 shape by dropping the column via table rebuild.
        conn = sqlite3.connect(f"{tmp}/outbox.db")
        cols = [r[1] for r in conn.execute("PRAGMA table_info(envelopes)")]
        assert "failure_detail_json" in cols
        keep = [c for c in cols if c != "failure_detail_json"]
        conn.execute("ALTER TABLE envelopes RENAME TO envelopes_old")
        conn.execute(f"CREATE TABLE envelopes ({','.join(k + ' TEXT' for k in keep)})")
        conn.execute(f"INSERT INTO envelopes SELECT {','.join(keep)} FROM envelopes_old")
        conn.execute("DROP TABLE envelopes_old")
        conn.commit(); conn.close()

        migrated = Outbox(path=tmp)
        assert migrated.by_id(rid).failure_detail is None
        migrated.close()


# ── 8 · success must not carry a stale failure narrative ──────────────
@pytest.mark.asyncio
async def test_success_clears_client_side_failure_detail(monkeypatch):
    ingest = _ingest(monkeypatch, _responder(200, {APP_ATTRIBUTION_HEADER: RID}))
    ob = Outbox()
    rid, _ = ob.record(_env("ok-r2"))
    await DeliveryWorker(ob, ingest).tick_once()
    assert ob.by_id(rid).status == OutboxStatus.DELIVERED
    assert ob.by_id(rid).last_error is None
    assert ingest.last_failure_detail is None
    assert ingest.status()["last_failure_detail"] is None
