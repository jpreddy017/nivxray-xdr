"""P0 · Dedupe production hardening — fault conditions, not happy-path replay.

Owner directive 2026-06:
  * the idempotency store must NOT fail open,
  * the claim lifecycle must never permit an extra raw/canonical chain after a
    crash or a transient fault,
  * retention must be bounded WITHOUT undermining idempotency.

These tests exercise the real ASGI app and the real store, and inject faults by
monkeypatching the store boundary — never by weakening a check.
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from pymongo import MongoClient
from pymongo.errors import PyMongoError

os.environ.setdefault("DB_NAME", "test_database")

from routers import xdr_ingest as ing  # noqa: E402
from server import app  # noqa: E402
from services import ingest_idempotency as idem  # noqa: E402

_db = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]
_claims = _db[idem.COLLECTION]

TENANT = f"harden-{uuid.uuid4().hex[:8]}"
ING = "/api/xdr/ingest/telemetry"

CEF_LINE = (
    "<14>Jun 10 12:40:11 fw01 CEF:0|Palo Alto Networks|PAN-OS|10.2|4001|"
    "encoded powershell observed|8|src=10.4.9.22 spt=51455 dst=203.0.113.55 "
    "dpt=443 proto=TCP dvchost=HYD-FW01 duser=r.mehta dproc=powershell.exe "
    "dpid=4412 cs1Label=CommandLine "
    "cs1=powershell.exe -enc SQBFAFgAJwBoAHQAdABwAA== act=alert"
)


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def _auth(c):
    r = c.post("/api/auth/login", json={"email": os.environ["ADMIN_EMAIL"],
                                        "password": os.environ["ADMIN_PASSWORD"]})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}",
            "X-Tenant-Id": TENANT}


@pytest.fixture(scope="module")
def collector(client):
    hdrs = _auth(client)
    r = client.post("/api/xdr/collectors", headers=hdrs,
                    json={"name": f"harden-{uuid.uuid4().hex[:8]}",
                          "protocol": "webhook"})
    assert r.status_code == 200, r.text
    yield r.json()["data"]["id"]
    _db["xdr_collectors"].delete_many({"tenant_id": TENANT})
    _db["xdr_canonical_events"].delete_many({"tenant_id": TENANT})
    _db["xdr_canonical_evidence"].delete_many({"tenant_id": TENANT})
    _db["workspace_cases"].delete_many({"tenant_id": TENANT})
    _claims.delete_many({"tenant_id": TENANT})


def _env(collector, sei, line=CEF_LINE):
    return {"tenant_id": TENANT, "collector_id": collector,
            "collection_method": "webhook", "source": "fw",
            "connector_id": "webhook-harden", "event_type": "alert",
            "source_event_id": sei,
            "raw": {"line": line, "payload_format": "cef"}}


def _post(client, envelope):
    return client.post(ING, headers=_auth(client),
                       json={"envelopes": [envelope]})


def _first(resp):
    return (resp.json().get("reasoning") or [{}])[0]


def _counts(sei):
    return (
        _db["xdr_canonical_events"].count_documents(
            {"tenant_id": TENANT, "source_event_id": sei}),
        _db["xdr_canonical_evidence"].count_documents({"tenant_id": TENANT}),
        _db["workspace_cases"].count_documents(
            {"tenant_id": TENANT, "doc_type": "xdr_incident"}),
    )


def _claim_of(collector, sei):
    ident = idem.event_identity(TENANT, collector, "fw", sei,
                               {"line": CEF_LINE, "payload_format": "cef"})
    return _claims.find_one({"key": ident["key"]}), ident["key"]


# ══ 1 · the store must NOT fail open ══════════════════════════════
def test_unbound_store_refuses_ingest_with_retryable_503(client, collector,
                                                          monkeypatch):
    monkeypatch.setattr(idem, "_client", None)
    monkeypatch.setattr(idem, "_index_ready", False)
    sei = f"unbound-{uuid.uuid4().hex[:8]}"
    r = _post(client, _env(collector, sei))
    assert r.status_code == 503, r.text
    d = r.json()["detail"]
    assert d["code"] == "INGEST_IDEMPOTENCY_UNAVAILABLE"
    assert d["retryable"] is True
    # Nothing may have been written without dedupe protection.
    assert _counts(sei)[0] == 0


def test_claim_write_failure_refuses_ingest(client, collector, monkeypatch):
    def boom(_identity):
        raise idem.IdempotencyUnavailable("unique index write failed")
    monkeypatch.setattr(ing.idem, "claim", boom)
    sei = f"claimfail-{uuid.uuid4().hex[:8]}"
    r = _post(client, _env(collector, sei))
    assert r.status_code == 503
    assert r.json()["detail"]["code"] == "INGEST_IDEMPOTENCY_UNAVAILABLE"
    assert _counts(sei)[0] == 0


def test_index_creation_failure_is_unavailable_not_unprotected(monkeypatch):
    class FakeColl:
        def create_index(self, *a, **k):
            raise PyMongoError("no index for you")

    class FakeDB(dict):
        def __getitem__(self, _):
            return FakeColl()

    monkeypatch.setattr(idem, "_index_ready", False)
    monkeypatch.setattr(idem, "_client", {idem._DB_NAME: FakeDB()})
    with pytest.raises(idem.IdempotencyUnavailable):
        idem._coll()


def test_store_error_during_claim_is_translated(monkeypatch):
    class FakeColl:
        def create_index(self, *a, **k):
            return None

        def insert_one(self, *a, **k):
            raise PyMongoError("primary stepped down")

    class FakeDB(dict):
        def __getitem__(self, _):
            return FakeColl()

    monkeypatch.setattr(idem, "_index_ready", False)
    monkeypatch.setattr(idem, "_client", {idem._DB_NAME: FakeDB()})
    with pytest.raises(idem.IdempotencyUnavailable):
        idem.claim(idem.event_identity("t", "c", "s", "e", {"a": 1}))


def test_auth_is_not_weakened_by_the_idempotency_gate(client, collector):
    """The 503 path must sit AFTER authorization — an anonymous caller still
    gets a 403 and never learns whether the store is healthy."""
    r = client.post(ING, json={"envelopes": [_env(collector, "anon")]})
    assert r.status_code == 403, r.text
    assert "IDEMPOTENCY" not in r.text


# ══ 2 · claim lifecycle ═══════════════════════════════════════════
def test_successful_delivery_reaches_completed_with_retention_armed(
        client, collector):
    sei = f"complete-{uuid.uuid4().hex[:8]}"
    r = _post(client, _env(collector, sei))
    assert r.status_code == 200, r.text
    rec, _ = _claim_of(collector, sei)
    assert rec["status"] == "COMPLETED" and rec["stage"] == "COMPLETED"
    assert rec["trace_id"] and rec["canonical_event_id"]
    assert isinstance(rec["retention_at"], datetime), "retention not armed"
    assert rec["attempt"] == 1


def test_crash_before_raw_persistence_is_fully_retryable(client, collector,
                                                          monkeypatch):
    """A fault before anything is written must leave stage=NONE, and the
    retry (after the lease expires) must process the event normally."""
    sei = f"prewrite-{uuid.uuid4().hex[:8]}"
    ident = idem.event_identity(TENANT, collector, "fw", sei,
                                {"line": CEF_LINE, "payload_format": "cef"})
    state, _ = idem.claim(ident)
    assert state == "FRESH"
    rec = _claims.find_one({"key": ident["key"]})
    assert rec["stage"] == "NONE"
    # Simulate the worker dying: expire the lease.
    _claims.update_one({"key": ident["key"]}, {"$set": {
        "lease_expires_at": datetime.now(timezone.utc) - timedelta(seconds=1)}})
    state2, rec2 = idem.claim(ident)
    assert state2 == "RESUME_FULL", "a never-processed delivery must be retryable"
    assert rec2["attempt"] == 2
    # And the real request now completes, creating exactly one chain.
    _claims.update_one({"key": ident["key"]}, {"$set": {
        "lease_expires_at": datetime.now(timezone.utc) - timedelta(seconds=1)}})
    r = _post(client, _env(collector, sei))
    assert r.status_code == 200, r.text
    assert _first(r)["status"] == "REASONED"
    assert _counts(sei)[0] == 1


def test_failure_after_raw_persistence_resumes_without_a_second_raw_row(
        client, collector):
    """The exact gap the owner flagged: a fault after the raw row is written
    must NOT permit an extra raw record on retry."""
    sei = f"postraw-{uuid.uuid4().hex[:8]}"
    r = _post(client, _env(collector, sei))
    assert r.status_code == 200, r.text
    raw_before = _counts(sei)[0]
    assert raw_before == 1
    key = _claim_of(collector, sei)[1]
    # Rewind the claim to the state it would hold had reasoning never
    # finished: raw persisted, lease dead.
    _claims.update_one({"key": key}, {"$set": {
        "status": "RAW_PERSISTED", "stage": "RAW_PERSISTED",
        "retention_at": None,
        "lease_expires_at": datetime.now(timezone.utc) - timedelta(seconds=1)}})
    r2 = _post(client, _env(collector, sei))
    assert r2.status_code == 200, r2.text
    assert r2.json()["resumed"] == 1, r2.json()
    assert r2.json()["duplicates"] == 0
    assert _counts(sei)[0] == raw_before, "a SECOND raw row was written"
    rec = _claims.find_one({"key": key})
    assert rec["status"] == "COMPLETED"
    assert rec["attempt"] == 2


def test_resume_does_not_inflate_the_locked_received_counter(client, collector):
    sei = f"resumecnt-{uuid.uuid4().hex[:8]}"
    _post(client, _env(collector, sei))
    before = _db["xdr_collectors"].find_one({"id": collector})["events_received"]
    key = _claim_of(collector, sei)[1]
    _claims.update_one({"key": key}, {"$set": {
        "status": "RAW_PERSISTED", "stage": "RAW_PERSISTED",
        "retention_at": None,
        "lease_expires_at": datetime.now(timezone.utc) - timedelta(seconds=1)}})
    _post(client, _env(collector, sei))
    after = _db["xdr_collectors"].find_one({"id": collector})["events_received"]
    assert after == before, "a resumed delivery was counted as new telemetry"


def test_pipeline_fault_flags_needs_review_and_never_releases_the_claim(
        client, collector, monkeypatch):
    """A fault that may have already written canonical evidence must not be
    auto-retried into a second canonical chain."""
    sei = f"pipefault-{uuid.uuid4().hex[:8]}"

    async def boom(*a, **k):
        raise RuntimeError("detection engine exploded")

    import detection_content.xdr_pipeline as pipe
    monkeypatch.setattr(pipe, "process_event_through_pipeline", boom)
    r = _post(client, _env(collector, sei))
    assert r.status_code == 200, r.text
    assert _first(r)["status"] == "FAILED"
    rec, key = _claim_of(collector, sei)
    assert rec is not None, "the claim was released — a retry could duplicate"
    assert rec["status"] == "NEEDS_REVIEW"
    assert rec["stage"] == "REASONING_INCOMPLETE"
    assert "detection engine exploded" in rec["review_reason"]
    raw_before, _, inc_before = _counts(sei)

    monkeypatch.undo()
    r2 = _post(client, _env(collector, sei))
    assert r2.status_code == 200, r2.text
    o = _first(r2)
    assert o["status"] == "DUPLICATE_NEEDS_REVIEW"
    assert o["incident_created"] is False
    raw_after, _, inc_after = _counts(sei)
    assert raw_after == raw_before, "retry after a partial failure duplicated raw"
    assert inc_after == inc_before


def test_concurrent_duplicate_is_refused_while_the_lease_is_live(collector):
    ident = idem.event_identity(TENANT, collector, "fw",
                                f"inflight-{uuid.uuid4().hex[:8]}",
                                {"line": CEF_LINE, "payload_format": "cef"})
    assert idem.claim(ident)[0] == "FRESH"
    state, rec = idem.claim(ident)
    assert state == "IN_FLIGHT", "a concurrent copy was allowed to start work"
    assert rec["attempt"] == 1, "the live lease must not be taken over"
    assert _claims.find_one({"key": ident["key"]})["duplicate_count"] == 1


def test_completed_claim_is_never_taken_over_even_with_a_dead_lease(
        client, collector):
    sei = f"terminal-{uuid.uuid4().hex[:8]}"
    _post(client, _env(collector, sei))
    key = _claim_of(collector, sei)[1]
    _claims.update_one({"key": key}, {"$set": {
        "lease_expires_at": datetime.now(timezone.utc) - timedelta(days=1)}})
    ident = idem.event_identity(TENANT, collector, "fw", sei,
                                {"line": CEF_LINE, "payload_format": "cef"})
    state, _ = idem.claim(ident)
    assert state == "DUPLICATE"


# ══ 3 · retention must not undermine idempotency ══════════════════
def test_ttl_index_is_on_a_dedicated_field_with_expire_zero():
    idem._coll()
    info = _claims.index_information()
    ttl = info["ttl_retention_at"]
    assert ttl["key"] == [("retention_at", 1)]
    assert ttl["expireAfterSeconds"] == 0
    assert info["uniq_event_key"].get("unique") is True


def test_active_claims_are_never_ttl_eligible(collector):
    """An in-progress claim carries retention_at=None, and MongoDB's TTL
    monitor ignores a non-date value — so it can never be expired mid-flight."""
    ident = idem.event_identity(TENANT, collector, "fw",
                                f"active-{uuid.uuid4().hex[:8]}",
                                {"line": CEF_LINE, "payload_format": "cef"})
    idem.claim(ident)
    rec = _claims.find_one({"key": ident["key"]})
    assert rec["retention_at"] is None
    assert rec["status"] not in idem.TERMINAL


def test_retention_horizon_exceeds_the_collector_replay_horizon():
    assert idem.RETENTION_DAYS >= 14
    assert idem.LEASE_SECONDS >= 60


def test_terminal_claims_arm_retention_in_the_future(client, collector):
    sei = f"ttl-{uuid.uuid4().hex[:8]}"
    _post(client, _env(collector, sei))
    rec, _ = _claim_of(collector, sei)
    # pymongo returns BSON dates as naive UTC by default.
    retention = rec["retention_at"].replace(tzinfo=timezone.utc)
    assert retention > datetime.now(timezone.utc) + timedelta(days=13)


def test_replay_after_retention_window_is_a_new_delivery(client, collector):
    """Documented consequence: once the claim has been reclaimed by TTL the
    delivery is indistinguishable from a first delivery and is processed as
    one.  The window is set beyond the supported replay horizon so a
    compliant collector can never reach this state."""
    sei = f"expired-{uuid.uuid4().hex[:8]}"
    _post(client, _env(collector, sei))
    raw_before = _counts(sei)[0]
    key = _claim_of(collector, sei)[1]
    _claims.delete_one({"key": key})          # what the TTL monitor does
    r = _post(client, _env(collector, sei))
    assert r.status_code == 200
    assert _first(r)["status"] == "REASONED"
    assert _counts(sei)[0] == raw_before + 1


# ══ 4 · accepted semantics preserved ══════════════════════════════
def test_distinct_source_event_id_is_still_a_new_delivery(client, collector):
    a = _env(collector, f"dA-{uuid.uuid4().hex[:8]}")
    b = _env(collector, f"dB-{uuid.uuid4().hex[:8]}")
    r1, r2 = _post(client, a), _post(client, b)
    assert r2.json()["duplicates"] == 0
    assert _first(r1)["trace_id"] != _first(r2)["trace_id"]


def test_no_payload_only_suppression(client, collector):
    """Identical payloads with different ids must BOTH be processed, so a
    repeated real attack is never hidden."""
    line = CEF_LINE
    ids = []
    for _ in range(3):
        r = _post(client, _env(collector, f"same-{uuid.uuid4().hex[:8]}", line))
        assert r.json()["duplicates"] == 0
        ids.append(_first(r)["trace_id"])
    assert len(set(ids)) == 3
