"""Durable delivery receipts · the MACHINE authority surface.

The collector must be able to ask "what did you actually do with these
deliveries?" with the same tenant-pinned credential it delivers with, because
permanent automatic reconciliation cannot depend on a human console session.

What these tests hold:

  · the surface exists and is READ-ONLY (it writes nothing and re-decides
    nothing — the accounting comes from `services.delivery_reconciliation`);
  · it is unreachable without `collectors.enroll`;
  · scope is the CREDENTIAL's tenant, never a header claim and never
    cross-tenant;
  · the named collector must exist AND belong to that tenant;
  · every identity must belong to that collector;
  · the response carries the authority binding the endpoint verifies against.

EVIDENCE LABELLING — TEST/SYNTHETIC. Synthetic tenants, synthetic collector,
synthetic claims. No endpoint state and no production data.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from pymongo import MongoClient

os.environ.setdefault("DB_NAME", "test_database")

from routers import xdr_api_keys as ak                          # noqa: E402
from routers import xdr_ingest as ingest_router                 # noqa: E402
from server import app                                          # noqa: E402
from services import delivery_reconciliation as recon           # noqa: E402
from services import ingest_idempotency as idem                 # noqa: E402
from services import tenant_registry as reg                     # noqa: E402

PATH = "/api/xdr/ingest/delivery/receipts"
#: Every id carries the xdist worker id: the fixtures below create and then
#: delete real registry objects, and a sibling worker must never be able to
#: delete the tenancy this worker is still using.
_WORKER = os.environ.get("PYTEST_XDIST_WORKER", "main")
_RUN = f"{_WORKER}{uuid.uuid4().hex[:8]}"
TENANT = f"ten_receipts_{_RUN}"
OTHER_TENANT = f"ten_receipts_other_{_RUN}"
COLLECTOR = f"col-receipts-{_RUN}"
OTHER_COLLECTOR = f"col-receipts-other-{_RUN}"
SOURCE = "windows-security-evd"

#: Fixtures are written through the SAME collection handles the application
#: authenticates and resolves tenancy with, so a sibling suite that rebinds a
#: client cannot make this module's own credential invisible to the app.
_db = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]


def _keys_coll():
    return ak._coll()                                        # noqa: SLF001


def _collectors_coll():
    return ingest_router._c_collectors()                     # noqa: SLF001


def _evidence_db():
    """The same database the receipt surface reads its facts from."""
    from routers.xdr_ingest_routing import _db as _routing_db
    return _routing_db()

ORG = f"org_receipts_{_RUN}"


def _mint(tenant: str = TENANT, scopes=("collectors.enroll",)) -> str:
    raw = "nvx_" + secrets.token_hex(24)
    now = datetime.now(timezone.utc).isoformat()
    _keys_coll().insert_one({
        "id": f"key_{uuid.uuid4().hex[:20]}", "tenant_id": tenant,
        "name": f"receipts-test-{uuid.uuid4().hex[:8]}", "prefix": raw[:12],
        "hash": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        "scopes": list(scopes), "enabled": True, "revoked_at": None,
        "expires_at": None, "created_at": now, "updated_at": now,
        "last_used_at": None, "last_used_ip": None, "use_count": 0})
    return raw


@pytest.fixture(scope="module", autouse=True)
def _fixtures():
    # Tenancy is registry-established; telemetry and receipts never create it.
    now = datetime.now(timezone.utc).isoformat()
    reg._orgs().insert_one({"id": ORG, "slug": ORG, "display_name": ORG,
                      "kind": "CUSTOMER", "state": "ACTIVE",
                      "created_at": now, "updated_at": now,
                      "created_by": "test"})
    for tenant, cid in ((TENANT, COLLECTOR), (OTHER_TENANT, OTHER_COLLECTOR)):
        reg._tenants().insert_one({
            "id": tenant, "organization_id": ORG, "slug": tenant,
            "display_name": tenant, "kind": "CUSTOMER", "state": "ACTIVE",
            "products": ["xdr"], "created_at": now, "updated_at": now,
            "created_by": "test"})
        _collectors_coll().insert_one({
            "id": cid, "tenant_id": tenant, "name": cid,
            "authorized_sources": [SOURCE], "state": "CONNECTED"})
    yield
    _keys_coll().delete_many({"tenant_id": {"$in": [TENANT, OTHER_TENANT]}})
    _collectors_coll().delete_many({"id": {"$in": [COLLECTOR,
                                                   OTHER_COLLECTOR]}})
    reg._tenants().delete_many({"id": {"$in": [TENANT, OTHER_TENANT]}})
    reg._orgs().delete_many({"id": ORG})
    for coll in (recon.DEDUPE_COLLECTION, recon.EVIDENCE_COLLECTION,
                 recon.BLOCKS_COLLECTION, recon.RETAINED_COLLECTION):
        _evidence_db()[coll].delete_many(
            {"tenant_id": {"$in": [TENANT, OTHER_TENANT]}})


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


def _hdrs(raw: str, tenant: str = TENANT) -> dict:
    return {"X-XDR-API-Key": raw, "X-Tenant-Id": tenant}


def _identity(sei: str, tenant: str = TENANT, collector: str = COLLECTOR):
    return idem.event_identity(tenant, collector, SOURCE, sei,
                               {"EventID": 4688, "RecordId": sei})


def _seed_canonical(sei: str, tenant: str = TENANT,
                    collector: str = COLLECTOR) -> dict:
    ident = _identity(sei, tenant, collector)
    event_id = f"evt_{uuid.uuid4().hex[:16]}"
    _evidence_db()[recon.DEDUPE_COLLECTION].insert_one({
        **ident, "status": "COMPLETED", "stage": "COMPLETED",
        "delivery_count": 1, "duplicate_count": 0,
        "trace_id": f"tr_{sei}", "canonical_event_id": event_id,
        "raw_row_id": None})
    _evidence_db()[recon.EVIDENCE_COLLECTION].insert_one({
        "event_id": event_id, "tenant_id": tenant,
        "ingest_time": "2026-06-01T00:00:00+00:00", "source_event_id": sei})
    return ident


def _body(idents, collector: str = COLLECTOR, outcome="unknown_commit_state"):
    return {"collector_id": collector,
            "identities": [{"ref": f"row-{i['source_event_id']}",
                            "delivery_key": i["key"],
                            "source_event_id": i["source_event_id"],
                            "collector_id": collector,
                            "payload_digest": i["payload_digest"],
                            "endpoint_outcome": outcome}
                           for i in idents]}


# ── authority ─────────────────────────────────────────────────────────
def test_the_surface_is_unreachable_without_a_credential(client):
    r = client.post(PATH, json={"collector_id": COLLECTOR, "identities": []})
    assert r.status_code in (401, 403), r.text


def test_a_credential_without_collectors_enroll_is_refused(client):
    raw = _mint(scopes=("collectors.read",))
    r = client.post(PATH, headers=_hdrs(raw),
                    json=_body([_identity("4624-scope")]))
    assert r.status_code == 403, r.text


def test_a_machine_credential_gets_the_authoritative_disposition(client):
    raw = _mint()
    ident = _seed_canonical("4624-ok")
    r = client.post(PATH, headers=_hdrs(raw), json=_body([ident]))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["contract"] == "nivx.delivery.receipt/1"
    assert body["authority"]["tenant_id"] == TENANT
    assert body["authority"]["collector_id"] == COLLECTOR
    assert body["authority"]["read_only"] is True
    assert body["authority"]["principal_kind"] == "api_key"
    row = body["rows"][0]
    assert row["ref"] == "row-4624-ok"
    assert row["delivery_key"] == ident["key"]
    assert row["disposition"] == "DELIVERED_CANONICAL"
    assert row["bucket"] == "DELIVERED_CANONICAL"
    assert row["evidence_ref"]


def test_a_b4_retained_raw_delivery_is_reported_as_retained_not_canonical(
        client):
    raw = _mint()
    ident = _identity("4624-retained")
    _evidence_db()[recon.RETAINED_COLLECTION].insert_one({
        "id": f"raw_{uuid.uuid4().hex[:12]}", "tenant_id": TENANT,
        "collector_id": COLLECTOR, "retained_identity_key": ident["key"],
        "source_event_id": "4624-retained",
        "disposition": {"mismatch_reason": "SOURCE_RECORD_NOT_SUPPORTED"}})
    r = client.post(PATH, headers=_hdrs(raw), json=_body([ident]))
    row = r.json()["rows"][0]
    assert row["disposition"] == "DELIVERED_RETAINED_RAW"
    assert row["bucket"] == "DELIVERED_RETAINED_RAW"
    assert row["retained_raw_id"]
    assert row["evidence_ref"] is None


def test_an_unknown_delivery_is_proven_absent_not_assumed_landed(client):
    raw = _mint()
    r = client.post(PATH, headers=_hdrs(raw),
                    json=_body([_identity("4624-absent")]))
    row = r.json()["rows"][0]
    assert row["disposition"] == "NOT_FOUND"
    assert row["bucket"] == "RETRYABLE_STILL_QUEUED"


def test_an_endpoint_that_claims_delivered_with_no_record_is_unexplained(
        client):
    raw = _mint()
    r = client.post(PATH, headers=_hdrs(raw),
                    json=_body([_identity("4624-phantom")],
                               outcome="delivered"))
    row = r.json()["rows"][0]
    assert row["bucket"] == "UNEXPLAINED"
    assert r.json()["pass"] is False


# ── isolation ─────────────────────────────────────────────────────────
def test_another_tenants_collector_is_refused(client):
    raw = _mint()
    r = client.post(PATH, headers=_hdrs(raw),
                    json=_body([_identity("4624-x", OTHER_TENANT,
                                          OTHER_COLLECTOR)],
                               collector=OTHER_COLLECTOR))
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["code"] == "TENANT_ISOLATION_VIOLATION"


def test_an_unknown_collector_is_refused(client):
    raw = _mint()
    r = client.post(PATH, headers=_hdrs(raw),
                    json=_body([_identity("4624-y")],
                               collector="col-does-not-exist"))
    assert r.status_code == 404, r.text


def test_an_identity_for_another_collector_is_refused(client):
    raw = _mint()
    body = _body([_identity("4624-z")])
    body["identities"][0]["collector_id"] = OTHER_COLLECTOR
    r = client.post(PATH, headers=_hdrs(raw), json=body)
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["code"] == "COLLECTOR_IDENTITY_MISMATCH"


def test_another_tenants_evidence_is_never_described(client):
    """The same delivery identity, seeded in the OTHER tenant."""
    raw = _mint()
    ident = _seed_canonical("4624-cross", OTHER_TENANT, COLLECTOR)
    r = client.post(PATH, headers=_hdrs(raw), json=_body([ident]))
    assert r.status_code == 200, r.text
    row = r.json()["rows"][0]
    assert row["disposition"] == "NOT_FOUND", (
        "a record outside the credential's tenant must be reported as absent")
    assert row["claim"] is None


def test_a_header_cannot_widen_the_credentials_tenant(client):
    raw = _mint()
    ident = _seed_canonical("4624-hdr-scope", OTHER_TENANT, COLLECTOR)
    r = client.post(PATH, headers=_hdrs(raw, tenant=OTHER_TENANT),
                    json=_body([ident]))
    # The credential is pinned to TENANT; asking for another tenant cannot
    # succeed, and it certainly cannot return the other tenant's evidence.
    assert r.status_code in (403, 200)
    if r.status_code == 200:
        assert r.json()["authority"]["tenant_id"] == TENANT
        assert r.json()["rows"][0]["disposition"] == "NOT_FOUND"


# ── request bounds ────────────────────────────────────────────────────
def test_an_unidentifiable_delivery_is_refused(client):
    raw = _mint()
    r = client.post(PATH, headers=_hdrs(raw), json={
        "collector_id": COLLECTOR,
        "identities": [{"ref": "row-1", "endpoint_outcome": "delivering"}]})
    assert r.status_code == 400, r.text
    assert r.json()["detail"]["code"] == "RECEIPT_REQUEST_INVALID"


def test_the_population_is_bounded(client):
    raw = _mint()
    idents = [_identity(f"4624-bulk-{i}") for i in range(2)]
    body = _body(idents)
    body["identities"] = body["identities"] * 300          # 600 > 500
    r = client.post(PATH, headers=_hdrs(raw), json=body)
    assert r.status_code == 400, r.text
    assert r.json()["detail"]["max_identities"] == recon.MAX_IDENTITIES


def test_the_surface_writes_nothing(client):
    """A receipt request must not create, mutate or delete any record."""
    raw = _mint()
    ident = _seed_canonical("4624-readonly")
    before = {coll: _evidence_db()[coll].count_documents(
                  {"tenant_id": TENANT})
              for coll in (recon.DEDUPE_COLLECTION, recon.EVIDENCE_COLLECTION,
                           recon.BLOCKS_COLLECTION, recon.RETAINED_COLLECTION)}
    claim_before = _evidence_db()[recon.DEDUPE_COLLECTION].find_one({"key": ident["key"]})
    r = client.post(PATH, headers=_hdrs(raw), json=_body([ident]))
    assert r.status_code == 200, r.text
    after = {coll: _evidence_db()[coll].count_documents(
                 {"tenant_id": TENANT})
             for coll in before}
    assert before == after
    claim_after = _evidence_db()[recon.DEDUPE_COLLECTION].find_one({"key": ident["key"]})
    assert claim_before == claim_after, (
        "the receipt surface must not touch the idempotency claim")
    assert r.json()["read_only_note"]


def test_one_implementation_of_the_accounting_is_shared_with_the_analyst_surface():
    with open("/app/backend/routers/xdr_delivery_receipts.py",
              encoding="utf-8") as fh:
        src = fh.read()
    assert "delivery_reconciliation.reconcile(" in src
    assert "insert_one" not in src and "update_one" not in src
    assert "find_one_and_update" not in src
