"""STEP 34H-A · the migration control route is a CLOSED, admin-only surface.

Runs against the real app and the PREVIEW database. It never touches
production, never executes Behavior and never reads real endpoint evidence: the
only writes are migration audit records, plus — in the one `apply` test — index
metadata on a throwaway collection reached through a temporarily registered
test operation, which is removed in the same test.

HTTP goes through `TestClient` (the app's own loop); set-up and assertions use a
separate synchronous client, so these tests never fight the app's event loop.
"""
from __future__ import annotations

import inspect
import json
import os
import sys
import uuid

import jwt
import pytest
from fastapi.testclient import TestClient
from pymongo import MongoClient

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import deps  # noqa: E402
from edr_plane import migration_control as mc  # noqa: E402
from edr_plane.canonical_index_contract import \
    TARGET_CANONICAL_INDEXES  # noqa: E402
from server import app  # noqa: E402

sync = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]


@pytest.fixture(scope="module")
def client():
    """One client for the module: the context manager runs the app's real
    startup (which binds the database) and keeps a single event loop alive, so
    the route is exercised exactly as it is in the running service."""
    with TestClient(app) as c:
        yield c

BASE = "/api/internal/admin/migrations"
ENSURE = f"{BASE}/ensure-canonical-identity-indexes"


def _token(email: str) -> str:
    return jwt.encode({"sub": email}, deps.JWT_SECRET, algorithm=deps.JWT_ALG)


def _hdr(email: str):
    return {"Authorization": f"Bearer {_token(email)}"}


def _user(role: str):
    email = f"mig-{role}-{uuid.uuid4().hex[:8]}@test.local"
    sync.users.insert_one({"email": email, "role": role, "password": "x"})
    return email


@pytest.fixture
def admin_user():
    email = _user("admin")
    yield email
    sync.users.delete_one({"email": email})


@pytest.fixture
def analyst_user():
    email = _user("analyst")
    yield email
    sync.users.delete_one({"email": email})


# ── authorization ────────────────────────────────────────────────────────

def test_an_unauthenticated_caller_is_refused(client):
    assert client.post(ENSURE, json={"mode": "report"}).status_code in (401, 403)
    assert client.get(BASE).status_code in (401, 403)
    assert client.post(f"{BASE}/{mc.OP_ENSURE_IDENTITY_INDEXES}",
                       json={"mode": "apply"}).status_code in (401, 403)


def test_an_invalid_token_is_refused(client):
    bad = {"Authorization": "Bearer not-a-real-token"}
    assert client.post(ENSURE, headers=bad, json={}).status_code == 401


def test_a_non_admin_principal_is_refused(client, analyst_user):
    assert client.post(ENSURE, headers=_hdr(analyst_user),
                       json={}).status_code == 403
    assert client.get(BASE, headers=_hdr(analyst_user)).status_code == 403


def test_a_non_admin_refusal_writes_no_migration_record(client, analyst_user):
    client.post(ENSURE, headers=_hdr(analyst_user), json={})
    assert sync[mc.RUNS].count_documents({"actor": analyst_user}) == 0


# ── the surface is closed ────────────────────────────────────────────────

def test_an_arbitrary_operation_is_refused_and_audited(client, admin_user):
    resp = client.post(f"{BASE}/drop_everything", headers=_hdr(admin_user),
                       json={"mode": "apply"})
    assert resp.status_code == 400
    detail = resp.json()["detail"]
    assert detail["state"] == mc.STATE_REFUSED
    assert detail["refusal_reason"] == mc.REFUSED_UNKNOWN_OPERATION
    record = sync[mc.RUNS].find_one(
        {"migration_run_id": detail["migration_run_id"]}, {"_id": 0})
    assert record["actor"] == admin_user
    assert record["operation"] == "drop_everything"
    assert record["state"] == mc.STATE_REFUSED


def test_an_unknown_mode_is_refused(client, admin_user):
    resp = client.post(ENSURE, headers=_hdr(admin_user), json={"mode": "drop"})
    assert resp.status_code == 400
    assert resp.json()["detail"]["refusal_reason"] == mc.REFUSED_UNKNOWN_MODE


def test_no_collection_index_or_query_can_be_supplied(client, admin_user):
    """Every attempt to smuggle a target or a specification is rejected by the
    request model itself — the fields do not exist."""
    for payload in ({"mode": "apply", "collection": "users"},
                    {"mode": "apply", "index": {"key": {"x": 1}}},
                    {"mode": "apply", "filter": {}},
                    {"mode": "apply", "pipeline": [{"$out": "users"}]},
                    {"mode": "apply", "command": {"dropDatabase": 1}},
                    {"mode": "apply", "uri": "mongodb://x"},
                    {"mode": "report", "db": "admin"}):
        resp = client.post(ENSURE, headers=_hdr(admin_user), json=payload)
        assert resp.status_code == 422, payload


def test_the_registry_is_the_only_operation_source(client):
    assert mc.allowed_operations() == sorted([
        mc.OP_ENSURE_IDENTITY_INDEXES, mc.OP_BACKFILL_IDENTITY,
        mc.OP_REVERT_IDENTITY_BACKFILL, mc.OP_EXPLAIN_IDENTITY_READ_PLAN])
    src = inspect.getsource(mc)
    assert "CANONICAL_COLLECTION" in src and "TARGET_CANONICAL_INDEXES" in src
    code = "\n".join(line for line in src.splitlines()
                     if not line.strip().startswith(("#", "*", '"""')))
    for forbidden in (".drop_index(", ".drop_indexes(", ".drop(", ".rename(",
                      ".delete_many(", ".update_many(", ".aggregate(",
                      ".command("):
        assert forbidden not in code, forbidden


def test_the_registered_operations_hold_no_destructive_call(client):
    """Every operation reachable through the registry, not just the index one."""
    from edr_plane import identity_backfill as ib
    src = inspect.getsource(ib)
    code = "\n".join(line for line in src.splitlines()
                     if not line.strip().startswith(("#", "*", '"""')))
    for forbidden in (".drop_index(", ".drop_indexes(", ".drop(", ".rename(",
                      ".delete_many(", ".delete_one(", ".update_many(",
                      ".insert_many(", ".aggregate("):
        assert forbidden not in code, forbidden
    # the one command issued is an explain, and it is the only one
    assert code.count("db.command(") == 1
    assert '"explain":' in code


def test_the_route_module_exposes_no_other_write_surface(client):
    from routers import edr_migration_control as route
    src = inspect.getsource(route)
    for forbidden in ("insert_one", "update_one", "delete_one", "create_index",
                      "aggregate", "command("):
        assert forbidden not in src, forbidden
    assert 'extra": "forbid"' in src


# ── report mode, idempotency and verification ────────────────────────────

def test_report_mode_changes_nothing_and_names_the_exact_specs(client, admin_user):
    resp = client.post(ENSURE, headers=_hdr(admin_user),
                       json={"mode": "report"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["state"] == mc.STATE_COMPLETED and body["mode"] == mc.MODE_REPORT
    result = body["result"]
    assert result["collection"] == "xdr_canonical_evidence"
    assert result["existing_indexes_changed"] is False
    assert [i["name"] for i in result["indexes"]] == \
        [s["name"] for s in TARGET_CANONICAL_INDEXES]
    for item, spec in zip(result["indexes"], TARGET_CANONICAL_INDEXES):
        assert item["state"] in (mc.INDEX_WOULD_CREATE, mc.INDEX_PRESENT,
                                 mc.INDEX_NAME_CONFLICT)
        if item["state"] != mc.INDEX_NAME_CONFLICT:
            assert [tuple(kv) for kv in item["key"]] == \
                [tuple(kv) for kv in spec["key"]]
        assert item["created"] is False


def test_two_consecutive_runs_are_idempotent(client, admin_user):
    first = client.post(ENSURE, headers=_hdr(admin_user),
                        json={"mode": "report"}).json()
    second = client.post(ENSURE, headers=_hdr(admin_user),
                         json={"mode": "report"}).json()
    assert [i["state"] for i in first["result"]["indexes"]] == \
        [i["state"] for i in second["result"]["indexes"]]
    assert first["migration_run_id"] != second["migration_run_id"]
    assert second["result"]["existing_indexes_changed"] is False


def test_apply_then_reapply_creates_once_and_then_verifies(client, admin_user):
    """Proven on a THROWAWAY collection, so no real collection is indexed by a
    test: the operation is registered against a scratch spec, exercised twice,
    and unregistered again."""
    scratch = f"t34ha_scratch_{uuid.uuid4().hex[:8]}"
    spec = {"name": "t34ha_idx", "key": (("tenant_id", 1), ("x", -1))}

    async def op(db, *, mode, run_id=""):
        res = await mc._ensure_one(db[scratch], spec,
                                   apply_changes=(mode == "apply"),
                                   legacy_background=False)
        return {"indexes": [res], "existing_indexes_changed": False,
                "collection": scratch, "ok": True}

    mc.OPERATIONS["t34ha_scratch_op"] = op
    try:
        sync[scratch].insert_one({"tenant_id": "t", "x": 1, "y": 1})
        url = f"{BASE}/t34ha_scratch_op"
        dry = client.post(url, headers=_hdr(admin_user),
                          json={"mode": "report"}).json()
        assert dry["result"]["indexes"][0]["state"] == mc.INDEX_WOULD_CREATE
        made = client.post(url, headers=_hdr(admin_user),
                           json={"mode": "apply"}).json()
        assert made["result"]["indexes"][0]["state"] == mc.INDEX_CREATED
        assert [tuple(kv) for kv in made["result"]["indexes"][0]["key"]] == \
            [("tenant_id", 1), ("x", -1)]
        again = client.post(url, headers=_hdr(admin_user),
                            json={"mode": "apply"}).json()
        assert again["result"]["indexes"][0]["state"] == mc.INDEX_PRESENT
        assert again["result"]["indexes"][0]["created"] is False

        # a same-name / different-key index is REFUSED, never resolved
        spec["key"] = (("tenant_id", 1), ("y", -1))
        conflict = client.post(url, headers=_hdr(admin_user),
                               json={"mode": "apply"}).json()
        assert conflict["result"]["indexes"][0]["state"] == mc.INDEX_NAME_CONFLICT
        names = [i["name"] for i in sync[scratch].list_indexes()]
        assert names.count("t34ha_idx") == 1
        assert dict(sync[scratch].index_information()
                    )["t34ha_idx"]["key"] == [("tenant_id", 1), ("x", -1)]
    finally:
        mc.OPERATIONS.pop("t34ha_scratch_op", None)
        sync[scratch].drop()


# ── concurrency, audit and secrecy ───────────────────────────────────────

def test_a_concurrent_duplicate_request_conflicts_instead_of_racing(client, admin_user):
    sync[mc.LOCKS].insert_one({
        "_id": mc.OP_ENSURE_IDENTITY_INDEXES, "migration_run_id": "mig_held",
        "actor": "someone-else", "acquired_at": "2026-06-01T00:00:00Z"})
    try:
        resp = client.post(ENSURE, headers=_hdr(admin_user),
                           json={"mode": "apply"})
        assert resp.status_code == 409
        detail = resp.json()["detail"]
        assert detail["refusal_reason"] == mc.REFUSED_CONCURRENT
        assert detail["conflict"]["holder_run_id"] == "mig_held"
        assert detail["conflict"]["stale"] is True
        record = sync[mc.RUNS].find_one(
            {"migration_run_id": detail["migration_run_id"]}, {"_id": 0})
        assert record["state"] == mc.STATE_REFUSED
    finally:
        sync[mc.LOCKS].delete_one({"_id": mc.OP_ENSURE_IDENTITY_INDEXES})


def test_the_lock_is_released_so_the_next_run_is_not_blocked(client, admin_user):
    client.post(ENSURE, headers=_hdr(admin_user), json={"mode": "report"})
    assert sync[mc.LOCKS].find_one({"_id": mc.OP_ENSURE_IDENTITY_INDEXES}) is None
    assert client.post(ENSURE, headers=_hdr(admin_user),
                       json={"mode": "report"}).status_code == 200


def test_a_failing_operation_is_recorded_and_releases_the_lock(client, admin_user):
    async def boom(db, *, mode, run_id=""):
        raise RuntimeError("deliberate test failure")

    mc.OPERATIONS["t34ha_failing_op"] = boom
    try:
        resp = client.post(f"{BASE}/t34ha_failing_op",
                           headers=_hdr(admin_user), json={"mode": "apply"})
        assert resp.status_code == 500
        detail = resp.json()["detail"]
        assert detail["state"] == mc.STATE_FAILED
        assert detail["failure"] == "RuntimeError"
        record = sync[mc.RUNS].find_one(
            {"migration_run_id": detail["migration_run_id"]}, {"_id": 0})
        assert record["state"] == mc.STATE_FAILED
        assert record["started_at"] and record["completed_at"]
        assert sync[mc.LOCKS].find_one({"_id": "t34ha_failing_op"}) is None
    finally:
        mc.OPERATIONS.pop("t34ha_failing_op", None)


def test_every_lifecycle_state_is_durably_recorded(client, admin_user):
    body = client.post(ENSURE, headers=_hdr(admin_user),
                       json={"mode": "report"}).json()
    record = sync[mc.RUNS].find_one(
        {"migration_run_id": body["migration_run_id"]}, {"_id": 0})
    for field in ("operation", "mode", "actor", "requested_at", "started_at",
                  "completed_at", "state", "result"):
        assert field in record, field
    assert record["actor"] == admin_user
    assert record["state"] == mc.STATE_COMPLETED


def test_no_secret_or_connection_detail_is_ever_returned(client, admin_user):
    body = client.post(ENSURE, headers=_hdr(admin_user),
                       json={"mode": "report"}).json()
    listing = client.get(BASE, headers=_hdr(admin_user)).json()
    blob = json.dumps([body, listing]).lower()
    for secret in ("mongodb://", "mongodb+srv", "password", "jwt_secret",
                   "authorization", "bearer", "mongo_url", "@cluster",
                   "api_key", "secret"):
        assert secret not in blob, secret


def test_the_listing_exposes_only_registered_operations(client, admin_user):
    body = client.get(BASE, headers=_hdr(admin_user)).json()
    assert body["allowed_operations"] == mc.allowed_operations()
    assert mc.OP_ENSURE_IDENTITY_INDEXES in body["allowed_operations"]
    assert body["modes"] == list(mc.MODES)
    assert isinstance(body["runs"], list)
