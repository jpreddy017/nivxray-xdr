"""P0.1 · RESPONSE-EVIDENCE **WRITE** TENANT AUTHORITY — regression guard.

The defect: `POST /api/xdr/response-evidence` stored `body.tenant_id`, the
value the WRITER presented, as the tenant of the response evidence / audit /
timeline rows. Response evidence is audit material, so a writer could stamp
another customer's tenant onto it, and `execution_id` idempotency was looked
up globally, making the ref triple a cross-tenant side channel.

Owner contract (2026-06):
  * `body.tenant_id` is an ASSERTION that may be CHECKED — never authority.
  * single-tenant verified principal + no resource anchor → its one tenant.
  * any principal + authoritative incident anchor → the incident's tenant.
  * multi/all-tenant principal + no authoritative anchor → DENY. Being
    authorized for tenant B does not prove THIS evidence belongs to B.
  * idempotency is tenant-scoped: same `execution_id` in two tenants can
    neither collide nor disclose the other tenant's refs.

Only the RBAC permission gate is overridden (same as the pre-existing
harnesses); the tenant authority and the incident authority are the REAL ones.
"""
import os
from datetime import datetime, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from deps import get_current_user, init_database, validate_config
from routers.xdr_response_evidence import router
from tests.test_xdr_response_evidence import _FakeDb

validate_config()
init_database()

_W = os.environ.get("PYTEST_XDIST_WORKER", "master")
_PREFIX = f"p01write-{_W}-"

T_A, T_B, T_FOREIGN = "p01-tenant-a", "p01-tenant-b", "p01-tenant-foreign"
INC_A = f"{_PREFIX}inc-a"                     # owned by T_A
INC_FOREIGN = f"{_PREFIX}inc-foreign"         # owned by T_FOREIGN

SINGLE_A = {"email": f"{_PREFIX}single-a@test", "role": "analyst"}
MULTI_AB = {"email": f"{_PREFIX}multi-ab@test", "role": "analyst"}
ADMIN = {"email": "admin@nivxray.com", "role": "admin"}   # cross-tenant


def _app():
    app = FastAPI()
    app.state.db = _FakeDb()
    app.include_router(router, prefix="/api")
    for route in app.routes:
        dependant = getattr(route, "dependant", None)
        for dep in (dependant.dependencies if dependant else []):
            if dep.call is not None and "require_permission" \
                    in getattr(dep.call, "__qualname__", ""):
                app.dependency_overrides[dep.call] = lambda: True
    return app


def _db():
    from pymongo import MongoClient
    return MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]


@pytest.fixture
def harness():
    db = _db()
    db.workspace_cases.delete_many({"id": {"$regex": f"^{_PREFIX}"}})
    db.users.delete_many({"email": {"$regex": f"^{_PREFIX}"}})
    now = datetime.now(timezone.utc).isoformat()
    for cid, tid in ((INC_A, T_A), (INC_FOREIGN, T_FOREIGN)):
        db.workspace_cases.insert_one({
            "id": cid, "doc_type": "xdr_incident", "tenant_id": tid,
            "incident_number": f"INC000{abs(hash(cid)) % 10000:04d}",
            "title": "p01 write fixture", "name": "P01-SECRET-INCIDENT",
            "incident_state": "new", "created_at": now, "updated_at": now})
    db.users.insert_one({"email": SINGLE_A["email"], "role": "analyst",
                         "tenant_id": T_A, "created_at": now,
                         "password_hash": "!p01-fixture-no-login"})
    db.users.insert_one({"email": MULTI_AB["email"], "role": "analyst",
                         "tenant_ids": [T_A, T_B], "created_at": now,
                         "password_hash": "!p01-fixture-no-login"})
    app = _app()
    yield app, db
    app.dependency_overrides.clear()
    db.workspace_cases.delete_many({"id": {"$regex": f"^{_PREFIX}"}})
    db.users.delete_many({"email": {"$regex": f"^{_PREFIX}"}})


def _client(app, user):
    app.dependency_overrides[get_current_user] = lambda: user
    return TestClient(app)


WRITE = "/api/xdr/response-evidence"


def _body(execution_id, *, tenant_id=None, incident_id=None):
    context = {"incident_id": incident_id} if incident_id else {}
    body = {
        "execution_id": execution_id,
        "invoker": {"kind": "analyst", "id": "user:a@test", "context": context},
        "action": {"action_id": "endpoint.isolate", "provider": "endpoint",
                   "capability": "isolate_endpoint"},
        "parameters": {"host_id": "HOST-A"},
        "canonical_target": {"asset": "asset:HOST-A"},
        "adapter_ok": True,
    }
    if tenant_id is not None:
        body["tenant_id"] = tenant_id
    return body


def _stored(app, execution_id):
    return [r for r in app.state.db.xdr_response_evidence.rows
            if r["execution_id"] == execution_id]


# ── 1 · single tenant / no incident → own tenant is authoritative ───
def test_single_tenant_no_incident_writes_its_own_tenant(harness):
    app, _ = harness
    r = _client(app, SINGLE_A).post(WRITE, json=_body("p01-single-no-inc"))
    assert r.status_code == 200, r.text
    rows = _stored(app, "p01-single-no-inc")
    assert len(rows) == 1
    assert rows[0]["tenant_id"] == T_A
    auth = rows[0]["provenance"]["tenant_authority"]
    assert auth == {"source": "principal_scope", "tenant_id": T_A,
                    "asserted_tenant_id": None}


def test_single_tenant_matching_assertion_is_accepted(harness):
    app, _ = harness
    r = _client(app, SINGLE_A).post(
        WRITE, json=_body("p01-single-assert-ok", tenant_id=T_A))
    assert r.status_code == 200, r.text
    assert _stored(app, "p01-single-assert-ok")[0]["tenant_id"] == T_A


# ── 2 · single tenant / foreign assertion → DENY ────────────────────
def test_single_tenant_foreign_assertion_is_denied(harness):
    app, _ = harness
    r = _client(app, SINGLE_A).post(
        WRITE, json=_body("p01-single-foreign", tenant_id=T_FOREIGN))
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["error"] == "tenant_authority_denied"
    assert _stored(app, "p01-single-foreign") == []
    assert app.state.db.xdr_response_audit.rows == []
    assert app.state.db.xdr_response_timeline.rows == []


# ── 3 · multi-tenant / authoritative incident → incident's tenant ───
def test_multi_tenant_with_incident_derives_tenant_from_incident(harness):
    app, _ = harness
    r = _client(app, MULTI_AB).post(
        WRITE, json=_body("p01-multi-inc", incident_id=INC_A))
    assert r.status_code == 200, r.text
    row = _stored(app, "p01-multi-inc")[0]
    assert row["tenant_id"] == T_A
    assert row["provenance"]["tenant_authority"]["source"] == "incident"


def test_admin_with_incident_derives_tenant_from_incident(harness):
    app, _ = harness
    r = _client(app, ADMIN).post(
        WRITE, json=_body("p01-admin-inc", incident_id=INC_FOREIGN))
    assert r.status_code == 200, r.text
    assert _stored(app, "p01-admin-inc")[0]["tenant_id"] == T_FOREIGN


# ── 4 · multi-tenant / incident vs assertion mismatch → DENY ────────
def test_multi_tenant_incident_assertion_mismatch_is_denied(harness):
    app, _ = harness
    r = _client(app, MULTI_AB).post(
        WRITE, json=_body("p01-multi-mismatch", tenant_id=T_B,
                          incident_id=INC_A))
    assert r.status_code == 403, r.text
    detail = r.json()["detail"]
    assert detail["error"] == "tenant_authority_denied"
    # the refusal must not disclose the incident's real tenant
    assert T_A not in r.text
    assert _stored(app, "p01-multi-mismatch") == []


def test_incident_outside_principal_scope_is_404_without_disclosure(harness):
    app, _ = harness
    r = _client(app, SINGLE_A).post(
        WRITE, json=_body("p01-single-foreign-inc", incident_id=INC_FOREIGN))
    assert r.status_code == 404, r.text
    assert "P01-SECRET-INCIDENT" not in r.text
    assert T_FOREIGN not in r.text
    assert _stored(app, "p01-single-foreign-inc") == []


# ── 5 · multi/all-tenant + no anchor + only body tenant → DENY ──────
@pytest.mark.parametrize("user", [MULTI_AB, ADMIN])
def test_no_resource_anchor_with_ambiguous_principal_is_denied(harness, user):
    app, _ = harness
    r = _client(app, user).post(
        WRITE, json=_body("p01-ambiguous", tenant_id=T_A))
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["reason"] == \
        "ambiguous_tenant_authority_without_resource_anchor"
    assert _stored(app, "p01-ambiguous") == []


def test_principal_holding_no_tenant_is_denied(harness):
    app, _ = harness
    r = _client(app, {"email": "nobody@nowhere.test", "role": "analyst"}).post(
        WRITE, json=_body("p01-no-tenant", tenant_id=T_A))
    assert r.status_code == 403, r.text
    assert _stored(app, "p01-no-tenant") == []


# ── 6 · idempotency is tenant-scoped ────────────────────────────────
def test_same_execution_id_across_tenants_does_not_collide(harness):
    """Two tenants, one execution_id: distinct triples, no replay, and
    neither response nor row discloses the other tenant's refs."""
    app, _ = harness
    a = _client(app, SINGLE_A).post(
        WRITE, json=_body("p01-shared-exec", incident_id=INC_A))
    b = _client(app, ADMIN).post(
        WRITE, json=_body("p01-shared-exec", incident_id=INC_FOREIGN))
    assert a.status_code == 200 and b.status_code == 200, (a.text, b.text)
    ja, jb = a.json(), b.json()
    assert jb.get("idempotent_replay") is not True
    assert ja["evidence_ref"] != jb["evidence_ref"]
    assert ja["audit_ref"]    != jb["audit_ref"]
    assert ja["timeline_ref"] != jb["timeline_ref"]
    assert ja["evidence_ref"] not in b.text
    tenants = {r["tenant_id"] for r in _stored(app, "p01-shared-exec")}
    assert tenants == {T_A, T_FOREIGN}


def test_replay_within_the_same_tenant_is_still_idempotent(harness):
    app, _ = harness
    c = _client(app, SINGLE_A)
    r1 = c.post(WRITE, json=_body("p01-replay", incident_id=INC_A))
    r2 = c.post(WRITE, json=_body("p01-replay", incident_id=INC_A))
    assert r1.status_code == 200 and r2.status_code == 200
    assert r1.json()["evidence_ref"] == r2.json()["evidence_ref"]
    assert r2.json()["idempotent_replay"] is True
    assert len(_stored(app, "p01-replay")) == 1
