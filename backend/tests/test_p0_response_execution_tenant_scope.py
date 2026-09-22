"""P0 · RESPONSE-EXECUTION TENANT ISOLATION — focused regression guard.

The defect: `GET /api/xdr/incidents/{id}/response-executions` queried purely
by `invoker.context.incident_id`, with the tenant predicate coming from an
OPTIONAL, CLIENT-SUPPLIED `tenant_id` query parameter. Any principal holding
`evidence.read` could read another customer's response executions by putting
their own incident id in the path. Its sibling
`GET /api/xdr/response-evidence/{execution_id}` had the same defect keyed on
an execution id.

This guard drives the REAL router with the REAL tenant authority
(`resolve_tenant_scope`) and the REAL incident authority
(`routers.incidents.authorized_incident`); only the RBAC permission gate is
overridden, exactly as the pre-existing harness in
`tests/test_xdr_response_evidence.py` does, because no production tenant role
in this deployment currently holds `evidence.read` (that gate itself is
proven in `tests/test_xdr_rbac_enforcement.py`).

The decisive case: an evidence row of ANOTHER tenant that references the same
`incident_id` must never appear.
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
_PREFIX = f"p0resp-{_W}-"
INC = f"{_PREFIX}inc"                       # belongs to tenant OWN
OWN_T, OTHER_T = "p0-own-tenant", "p0-other-tenant"

ADMIN = {"email": "admin@nivxray.com", "role": "admin"}
OWN = {"email": f"{_PREFIX}own@test", "role": "analyst"}
OTHER = {"email": f"{_PREFIX}other@test", "role": "analyst"}


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
    db.workspace_cases.insert_one({
        "id": INC, "doc_type": "xdr_incident", "tenant_id": OWN_T,
        "incident_number": "INC0000991", "title": "p0 fixture",
        "name": "P0-SECRET-INCIDENT-NAME", "incident_state": "new",
        "created_at": now, "updated_at": now})
    for u, t in ((OWN, OWN_T), (OTHER, OTHER_T)):
        db.users.insert_one({"email": u["email"], "role": "analyst",
                             "tenant_id": t, "created_at": now,
                             "password_hash": "!p0-fixture-no-login"})
    app = _app()
    fake = app.state.db
    # two executions referencing the SAME incident id, in two tenants
    fake.xdr_response_evidence.rows.extend([
        {"execution_id": "exec-own", "tenant_id": OWN_T,
         "invoker": {"kind": "analyst", "context": {"incident_id": INC}},
         "action": {"action_id": "endpoint.isolate"}, "adapter_ok": True,
         "completed_at": now},
        {"execution_id": "exec-foreign", "tenant_id": OTHER_T,
         "invoker": {"kind": "analyst", "context": {"incident_id": INC}},
         "action": {"action_id": "endpoint.isolate"}, "adapter_ok": True,
         "completed_at": now},
    ])
    fake.xdr_response_executions.rows.extend([
        {"execution_id": "exec-own", "tenant_id": OWN_T,
         "evidence_ref": "ev-own", "audit_ref": "au-own",
         "timeline_ref": "tl-own", "ingested_at": now},
        {"execution_id": "exec-foreign", "tenant_id": OTHER_T,
         "evidence_ref": "ev-foreign", "audit_ref": "au-foreign",
         "timeline_ref": "tl-foreign", "ingested_at": now},
    ])
    yield app, db
    app.dependency_overrides.clear()
    db.workspace_cases.delete_many({"id": {"$regex": f"^{_PREFIX}"}})
    db.users.delete_many({"email": {"$regex": f"^{_PREFIX}"}})


def _client(app, user=None):
    if user is None:
        app.dependency_overrides.pop(get_current_user, None)
    else:
        app.dependency_overrides[get_current_user] = lambda: user
    return TestClient(app)


LIST = f"/api/xdr/incidents/{INC}/response-executions"


def test_anonymous_is_refused(harness):
    app, _ = harness
    r = _client(app).get(LIST)
    assert r.status_code in (401, 403), r.status_code
    assert "P0-SECRET-INCIDENT-NAME" not in r.text
    assert "exec-own" not in r.text


def test_own_tenant_sees_only_its_own_executions(harness):
    """THE defect: a foreign-tenant row referencing the same incident id."""
    app, _ = harness
    r = _client(app, OWN).get(LIST)
    assert r.status_code == 200, r.text[:200]
    body = r.json()
    ids = [e["execution_id"] for e in body["executions"]]
    assert ids == ["exec-own"], ids
    assert "exec-foreign" not in r.text
    assert body["tenant_scope"] == "PRINCIPAL_TENANTS"
    assert body["tenant_id"] == [OWN_T]
    # the joined ref triple must be the own-tenant one
    assert body["executions"][0]["audit_ref"] == "au-own"


def test_cross_tenant_principal_is_404_without_disclosure(harness):
    app, _ = harness
    r = _client(app, OTHER).get(LIST)
    assert r.status_code == 404, r.status_code
    assert "P0-SECRET-INCIDENT-NAME" not in r.text
    assert "exec-own" not in r.text and "exec-foreign" not in r.text


@pytest.mark.parametrize("q", [f"?tenant_id={OTHER_T}",
                               f"?customer={OTHER_T}",
                               f"?tenant={OTHER_T}"])
def test_client_supplied_tenant_cannot_widen_scope(harness, q):
    app, _ = harness
    r = _client(app, OWN).get(LIST + q,
                              headers={"X-Tenant-Id": OTHER_T,
                                       "X-Principal-Id": ADMIN["email"]})
    assert r.status_code == 200, r.status_code
    assert "exec-foreign" not in r.text
    # `tenant_id` narrows; `customer`/`tenant` are not part of the contract
    # at all and are simply ignored — either way nothing widens.
    assert all(e["execution_id"] == "exec-own"
               for e in r.json()["executions"]) or \
           r.json()["executions"] == []


def test_requested_tenant_can_only_narrow(harness):
    app, _ = harness
    r = _client(app, OWN).get(LIST + f"?tenant_id={OTHER_T}")
    assert r.status_code == 200
    assert r.json()["tenant_id"] == []
    assert r.json()["count"] == 0


def test_cross_tenant_role_is_unchanged(harness):
    app, _ = harness
    r = _client(app, ADMIN).get(LIST)
    assert r.status_code == 200, r.text[:200]
    assert r.json()["tenant_scope"] == "ALL_TENANTS"
    assert {e["execution_id"] for e in r.json()["executions"]} \
        == {"exec-own", "exec-foreign"}


# ── the sibling execution-detail read ───────────────────────────────
DETAIL = "/api/xdr/response-evidence/"


def test_execution_detail_is_refused_anonymously(harness):
    app, _ = harness
    assert _client(app).get(DETAIL + "exec-own").status_code in (401, 403)


def test_execution_detail_of_another_tenant_is_404(harness):
    app, _ = harness
    r = _client(app, OWN).get(DETAIL + "exec-foreign")
    assert r.status_code == 404, r.status_code
    assert "ev-foreign" not in r.text


def test_execution_detail_of_own_tenant_is_readable(harness):
    app, _ = harness
    r = _client(app, OWN).get(DETAIL + "exec-own")
    assert r.status_code == 200, r.text[:200]
    assert r.json()["evidence_ref"] == "ev-own"


def test_execution_detail_requested_tenant_cannot_widen(harness):
    app, _ = harness
    r = _client(app, OWN).get(DETAIL + f"exec-foreign?tenant_id={OTHER_T}")
    assert r.status_code == 404, r.status_code


def test_an_unauthorized_principal_holds_no_tenant(harness):
    """A principal with no user record is authorized as a principal and
    holds NO tenant — an honest empty state, never a default tenant."""
    app, _ = harness
    r = _client(app, {"email": "nobody@nowhere.test", "role": "analyst"}) \
        .get(DETAIL + "exec-own")
    assert r.status_code == 404, r.status_code
