"""S2-mini · ENGINE-DEPTH READ AUTHORIZATION GUARD.

The Individual Incident workspace reads three engine projections, all keyed on
a `case_id` and all previously `require_admin`, so a tenant-scoped analyst
could not read the depth of their OWN incident:

    GET /api/v2/cases/{case_id}/investigation
    GET /api/v2/cases/{case_id}/trajectory/device
    GET /api/v2/cases/{case_id}/artifacts

Invariants asserted here (the live counterpart, with real JWTs and real
records, is `scripts/s2_mini_engine_depth_live_proof.py`):
  · anonymous is refused
  · a principal authorized for the incident may read its engine depth
  · another tenant's analyst is 404 — existence is never disclosed
  · an engine-NATIVE case (no incident, and `v2_cases` carries NO tenant
    field at all) is never readable by an analyst and is never substituted
  · an authorized incident with no engine observation states NOT_ASSOCIATED
    instead of returning an empty projection that reads as "no activity"
  · the analyst gains NO engine mutation, ingest, registry or configuration
    access, and admin access is unchanged

Test hygiene: this module owns exactly ONE dependency-override key and pops
only that key (another module's import-time override must survive), and every
seeded document is prefix-scoped and removed on success and on failure.
"""
import os
from contextlib import contextmanager
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from motor.motor_asyncio import AsyncIOMotorClient

import deps
from server import app
from deps import get_current_user, init_database, validate_config

validate_config()
init_database()

client = TestClient(app)

ADMIN = {"email": "admin@nivxray.com", "role": "admin"}
ANALYST = {"email": "s2-analyst@nivx-live.test", "role": "analyst",
           "tenant_id": "nivx-live"}
OTHER = {"email": "s2-analyst@default.test", "role": "analyst",
         "tenant_id": "default"}

_W = os.environ.get("PYTEST_XDIST_WORKER", "master")
_PREFIX = f"s2-case-{_W}-"
INC_ASSOC = f"{_PREFIX}assoc"        # nivx-live, engine observation exists
INC_EMPTY = f"{_PREFIX}empty"        # nivx-live, no engine observation
ENGINE_NATIVE = f"{_PREFIX}engine-native"   # not an incident at all

READS = ["/investigation", "/trajectory/device", "/artifacts"]


def _as(user):
    app.dependency_overrides[get_current_user] = lambda: user


def _anon():
    app.dependency_overrides.pop(get_current_user, None)


def teardown_module():
    app.dependency_overrides.pop(get_current_user, None)


def _db():
    from pymongo import MongoClient
    return MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]


@contextmanager
def motor_client():
    """One event loop for the whole block: these routes are motor-backed.

    No authorization is bypassed or relaxed by this fixture.
    """
    with TestClient(app) as c:
        real = AsyncIOMotorClient(os.environ["MONGO_URL"])
        deps.client._bind(real)
        deps.db._bind(real[os.environ["DB_NAME"]])
        try:
            yield c
        finally:
            real.close()
            init_database()


@pytest.fixture
def seeded():
    db = _db()
    db.workspace_cases.delete_many({"id": {"$regex": f"^{_PREFIX}"}})
    db.v2_shadow_observations.delete_many({"case_id": {"$regex": f"^{_PREFIX}"}})
    db.v2_cases.delete_many({"_id": {"$regex": f"^{_PREFIX}"}})
    now = datetime.now(timezone.utc).isoformat()
    # `resolve_tenant_scope` reads the principal's OWN user record — the
    # tenant is never taken from the token or a header.
    db.users.delete_many({"email": {"$in": [ANALYST["email"], OTHER["email"]]}})
    for u in (ANALYST, OTHER):
        db.users.insert_one({"email": u["email"], "role": "analyst",
                             "tenant_id": u["tenant_id"], "created_at": now,
                             "password_hash": "!s2-fixture-no-login"})
    for n, cid in enumerate((INC_ASSOC, INC_EMPTY)):
        db.workspace_cases.insert_one({
            "id": cid, "doc_type": "xdr_incident", "tenant_id": "nivx-live",
            "incident_number": f"INC0000097{n}",
            "title": "s2 fixture", "name": "S2-SECRET-INCIDENT-NAME",
            "incident_state": "new", "created_at": now, "updated_at": now})
    # Modelled on the real CEM observation shape. A frame with no parseable
    # `ts` makes the IRG enricher raise `KeyError` (pre-existing engine
    # fragility, out of S2-mini scope) — so the fixture carries one.
    obs_event = {
        "iid": "evt_s2_fixture", "adapter": "s2-fixture",
        "adapter_version": "1.0", "ts": now, "sequence": 0,
        "kind": "process_create", "device_iid": "dev_s2fixture",
        "actor_iid": "user_s2fixture", "process_iid": "proc_s2fixture",
        "artefacts_iids": [], "artefacts": {}, "labels": [], "mitre": [],
        "process": {"name": "s2fixture.exe", "image": "s2fixture.exe",
                    "iid": "proc_s2fixture", "parent_iid": None},
        "raw": {"command_line": "s2fixture.exe"},
    }
    db.v2_shadow_observations.insert_one({
        "case_id": INC_ASSOC, "kind": "process_create", "captured_at": now,
        "adapter": "s2-fixture", "cem_version": "v1",
        "process_iid": "proc_s2fixture", "artefacts_iids": [],
        "event": dict(obs_event)})
    # an engine-NATIVE case: a real engine case document, with no incident
    # and — exactly as in production — NO tenant field.
    db.v2_cases.insert_one({"_id": ENGINE_NATIVE, "name": "s2 engine native",
                            "status": "open", "created_by": "s2-fixture"})
    db.v2_shadow_observations.insert_one({
        "case_id": ENGINE_NATIVE, "kind": "process_create",
        "captured_at": now, "adapter": "s2-fixture", "cem_version": "v1",
        "process_iid": "proc_s2fixture", "artefacts_iids": [],
        "event": dict(obs_event)})
    yield db
    db.workspace_cases.delete_many({"id": {"$regex": f"^{_PREFIX}"}})
    db.v2_shadow_observations.delete_many({"case_id": {"$regex": f"^{_PREFIX}"}})
    db.v2_cases.delete_many({"_id": {"$regex": f"^{_PREFIX}"}})
    db.users.delete_many({"email": {"$in": [ANALYST["email"], OTHER["email"]]}})


# ── denial paths (refused before any engine read) ───────────────────
@pytest.mark.parametrize("path", READS)
def test_anonymous_is_refused(seeded, path):
    _anon()
    r = client.get(f"/api/v2/cases/{INC_ASSOC}{path}")
    assert r.status_code in (401, 403), f"{path} → {r.status_code}"
    assert "S2-SECRET-INCIDENT-NAME" not in r.text


@pytest.mark.parametrize("path", READS)
def test_cross_tenant_is_404_without_disclosure(seeded, path):
    _as(OTHER)
    r = client.get(f"/api/v2/cases/{INC_ASSOC}{path}")
    assert r.status_code == 404, f"{path} → {r.status_code}"
    assert "S2-SECRET-INCIDENT-NAME" not in r.text


@pytest.mark.parametrize("path", READS)
def test_engine_native_case_is_never_readable_by_an_analyst(seeded, path):
    """`v2_cases` has no tenant field, so an engine-native case can only be
    authorized by a cross-tenant role — never adopted by an incident."""
    _as(ANALYST)
    r = client.get(f"/api/v2/cases/{ENGINE_NATIVE}{path}")
    assert r.status_code == 404, f"{path} → {r.status_code}"


@pytest.mark.parametrize("q", ["?tenant_id=nivx-live", "?customer=nivx-live"])
def test_client_supplied_tenant_is_not_authority(seeded, q):
    _as(OTHER)
    r = client.get(f"/api/v2/cases/{INC_ASSOC}/investigation{q}",
                   headers={"X-Tenant-Id": "nivx-live",
                            "X-Principal-Id": "admin@nivxray.com"})
    assert r.status_code == 404, r.status_code


@pytest.mark.parametrize("method,path,body", [
    ("POST", "/api/v2/cases", {"name": "refused"}),
    ("GET", "/api/v2/cases", None),
    ("DELETE", f"/api/v2/cases/{ENGINE_NATIVE}", None),
    ("POST", f"/api/v2/cases/{INC_ASSOC}/observations",
     {"kind": "process", "event": {}}),
    ("GET", f"/api/v2/cases/{INC_ASSOC}/investigation/explain/lateral_movement",
     None),
])
def test_analyst_gains_no_engine_administration(seeded, method, path, body):
    _as(ANALYST)
    r = client.request(method, path, json=body)
    assert r.status_code in (401, 403), f"{method} {path} → {r.status_code}"


# ── the reads S2-mini exists for ────────────────────────────────────
def test_authorized_analyst_reads_its_own_engine_depth(seeded):
    _as(ANALYST)
    with motor_client() as c:
        for path in READS:
            r = c.get(f"/api/v2/cases/{INC_ASSOC}{path}?limit=50")
            assert r.status_code == 200, f"{path} → {r.status_code}"
            assoc = r.json()["engine_association"]
            assert assoc["state"] == "ASSOCIATED", f"{path} → {assoc}"
            assert assoc["authority"] == "INCIDENT_TENANT_AUTHORITY"
            assert assoc["read_from"] == "v2_shadow_observations.case_id"


def test_authorized_but_unassociated_incident_states_not_associated(seeded):
    _as(ANALYST)
    with motor_client() as c:
        r = c.get(f"/api/v2/cases/{INC_EMPTY}/investigation?limit=50")
    assert r.status_code == 200, r.status_code
    assoc = r.json()["engine_association"]
    assert assoc["state"] == "NOT_ASSOCIATED"
    assert assoc["reason"]
    assert assoc["read_from"] == "v2_shadow_observations.case_id"


def test_admin_access_is_unchanged(seeded):
    _as(ADMIN)
    with motor_client() as c:
        for path in READS:
            own = c.get(f"/api/v2/cases/{INC_ASSOC}{path}?limit=50")
            native = c.get(f"/api/v2/cases/{ENGINE_NATIVE}{path}?limit=50")
            assert own.status_code == 200, f"{path} → {own.status_code}"
            assert native.status_code == 200, f"{path} → {native.status_code}"
            assert own.json()["engine_association"]["authority"] \
                == "CROSS_TENANT_ROLE"
        assert c.get("/api/v2/cases").status_code == 200
