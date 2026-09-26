"""S1 · INCIDENT SUB-RESOURCE AUTHORIZATION BOUNDARY.

Six routers used to answer for an incident with either an OPTIONAL principal
and no tenant predicate, or — for the whole report API — no authentication
dependency at all. Proven live before the fix: anonymous `200` on
`…/investigation`, `…/investigation/findings`, `…/attack-story`,
`…/attack-graph`, `…/report`, `…/report/pdf`, and an unauthenticated report
write whose author identity came from the request body.

The model locked here is the one the incident record itself already used:

    authenticated principal → server-resolved tenant scope
    → incident belongs to that scope → required permission (mutations)
    → resource / action

Invariants asserted:
  · anonymous read AND anonymous write fail closed
  · cross-tenant read AND cross-tenant write are 404 — a sub-resource never
    discloses that another customer's incident exists, and never leaks its
    content
  · same-tenant authorized read succeeds (the fix does not narrow legitimate
    analyst access — read stays the incident record's own contract)
  · same-tenant principal WITHOUT `incidents.update` cannot mutate a report
  · the PDF projection carries the same authorization as the JSON contract
  · actor attribution comes from the verified principal; `author_email` in
    the body is ignored
  · a block is addressable only through the incident that owns it
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


@contextmanager
def motor_client():
    """A client for the routes that reach MOTOR (report compose / PDF /
    block writes).

    Test-infrastructure only: `deps.db` is a process-wide Motor proxy bound
    to whichever event loop touched it first, and every bare `TestClient`
    call runs in a fresh loop — so a motor-backed route answers
    `Event loop is closed`. Entering the client as a context manager keeps
    ONE loop for the whole block, and the proxy is rebound inside it. No
    authorization is bypassed or relaxed by this fixture.
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

ADMIN = {"email": "admin@nivxray.com", "role": "admin"}
# A tenant-scoped analyst seeded by the fixture below: authorized for its
# own tenant's incidents (so reads must keep working) and holding NO
# `incidents.update` grant (so a report mutation must be refused).
NIVX_ANALYST = {"email": "s1-analyst@nivx-live.test", "role": "analyst",
                "tenant_id": "nivx-live"}

# Fixture ids are per-worker: this suite runs under xdist, and a shared id
# means one worker's fixture teardown deletes another worker's incident
# mid-test (the contention class recorded in P0.5).
_W = os.environ.get("PYTEST_XDIST_WORKER", "master")
_PREFIX = f"s1-inc-{_W}-"
INC_DEFAULT = f"{_PREFIX}default"
INC_NIVXLIVE = f"{_PREFIX}nivxlive"

READS = ["/investigation", "/investigation/executions",
         "/investigation/findings", "/attack-story", "/attack-graph",
         "/report", "/report/pdf",
         # S1 · SAME-CLASS LEAKS FOUND WHILE VERIFYING THE BOUNDARY.
         # `…/attack-evidence` and `…/inspector/**` carried NO
         # authentication dependency at all; `…/summary` and
         # `…/threat-model` were authenticated (or optional) but resolved
         # `{"id": incident_id}` with NO tenant predicate; the whole
         # `…/intelligence/overlays` family was authenticated with no
         # tenant predicate on either the read or the write path.
         "/attack-evidence", "/summary", "/threat-model",
         "/inspector/event/s1-ref-does-not-exist",
         "/intelligence/overlays"]

OVERLAY = "/intelligence/overlays/finding/s1-finding/summary"
OVERLAY_BODY = {"analyst_value": "analyst wrote this",
                "machine_value": "machine said that",
                "reason": "s1 authorization proof"}


def _as(user):
    app.dependency_overrides[get_current_user] = lambda: user


def _anon():
    # TEST HYGIENE, and a real defect this suite caused once: other modules
    # in the same process install their OWN dependency overrides at import
    # time (`test_xdr_incident_queue` overrides `get_current_user_optional`
    # for the whole module). `dependency_overrides.clear()` silently deleted
    # theirs and their queue then answered as an anonymous caller. This suite
    # owns exactly ONE key and touches nothing else.
    app.dependency_overrides.pop(get_current_user, None)


def _db():
    from pymongo import MongoClient
    return MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]


@pytest.fixture
def seeded():
    db = _db()
    from services.report import REPORT_BLOCKS_COLL
    from services.intelligence_overlay import OVERLAY_COLL, AUDIT_COLL
    db.workspace_cases.delete_many({"id": {"$regex": f"^{_PREFIX}"}})
    db[REPORT_BLOCKS_COLL].delete_many({"incident_id": {"$regex": f"^{_PREFIX}"}})
    db[OVERLAY_COLL].delete_many({"incident_id": {"$regex": f"^{_PREFIX}"}})
    db[AUDIT_COLL].delete_many({"incident_id": {"$regex": f"^{_PREFIX}"}})
    now = datetime.now(timezone.utc).isoformat()
    db.users.delete_many({"email": NIVX_ANALYST["email"]})
    db.users.insert_one({"email": NIVX_ANALYST["email"], "role": "analyst",
                         "tenant_id": "nivx-live", "created_at": now,
                         "password_hash": "!s1-fixture-no-login"})
    for n, (cid, tenant) in enumerate(((INC_DEFAULT, "default"),
                                       (INC_NIVXLIVE, "nivx-live"))):
        db.workspace_cases.insert_one({
            "id": cid, "doc_type": "xdr_incident", "tenant_id": tenant,
            # `uniq_incident_number` is a real unique index — two fixtures
            # sharing a number silently cost us the second document.
            "incident_number": f"INC0000098{_W[-1] if _W[-1].isdigit() else 0}{n}",
            "title": f"s1 fixture {tenant}",
            "name": "S1-SECRET-INCIDENT-NAME",
            "incident_state": "new", "created_at": now, "updated_at": now,
        })
    yield db
    db.workspace_cases.delete_many({"id": {"$regex": f"^{_PREFIX}"}})
    db[REPORT_BLOCKS_COLL].delete_many({"incident_id": {"$regex": f"^{_PREFIX}"}})
    db[OVERLAY_COLL].delete_many({"incident_id": {"$regex": f"^{_PREFIX}"}})
    db[AUDIT_COLL].delete_many({"incident_id": {"$regex": f"^{_PREFIX}"}})
    db.users.delete_many({"email": NIVX_ANALYST["email"]})


def _blocks(db, incident_id):
    from services.report import REPORT_BLOCKS_COLL
    return list(db[REPORT_BLOCKS_COLL].find({"incident_id": incident_id},
                                            {"_id": 0}))


def teardown_module():
    app.dependency_overrides.pop(get_current_user, None)


# ── 1 · anonymous read ──────────────────────────────────────────────
@pytest.mark.parametrize("path", READS)
def test_anonymous_read_fails_closed(seeded, path):
    _anon()
    r = client.get(f"/api/incidents/{INC_DEFAULT}{path}")
    assert r.status_code in (401, 403), f"{path} → {r.status_code}"
    assert "S1-SECRET-INCIDENT-NAME" not in r.text


# ── 2 · anonymous write ─────────────────────────────────────────────
def test_anonymous_write_fails_closed_and_stores_nothing(seeded):
    _anon()
    r = client.post(f"/api/incidents/{INC_DEFAULT}/report/blocks",
                    json={"section": "executive_summary",
                          "content": "anonymous injection",
                          "author_email": "attacker@evil.test"})
    assert r.status_code in (401, 403)
    assert _blocks(seeded, INC_DEFAULT) == []


def test_anonymous_block_mutations_fail_closed(seeded):
    _anon()
    assert client.patch(
        f"/api/incidents/{INC_DEFAULT}/report/blocks/blk-1",
        json={"content": "x"}).status_code in (401, 403)
    assert client.delete(
        f"/api/incidents/{INC_DEFAULT}/report/blocks/blk-1"
    ).status_code in (401, 403)
    assert client.post(
        f"/api/incidents/{INC_DEFAULT}/report/blocks/blk-1/suppress",
        json={"section": "executive_summary"}).status_code in (401, 403)


# ── 3 · same-tenant authorized read ─────────────────────────────────
@pytest.mark.parametrize("path", READS)
def test_authorized_read_still_works(seeded, path):
    _as(ADMIN)
    with motor_client() as c:
        r = c.get(f"/api/incidents/{INC_DEFAULT}{path}")
    assert r.status_code == 200, f"{path} → {r.status_code} {r.text[:200]}"


def test_tenant_analyst_reads_its_own_incident(seeded):
    _as(NIVX_ANALYST)
    for path in READS:
        with motor_client() as c:
            r = c.get(f"/api/incidents/{INC_NIVXLIVE}{path}")
        assert r.status_code == 200, f"{path} → {r.status_code}"


def test_pdf_projection_is_a_pdf_for_an_authorized_principal(seeded):
    _as(ADMIN)
    with motor_client() as c:
        r = c.get(f"/api/incidents/{INC_DEFAULT}/report/pdf")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert r.content[:4] == b"%PDF"


# ── 4 · cross-tenant read ───────────────────────────────────────────
@pytest.mark.parametrize("path", READS)
def test_cross_tenant_read_is_404_without_disclosure(seeded, path):
    _as(NIVX_ANALYST)
    r = client.get(f"/api/incidents/{INC_DEFAULT}{path}")
    assert r.status_code == 404, f"{path} → {r.status_code}"
    assert "S1-SECRET-INCIDENT-NAME" not in r.text


# ── 5 · cross-tenant write ──────────────────────────────────────────
def test_cross_tenant_write_is_refused_and_stores_nothing(seeded):
    _as(NIVX_ANALYST)
    r = client.post(f"/api/incidents/{INC_DEFAULT}/report/blocks",
                    json={"section": "executive_summary",
                          "content": "cross tenant injection"})
    assert r.status_code == 404
    assert _blocks(seeded, INC_DEFAULT) == []


# ── 6 · same-tenant, unauthorized ACTION ────────────────────────────
def test_same_tenant_without_update_permission_cannot_write(seeded):
    _as(NIVX_ANALYST)
    with motor_client() as c:
        # the read of the very same incident succeeds …
        assert c.get(
            f"/api/incidents/{INC_NIVXLIVE}/report").status_code == 200
        # … while the mutation is refused on the permission, with the reason
        r = c.post(f"/api/incidents/{INC_NIVXLIVE}/report/blocks",
                   json={"section": "executive_summary",
                         "content": "not authorized to write"})
    assert r.status_code == 403, r.text[:200]
    detail = r.json()["detail"]
    assert detail["permission"] == "incidents.update"
    assert detail["reason"]
    assert _blocks(seeded, INC_NIVXLIVE) == []


# ── 7 · actor attribution comes from the principal ──────────────────
def test_actor_attribution_ignores_the_request_body(seeded):
    _as(ADMIN)
    with motor_client() as c:
        r = c.post(f"/api/incidents/{INC_DEFAULT}/report/blocks",
                   json={"section": "executive_summary",
                         "content": "authored by the verified principal",
                         "author_email": "attacker@evil.test"})
        assert r.status_code == 200, r.text[:200]
        block = r.json()
        r2 = c.patch(
            f"/api/incidents/{INC_DEFAULT}/report/blocks/{block['block_id']}",
            json={"content": "edited", "author_email": "attacker@evil.test"})
    assert block["author_email"] == ADMIN["email"]
    stored = _blocks(seeded, INC_DEFAULT)
    assert len(stored) == 1
    assert stored[0]["author_email"] == ADMIN["email"]
    assert "attacker@evil.test" not in str(stored[0])

    # an edit is attributed the same way
    assert r2.status_code == 200
    assert r2.json()["modified_by"] == ADMIN["email"]


# ── 8 · a block belongs to ONE incident ─────────────────────────────
def test_a_block_cannot_be_mutated_through_another_incident(seeded):
    _as(ADMIN)
    with motor_client() as c:
        created = c.post(f"/api/incidents/{INC_DEFAULT}/report/blocks",
                         json={"section": "executive_summary",
                               "content": "belongs to the default tenant"})
        assert created.status_code == 200
        bid = created.json()["block_id"]
        # same authorized principal, but the WRONG incident in the path
        assert c.patch(
            f"/api/incidents/{INC_NIVXLIVE}/report/blocks/{bid}",
            json={"content": "hijacked"}).status_code == 404
        assert c.delete(
            f"/api/incidents/{INC_NIVXLIVE}/report/blocks/{bid}"
        ).status_code == 404
    assert _blocks(seeded, INC_DEFAULT)[0]["content"] \
        == "belongs to the default tenant"


# ── 9 · the intelligence-overlay family (same-class leak) ───────────
def _overlays(db, incident_id):
    from services.intelligence_overlay import OVERLAY_COLL
    return list(db[OVERLAY_COLL].find({"incident_id": incident_id},
                                      {"_id": 0}))


def test_anonymous_overlay_write_fails_closed(seeded):
    _anon()
    assert client.put(f"/api/incidents/{INC_DEFAULT}{OVERLAY}",
                      json=OVERLAY_BODY).status_code in (401, 403)
    assert client.request(
        "DELETE", f"/api/incidents/{INC_DEFAULT}{OVERLAY}",
        json={"machine_value": "m", "reason": "r"}).status_code in (401, 403)
    assert _overlays(seeded, INC_DEFAULT) == []


def test_cross_tenant_overlay_write_is_404_and_stores_nothing(seeded):
    _as(NIVX_ANALYST)
    r = client.put(f"/api/incidents/{INC_DEFAULT}{OVERLAY}",
                   json=OVERLAY_BODY)
    assert r.status_code == 404, r.status_code
    assert "S1-SECRET-INCIDENT-NAME" not in r.text
    assert _overlays(seeded, INC_DEFAULT) == []


def test_same_tenant_without_update_permission_cannot_write_an_overlay(seeded):
    _as(NIVX_ANALYST)
    with motor_client() as c:
        assert c.get(
            f"/api/incidents/{INC_NIVXLIVE}/intelligence/overlays"
        ).status_code == 200
        r = c.put(f"/api/incidents/{INC_NIVXLIVE}{OVERLAY}",
                  json=OVERLAY_BODY)
    assert r.status_code == 403, r.text[:200]
    assert r.json()["detail"]["permission"] == "incidents.update"
    assert _overlays(seeded, INC_NIVXLIVE) == []


def test_authorized_overlay_write_read_history_and_revert(seeded):
    _as(ADMIN)
    with motor_client() as c:
        put = c.put(f"/api/incidents/{INC_DEFAULT}{OVERLAY}",
                    json=OVERLAY_BODY)
        assert put.status_code == 200, put.text[:200]
        one = c.get(f"/api/incidents/{INC_DEFAULT}{OVERLAY}")
        hist = c.get(f"/api/incidents/{INC_DEFAULT}{OVERLAY}/history")
        rev = c.request("DELETE", f"/api/incidents/{INC_DEFAULT}{OVERLAY}",
                        json={"machine_value": "machine said that",
                              "reason": "s1 revert"})
    assert one.status_code == 200
    assert hist.status_code == 200
    assert rev.status_code == 200
    stored = _overlays(seeded, INC_DEFAULT)
    assert len(stored) == 1
    # attribution is the verified principal, not a body claim
    assert stored[0]["author_email"] == ADMIN["email"]


# ── 10 · a missing / invalid incident fails closed identically ──────
@pytest.mark.parametrize("path", READS)
def test_unknown_incident_is_404_for_an_authorized_principal(seeded, path):
    _as(ADMIN)
    r = client.get(f"/api/incidents/s1-no-such-incident{path}")
    assert r.status_code == 404, f"{path} → {r.status_code}"


def test_client_supplied_tenant_is_not_authority(seeded):
    """A query/header tenant cannot widen the principal's own scope."""
    _as(NIVX_ANALYST)
    for q in ("?tenant=default", "?customer=default", "?tenant_id=default"):
        r = client.get(f"/api/incidents/{INC_DEFAULT}/report{q}",
                       headers={"X-Tenant-Id": "default"})
        assert r.status_code == 404, f"{q} → {r.status_code}"
        assert "S1-SECRET-INCIDENT-NAME" not in r.text
