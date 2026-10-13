"""XDR-S1: real route, scope resolver and catalogue; synthetic storage only."""
import socket

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import deps
from routers import mitre_catalogue as route
from services import tenant_registry as registry


class Cases:
    def __init__(self, records):
        self.records = records
        self.queries = []

    def find(self, query, projection):
        # Assert the database boundary itself is scoped, not post-filtered.
        assert set(query) == {"tenant_id"}
        assert set(query["tenant_id"]) == {"$in"}
        self.queries.append(query)
        async def cursor():
            for record in self.records:
                if record.get("tenant_id") in query["tenant_id"]["$in"]:
                    yield record
        return cursor()


@pytest.fixture
def boundary(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("External network forbidden")
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    users = {
        "a@test.invalid": {"email": "a@test.invalid", "tenant_ids": ["A"], "role": "admin"},
        "multi@test.invalid": {"email": "multi@test.invalid", "tenant_ids": ["A", "B"]},
        "platform@test.invalid": {"email": "platform@test.invalid", "authority_scope": "PLATFORM"},
        "empty@test.invalid": {"email": "empty@test.invalid", "tenant_ids": []},
        "stale@test.invalid": {"email": "stale@test.invalid", "tenant_ids": ["S", "GHOST"]},
    }
    tenants = {t: {"id": t, "state": "ACTIVE", "organization_id": "O"} for t in ("A", "B")}
    tenants["S"] = {"id": "S", "state": "SUSPENDED", "organization_id": "O"}
    class Users:
        def find_one(self, query, projection):
            return users.get(query["email"])
    def collection(name):
        assert name == "users"
        return Users()
    monkeypatch.setattr(deps, "sync_collection", collection)
    monkeypatch.setattr(registry, "get_tenant", lambda key: tenants.get(key))
    monkeypatch.setattr(registry, "get_organization", lambda key: {"id": "O", "state": "ACTIVE"} if key == "O" else None)
    monkeypatch.setattr(registry, "list_organizations", lambda **kw: [{"id": "O", "state": "ACTIVE"}])
    monkeypatch.setattr(registry, "list_tenants", lambda **kw: list(tenants.values()))
    cases = Cases([
        {"id": "A-1", "tenant_id": "A", "mitre": ["T1059.001", "T1059.001"]},
        {"id": "B-1", "tenant_id": "B", "mitre": ["T1105"]},
        {"id": "S-1", "tenant_id": "S", "mitre": ["T1105"]},
        {"id": "UNOWNED", "mitre": ["T1105"]},
        {"id": "LEGACY", "user_email": "A", "mitre": ["T1105"]},
    ])
    monkeypatch.setattr(route, "db", {"workspace_cases": cases})
    principal = {"email": "a@test.invalid"}
    app = FastAPI()
    app.include_router(route.router, prefix="/api")
    app.dependency_overrides[deps.get_current_user] = lambda: principal
    with TestClient(app) as client:
        yield client, principal, cases, users


def observations(payload):
    ids = set()
    rows = {}
    for tactic in payload["tactics"]:
        for parent in tactic["techniques"]:
            for row in [parent, *parent["subs"]]:
                ids.update(row["incident_ids"])
                rows[row["external_id"]] = row
    return ids, rows


def test_tenant_a_cannot_observe_b_counts_or_ids(boundary):
    client, principal, cases, _ = boundary
    # Even an admin role is not PLATFORM authority.
    response = client.get("/api/mitre/catalogue/coverage")
    assert response.status_code == 200
    ids, rows = observations(response.json())
    assert ids == {"A-1"}
    assert rows["T1059.001"]["observed_count"] == 1
    assert rows["T1105"]["observed_count"] == 0
    assert rows["T1105"]["coverage_state"] == "NO_EVIDENCE"
    assert cases.queries == [{"tenant_id": {"$in": ["A"]}}]


@pytest.mark.parametrize("url,headers", [
    ("?tenant_id=B", {}), ("?customer=B", {}), ("?tenant=B", {}),
    ("", {"X-Tenant-Id": "B"}),
    ("?tenant_id=A&customer=B", {}),
    ("?tenant_id=B", {"X-Tenant-Id": "A"}),
    ("?tenant_id=A&tenant_id=B", {}),
    ("?tenant_id=", {}), ("?scope=PLATFORM", {}),
    ("?tenant_id=GHOST", {}),
])
def test_forged_conflicting_or_invalid_selectors_denied_before_read(boundary, url, headers):
    client, _, cases, _ = boundary
    response = client.get("/api/mitre/catalogue/coverage" + url, headers=headers)
    assert response.status_code == 403
    assert response.json() == {"detail": "ATTACK_SCOPE_DENIED"}
    assert cases.queries == []


def test_get_body_claim_is_not_silently_accepted(boundary):
    client, _, cases, _ = boundary
    response = client.request("GET", "/api/mitre/catalogue/coverage", json={"tenant_id": "B"})
    assert response.status_code == 400
    assert cases.queries == []


@pytest.mark.parametrize("email", ["empty@test.invalid", "stale@test.invalid", None])
def test_no_authorized_active_tenant_fails_closed(boundary, email):
    client, principal, cases, _ = boundary
    principal["email"] = email
    assert client.get("/api/mitre/catalogue/coverage").status_code == 403
    assert cases.queries == []


def test_authorized_empty_tenant_has_honest_no_evidence(boundary):
    client, _, cases, _ = boundary
    cases.records = []
    response = client.get("/api/mitre/catalogue/coverage", headers={"X-Tenant-Id": "A"})
    assert response.status_code == 200
    ids, rows = observations(response.json())
    assert ids == set()
    assert all(row["observed_count"] == 0 and row["coverage_state"] == "NO_EVIDENCE" for row in rows.values())


@pytest.mark.parametrize("email", ["multi@test.invalid", "platform@test.invalid"])
def test_explicit_multitenant_authority_and_selected_tenant(boundary, email):
    client, principal, cases, _ = boundary
    principal["email"] = email
    response = client.get("/api/mitre/catalogue/coverage")
    assert response.status_code == 200
    assert observations(response.json())[0] == {"A-1", "B-1"}
    assert set(cases.queries[-1]["tenant_id"]["$in"]) == {"A", "B"}
    response = client.get("/api/mitre/catalogue/coverage?tenant_id=B&scope=all_authorized", headers={"X-Tenant-Id": "B"})
    assert response.status_code == 200
    assert observations(response.json())[0] == {"B-1"}
    assert cases.queries[-1] == {"tenant_id": {"$in": ["B"]}}


def test_duplicate_header_conflict_denied(boundary):
    client, _, cases, _ = boundary
    response = client.get("/api/mitre/catalogue/coverage", headers=[("X-Tenant-Id", "A"), ("X-Tenant-Id", "B")])
    assert response.status_code == 403
    assert cases.queries == []


def test_registry_failure_does_not_release_observations(boundary, monkeypatch):
    client, _, cases, _ = boundary
    def broken(*args, **kwargs):
        raise RuntimeError("synthetic registry unavailable")
    monkeypatch.setattr(registry, "get_tenant", broken)
    assert client.get("/api/mitre/catalogue/coverage").status_code == 403
    assert cases.queries == []


def test_forged_principal_tenant_fields_are_not_authority(boundary):
    client, principal, _, _ = boundary
    principal.update(tenant_id="B", tenant_ids=["B"], authority_scope="PLATFORM")
    response = client.get("/api/mitre/catalogue/coverage")
    assert response.status_code == 200
    assert observations(response.json())[0] == {"A-1"}


def test_flat_catalogue_contract_remains_available(boundary):
    client, _, cases, _ = boundary
    response = client.get("/api/mitre/catalogue")
    assert response.status_code == 200
    assert response.json()["version"] == "16.1"  # Pinned RC2 catalogue; no version upgrade in this repair.
    assert cases.queries == []



def test_real_bearer_dependency_uses_stored_subject_not_token_tenant(boundary, monkeypatch):
    import jwt
    from types import SimpleNamespace
    client, _, cases, users = boundary
    client.app.dependency_overrides.clear()
    monkeypatch.setattr(deps, "JWT_SECRET", "synthetic-test-signing-key-000000000000")
    class StoredUsers:
        async def find_one(self, query, projection):
            return users.get(query["email"])
    monkeypatch.setattr(deps, "db", SimpleNamespace(users=StoredUsers()))
    token = jwt.encode({"sub": "a@test.invalid", "tenant_id": "B", "authority_scope": "PLATFORM"}, deps.JWT_SECRET, algorithm="HS256")
    response = client.get("/api/mitre/catalogue/coverage", headers={"Authorization": "Bearer " + token})
    assert response.status_code == 200
    assert observations(response.json())[0] == {"A-1"}
    assert cases.queries == [{"tenant_id": {"$in": ["A"]}}]


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer synthetic-invalid"}])
def test_real_authentication_rejects_unauthenticated_requests(boundary, headers):
    client, _, cases, _ = boundary
    client.app.dependency_overrides.clear()
    response = client.get("/api/mitre/catalogue/coverage", headers=headers)
    assert response.status_code in (401, 403)
    assert cases.queries == []


def test_tenant_b_isolated_symmetrically(boundary):
    client, principal, cases, users = boundary
    users["b@test.invalid"] = {"email": "b@test.invalid", "tenant_id": "B"}
    principal["email"] = "b@test.invalid"
    response = client.get("/api/mitre/catalogue/coverage")
    assert response.status_code == 200
    ids, rows = observations(response.json())
    assert ids == {"B-1"}
    assert rows["T1059.001"]["observed_count"] == 0
    assert cases.queries == [{"tenant_id": {"$in": ["B"]}}]
    assert client.get("/api/mitre/catalogue/coverage?tenant_id=A").status_code == 403
    assert len(cases.queries) == 1


def test_inactive_organization_removes_customer_authority(boundary, monkeypatch):
    client, _, cases, _ = boundary
    monkeypatch.setattr(registry, "get_organization", lambda key: {"id": "O", "state": "SUSPENDED"})
    assert client.get("/api/mitre/catalogue/coverage").status_code == 403
    assert cases.queries == []


def test_platform_registry_unavailable_fails_closed(boundary, monkeypatch):
    client, principal, cases, _ = boundary
    principal["email"] = "platform@test.invalid"
    def unavailable(**kwargs):
        raise RuntimeError("synthetic unavailable registry")
    monkeypatch.setattr(registry, "list_tenants", unavailable)
    assert client.get("/api/mitre/catalogue/coverage").status_code == 403
    assert cases.queries == []
