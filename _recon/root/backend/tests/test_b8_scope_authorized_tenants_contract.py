"""B8-SCOPE-1 · `/api/xdr/scope/authorized` publishes TWO lists.

The defect this closes: the route answered "what may this principal act
as?" with the INCIDENT CORPUS. An ACTIVE, authorised tenant that has
never had an XDR incident — exactly what a fresh EDR-only or LAB tenant
is — was therefore counted by `authorized_count` (authority-derived) and
absent from `tenants` (evidence-derived). The XDR scope selector and
every `AdminTenantGate` surface offered nothing while reporting
"1 authorized tenant", and the EDR console resolved the same tenant
correctly because it reads the authority list.

The repair is ADDITIVE: `authorized_tenants` is published alongside the
unchanged `tenants`. No authorization predicate is touched, which these
tests also assert — a PLATFORM principal must still NAME its tenant, and
a customer principal still cannot reach another tenancy.
"""
from __future__ import annotations

import os
import uuid

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("XDR_AUDIT_MASTER_SECRET", "test-master-secret")
os.environ.setdefault("XDR_SECRETS_MASTER", "test-secrets-master-passphrase")

from routers import xdr_rbac as rb                # noqa: E402
from server import app                            # noqa: E402
from services import tenant_registry as reg       # noqa: E402

client = TestClient(app)

SUF = uuid.uuid4().hex[:8]
#: ACTIVE, authorised, and deliberately EVIDENCE-FREE. This is the tenant
#: the defect made unselectable, and the shape of the intended LAB canary.
T_QUIET = f"b8-quiet-{SUF}"
#: ACTIVE with one XDR incident, so the evidence list keeps its meaning.
T_NOISY = f"b8-noisy-{SUF}"
#: Registered, then SUSPENDED. Must never be offered.
T_SUSPENDED = f"b8-suspended-{SUF}"
#: Never registered anywhere. A grant naming it must not resolve.
T_GHOST = f"b8-ghost-{SUF}"

U_PLATFORM = f"b8-platform-{SUF}@nivxray.test"
U_CUSTOMER = f"b8-customer-{SUF}@nivxray.test"
U_STALE_GRANT = f"b8-stale-{SUF}@nivxray.test"

INC_NOISY = f"inc_b8_noisy_{SUF}"


@pytest.fixture(scope="module", autouse=True)
def _seed():
    if rb._db() is None:
        pytest.skip("MONGO_URL not configured")
    from deps import sync_collection
    users = sync_collection("users")
    cases = sync_collection("workspace_cases")

    def _user(email, role, tenant_ids=None, authority_scope=None):
        doc = {"email": email, "role": role}
        if tenant_ids:
            doc["tenant_ids"] = tenant_ids
        if authority_scope:
            doc["authority_scope"] = authority_scope
        users.update_one({"email": email}, {"$set": doc}, upsert=True)

    _user(U_PLATFORM, "admin", authority_scope="PLATFORM")
    _user(U_CUSTOMER, "analyst", [T_QUIET])
    _user(U_STALE_GRANT, "analyst", [T_GHOST])

    org = (reg._orgs().find_one({"slug": f"b8-org-{SUF}"})
           or reg.create_organization(slug=f"b8-org-{SUF}",
                                      display_name=f"B8 fixture {SUF}",
                                      kind="CUSTOMER",
                                      created_by="test-suite"))
    for tenant in (T_QUIET, T_NOISY, T_SUSPENDED):
        reg.adopt_legacy(tenant_id=tenant, organization_id=org["id"],
                         slug=tenant, display_name=f"B8 {tenant}",
                         created_by="test-suite")
    reg.set_state("tenant", T_SUSPENDED, "SUSPENDED")

    cases.update_one({"id": INC_NOISY}, {"$set": {
        "id": INC_NOISY, "doc_type": "xdr_incident", "tenant_id": T_NOISY,
        "title": f"B8 fixture {T_NOISY}", "incident_state": "new"}},
        upsert=True)

    with client:
        yield

    users.delete_many({"email": {"$regex": f"b8-.*-{SUF}@nivxray.test"}})
    cases.delete_many({"id": INC_NOISY})
    reg._tenants().delete_many({"id": {"$in": [T_QUIET, T_NOISY,
                                               T_SUSPENDED]}})
    reg._orgs().delete_many({"id": org["id"]})


def _auth(email: str, tenant: str | None = None) -> dict:
    from deps import create_token
    headers = {"Authorization": f"Bearer {create_token(email)}"}
    if tenant:
        headers["X-Tenant-Id"] = tenant
    return headers


def _scope(email: str) -> dict:
    r = client.get("/api/xdr/scope/authorized", headers=_auth(email))
    assert r.status_code == 200, r.text
    return r.json()["data"]


def _offered(data: dict) -> list[str]:
    return [t["customer"] for t in data["authorized_tenants"]]


# ── A · the defect itself ─────────────────────────────────────────
def test_a_active_authorized_tenant_with_no_incidents_is_selectable():
    data = _scope(U_PLATFORM)
    assert T_QUIET in _offered(data), (
        "an ACTIVE authorized tenant with zero XDR incidents must be "
        "selectable; this is the defect that emptied the selector")
    # And it is absent from the EVIDENCE list, which is correct.
    assert T_QUIET not in [t["customer"] for t in data["tenants"]]


def test_a_count_and_offer_no_longer_disagree():
    data = _scope(U_PLATFORM)
    assert data["authorized_count"] == len(data["authorized_tenants"]), (
        "the count and the offer must come from the SAME predicate")
    assert data["authorized_count"] >= 2


# ── B · PLATFORM breadth is the authoritative registry ────────────
def test_b_platform_is_offered_every_active_registry_tenant():
    offered = _offered(_scope(U_PLATFORM))
    assert T_QUIET in offered and T_NOISY in offered
    assert data_has_display_names(_scope(U_PLATFORM))


def data_has_display_names(data: dict) -> bool:
    row = next(t for t in data["authorized_tenants"]
               if t["customer"] == T_QUIET)
    return row["display_name"] == f"B8 {T_QUIET}" and "kind" in row


# ── C · a customer principal sees only its own grants ─────────────
def test_c_customer_principal_is_offered_only_its_grants():
    data = _scope(U_CUSTOMER)
    assert _offered(data) == [T_QUIET]
    assert data["cross_tenant_role"] is False
    assert T_NOISY not in _offered(data), "no other tenancy may be disclosed"


# ── D · stale / inactive / unknown fails closed ───────────────────
def test_d_suspended_tenant_is_never_offered():
    assert T_SUSPENDED not in _offered(_scope(U_PLATFORM))


def test_d_grant_naming_an_unregistered_tenant_resolves_to_nothing():
    data = _scope(U_STALE_GRANT)
    assert _offered(data) == []
    assert data["authorized_count"] == 0


# ── E · the evidence list keeps its meaning ───────────────────────
def test_e_evidence_list_is_unchanged_for_a_tenant_with_incidents():
    # `list_customers` is the evidence predicate. It is read directly here
    # because the route caps it at the top 25 tenants BY OPEN VOLUME, so a
    # fixture tenant with a single incident is not guaranteed a place in
    # the response on a busy database — that cap is existing, intended
    # behaviour and is not what this repair touches.
    from services import session_context as sc
    rows = sc.list_customers(U_PLATFORM, limit=500)
    row = next((t for t in rows if t["customer"] == T_NOISY), None)
    assert row is not None, "a tenant WITH incidents must stay in `tenants`"
    assert row["open_incidents"] >= 1
    assert row["queue_href"].endswith(T_NOISY)

    data = _scope(U_PLATFORM)
    for served in data["tenants"]:
        assert {"customer", "open_incidents", "incidents",
                "queue_href"} <= set(served), "evidence row shape changed"
    assert T_NOISY in _offered(data)      # and it is selectable as well


# ── F/G/H · no authorization predicate was changed ────────────────
def test_f_platform_mutation_surface_still_demands_an_explicit_tenant():
    r = client.get("/api/edr/enrollment/tokens", headers=_auth(U_PLATFORM))
    assert r.status_code == 403, r.text
    detail = r.json()["detail"]
    assert detail["code"] == "TENANT_REQUIRED"
    assert detail["basis"] == "CROSS_TENANT_ROLE_NO_SINGLE_CUSTOMER"


def test_g_platform_naming_an_authoritative_tenant_is_authorized():
    r = client.get("/api/edr/enrollment/tokens",
                   headers=_auth(U_PLATFORM, T_QUIET))
    assert r.status_code == 200, r.text
    assert "tokens" in r.json()


def test_h_customer_principal_cannot_name_another_tenant():
    r = client.get("/api/edr/enrollment/tokens",
                   headers=_auth(U_CUSTOMER, T_NOISY))
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["code"] == "TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL"


def test_h_being_offered_a_tenant_is_not_authority_over_a_suspended_one():
    r = client.get("/api/edr/enrollment/tokens",
                   headers=_auth(U_PLATFORM, T_SUSPENDED))
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["code"] in ("TENANT_NOT_ACTIVE",
                                          "TENANT_NOT_FOUND")
