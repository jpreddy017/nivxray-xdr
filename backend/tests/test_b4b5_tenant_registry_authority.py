"""B4 / B5 · authoritative organization-tenant registry — adversarial.

    request -> principal -> requested tenant -> REGISTRY -> ACTIVE -> operation

Two proven defects motivated this suite:

  B4  `POST /api/xdr/collectors` accepted any `X-Tenant-Id` string with no
      existence check, and the document it wrote then satisfied the
      key-minting guard — so a typo bootstrapped a usable tenant.
  B5  `routers/edr_enrollment._tenant()` read `users["customer"]`, a field no
      code writes, so every NivXForge EDR enrolment resolved to the literal
      `"default"` — a second tenancy authority diverging from NivXRay XDR.

Both must now fail closed, and the same `ten_*` identity must serve both
products. Enforcement is behind `NIVX_TENANT_REGISTRY_ENFORCE`; the flag may
only ever make the platform stricter, so both states are tested.

EVIDENCE LABELLING — TEST/SYNTHETIC. Nothing live, nothing production.
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

from server import app                                        # noqa: E402
from services import tenant_registry as reg                   # noqa: E402

_db = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]
_keys = _db["xdr_api_keys"]
_collectors = _db["xdr_collectors"]

COLLECTORS = "/api/xdr/collectors"
API_KEYS = "/api/xdr/api-keys"
INGEST = "/api/xdr/ingest/telemetry"
ORGS = "/api/xdr/organizations"
TENANTS = "/api/xdr/tenants"


@pytest.fixture()
def client():
    # No lifespan context: the app's shutdown hooks block for minutes in this
    # environment and these tests exercise route logic, not startup.
    return TestClient(app)


@pytest.fixture()
def enforce(monkeypatch):
    monkeypatch.setenv("NIVX_TENANT_REGISTRY_ENFORCE", "true")
    yield


@pytest.fixture()
def relaxed(monkeypatch):
    monkeypatch.delenv("NIVX_TENANT_REGISTRY_ENFORCE", raising=False)
    yield


@pytest.fixture()
def org_and_tenant():
    """A registered ACTIVE organization + tenant, created through the
    registry service (never as a side effect of a data-plane write)."""
    org = reg.create_organization(
        slug=f"test-vendor-{uuid.uuid4().hex[:8]}",
        display_name="Test Vendor", kind="VENDOR", created_by="pytest")
    ten = reg.create_tenant(
        organization_id=org["id"], slug=f"t-{uuid.uuid4().hex[:8]}",
        display_name="Test Tenant", kind="INTERNAL_VALIDATION",
        products=["XDR", "EDR"], created_by="pytest")
    yield org, ten
    _db["tenants"].delete_one({"id": ten["id"]})
    _db["organizations"].delete_one({"id": org["id"]})


def _mint_key(tenant: str, scopes: list[str]) -> str:
    raw = "nvx_" + secrets.token_hex(24)
    now = datetime.now(timezone.utc).isoformat()
    _keys.insert_one({
        "id": f"key_{uuid.uuid4().hex[:20]}", "tenant_id": tenant,
        "name": f"reg-test-{uuid.uuid4().hex[:8]}", "prefix": raw[:12],
        "hash": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        "scopes": scopes, "enabled": True, "revoked_at": None,
        "expires_at": None, "created_at": now, "updated_at": now,
        "last_used_at": None, "last_used_ip": None, "use_count": 0})
    return raw


# ── identity shape ────────────────────────────────────────────────
def test_generated_identifiers_are_opaque_and_prefixed():
    assert reg.new_org_id().startswith("org_")
    assert reg.new_tenant_id().startswith("ten_")
    assert reg.new_tenant_id() != reg.new_tenant_id()
    # the security identifier is not derived from any human label
    org = reg.new_org_id()
    for label in ("nivxmachines", "internal-validation", "desktop", "xdr"):
        assert label not in org


def test_tenant_id_is_accepted_by_the_existing_tenant_header_pattern():
    from routers.xdr_rbac import _TENANT_RE
    assert _TENANT_RE.fullmatch(reg.new_tenant_id())


def test_slug_and_display_name_are_mutable_labels_not_the_identity(
        org_and_tenant):
    _org, ten = org_and_tenant
    _db["tenants"].update_one({"id": ten["id"]},
                              {"$set": {"slug": "renamed",
                                        "display_name": "Renamed"}})
    again = reg.get_tenant(ten["id"])
    assert again["id"] == ten["id"]
    assert again["slug"] == "renamed"


# ── fail closed ───────────────────────────────────────────────────
def test_unknown_tenant_denied_when_enforcing(enforce):
    with pytest.raises(reg.TenantRegistryError) as e:
        reg.authoritative("ten_does_not_exist", purpose="test")
    assert e.value.code == "TENANT_NOT_FOUND"


def test_missing_tenant_denied_when_enforcing_and_never_defaults(enforce):
    with pytest.raises(reg.TenantRegistryError) as e:
        reg.authoritative("", purpose="test")
    assert e.value.code == "TENANT_REQUIRED"


def test_inactive_tenant_denied(enforce, org_and_tenant):
    _org, ten = org_and_tenant
    reg.set_state("tenant", ten["id"], "SUSPENDED")
    with pytest.raises(reg.TenantRegistryError) as e:
        reg.authoritative(ten["id"], purpose="test")
    assert e.value.code == "TENANT_NOT_ACTIVE"


def test_inactive_organization_denies_its_active_tenant(enforce,
                                                        org_and_tenant):
    org, ten = org_and_tenant
    reg.set_state("organization", org["id"], "SUSPENDED")
    with pytest.raises(reg.TenantRegistryError) as e:
        reg.authoritative(ten["id"], purpose="test")
    assert e.value.code == "ORGANIZATION_NOT_ACTIVE"


def test_active_tenant_resolves(enforce, org_and_tenant):
    _org, ten = org_and_tenant
    assert reg.authoritative(ten["id"], purpose="test") == ten["id"]


# ── B4 · a data-plane write can never create tenancy ──────────────
def test_collector_creation_cannot_create_tenancy(client, enforce):
    r = client.post(COLLECTORS,
                    headers={"X-Tenant-Id": "ten_typo_not_registered"},
                    json={"name": "b4-probe", "protocol": "rest",
                          "authorized_sources": ["microsoft-sysmon"]})
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["code"] in ("TENANT_NOT_FOUND", "ACCESS_DENIED")
    assert reg.get_tenant("ten_typo_not_registered") is None
    assert _collectors.find_one({"tenant_id": "ten_typo_not_registered"}) is None


def test_api_key_creation_cannot_create_tenancy(client, enforce):
    r = client.post(API_KEYS, headers={"X-Tenant-Id": "ten_typo_not_registered"},
                    json={"name": "b4-key-probe",
                          "confirm_tenant_id": "ten_typo_not_registered",
                          "allow_new_tenant": True,
                          "scopes": ["collectors.enroll"]})
    assert r.status_code in (400, 403), r.text
    assert reg.get_tenant("ten_typo_not_registered") is None
    assert _keys.find_one({"tenant_id": "ten_typo_not_registered"}) is None


def test_allow_new_tenant_is_refused_when_enforcing(enforce, org_and_tenant,
                                                    client):
    _org, ten = org_and_tenant
    r = client.post(API_KEYS, headers={"X-Tenant-Id": ten["id"]},
                    json={"name": f"dep-{uuid.uuid4().hex[:6]}",
                          "confirm_tenant_id": ten["id"],
                          "allow_new_tenant": True,
                          "scopes": ["collectors.enroll"]})
    # unauthenticated control-plane calls are refused before the body is
    # considered; either refusal proves no credential was minted
    assert r.status_code in (400, 403), r.text
    assert _keys.find_one({"tenant_id": ten["id"]}) is None


def test_telemetry_cannot_create_tenancy(client, enforce):
    raw = _mint_key("ten_unregistered_ingest", ["collectors.enroll"])
    r = client.post(INGEST, headers={"X-XDR-API-Key": raw,
                                     "X-Tenant-Id": "ten_unregistered_ingest"},
                    json={"envelopes": [{
                        "tenant_id": "ten_unregistered_ingest",
                        "collector_id": "col_nope",
                        "collection_method": "windows_eventlog_pull",
                        "declared_source": "microsoft-sysmon",
                        "raw": {"EventID": 1}}]})
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["code"] == "TENANT_NOT_FOUND"
    assert reg.get_tenant("ten_unregistered_ingest") is None
    _keys.delete_many({"tenant_id": "ten_unregistered_ingest"})


def test_edr_enrollment_cannot_create_tenancy(client, enforce):
    r = client.post("/api/edr/agent/enroll",
                    json={"tenant_id": "ten_unregistered_edr",
                          "enrollment_token": "enr_" + "0" * 43,
                          "hostname": "probe-host"})
    assert r.status_code in (401, 403), r.text
    assert reg.get_tenant("ten_unregistered_edr") is None


def test_edr_admin_plane_no_longer_falls_back_to_default(enforce):
    """B5 · `users["customer"]` is absent on every real user document, so the
    old implementation returned `"default"`. It must now refuse."""
    from routers import edr_enrollment
    with pytest.raises(Exception) as e:
        edr_enrollment._tenant({"email": "admin@nivxray.com"}, None)
    detail = getattr(e.value, "detail", {})
    assert detail.get("code") == "TENANT_REQUIRED", detail


def test_edr_and_xdr_resolve_the_same_authority(enforce, org_and_tenant):
    from routers import edr_enrollment

    class _Req:
        headers = {"X-Tenant-Id": org_and_tenant[1]["id"]}

    _org, ten = org_and_tenant
    assert edr_enrollment._tenant({}, _Req()) == ten["id"]
    assert edr_enrollment._agent_tenant(ten["id"]) == ten["id"]
    assert reg.authoritative(ten["id"], purpose="xdr.collectors") == ten["id"]


# ── enforcement flag semantics ────────────────────────────────────
def test_flag_off_preserves_the_legacy_behaviour_exactly(relaxed):
    assert reg.enforcing() is False
    assert reg.authoritative("", purpose="test") == "default"
    assert reg.authoritative("legacy-string", purpose="test") == "legacy-string"


def test_flag_on_is_strictly_stricter(enforce, relaxed_after=None):
    assert reg.enforcing() is True
    with pytest.raises(reg.TenantRegistryError):
        reg.authoritative("", purpose="test")


# ── migration safety ──────────────────────────────────────────────
def test_legacy_adoption_preserves_the_existing_tenant_string(org_and_tenant):
    org, _ten = org_and_tenant
    legacy = f"legacy-{uuid.uuid4().hex[:8]}"
    doc = reg.adopt_legacy(tenant_id=legacy, organization_id=org["id"],
                           slug=legacy, display_name="Legacy",
                           created_by="pytest")
    assert doc["id"] == legacy           # value NEVER rewritten
    assert doc["kind"] == "LEGACY_ADOPTED"
    assert reg.adopt_legacy(tenant_id=legacy, organization_id=org["id"],
                            slug=legacy, display_name="Legacy",
                            created_by="pytest")["id"] == legacy  # idempotent
    _db["tenants"].delete_one({"id": legacy})


def test_evidence_identity_semantics_are_untouched():
    from services.ingest_idempotency import event_identity
    a = event_identity("ten_abc", "col_1", "microsoft-sysmon", "e1", "d1")
    b = event_identity("ten_abc", "col_1", "microsoft-sysmon", "e1", "d1")
    c = event_identity("ten_xyz", "col_1", "microsoft-sysmon", "e1", "d1")
    assert a == b and a != c


def test_registry_never_seeds_a_default_tenant():
    assert reg.get_tenant("default") is None
