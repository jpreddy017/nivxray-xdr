"""P0.3 · THE security regression gate.

One matrix, five planes, six outcomes. If this file is green, the platform's
authorization contract holds; if any cell flips, a release is blocked.

Planes covered: API keys · secrets · webhooks · audit log · RBAC.

Outcomes proven for every plane:

    unauthenticated                → DENY
    malformed / tampered bearer    → DENY
    expired JWT                    → DENY
    wrong tenant (not authorized)  → DENY
    authenticated, permission short→ DENY
    authorized principal + tenant  → ALLOW

Two further invariants are asserted because both were REAL defects found on
2026-06 and must never come back:

  * `audit.read` / `audit.write` are actually enforced — the audit router's
    permission dependency was returning an un-awaited coroutine, so the
    permission was never evaluated on any audit route.
  * a principal cannot read another tenant's audit chain by naming it — the
    audit router resolved the tenant through the registry only, and never
    asked whether the caller was AUTHORIZED for it.

Nothing here is a unit test: every assertion goes through the real ASGI
dependency graph, because that is exactly where the previous fail-open
defects lived.
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("XDR_AUDIT_MASTER_SECRET", "test-master-secret")
os.environ.setdefault("XDR_SECRETS_MASTER", "test-secrets-master-passphrase")
#: L3 is opt-in and would otherwise hold a threadpool slot through teardown.
os.environ.setdefault("NIVX_L3_DISABLE", "1")

import deps
from routers import xdr_rbac as rb
from server import app
from tests._verified_session import (admin_token, hdrs, login,
                                     provision_session_user, register_tenants)

_S = uuid.uuid4().hex[:6]
TEN = f"gate-{_S}"
OTHER = f"gate-other-{_S}"

READER = f"reader-{_S}@nivxray.gate"      # holds every READ, no write
NARROW = f"narrow-{_S}@nivxray.gate"      # holds one unrelated permission

#: Every plane: a read this gate authorizes, and a write it never does.
READS = {
    "api_keys": "/api/xdr/api-keys",
    "secrets":  "/api/xdr/secrets",
    "webhooks": "/api/xdr/webhooks",
    "audit":    "/api/xdr/audit-log",
    "rbac":     "/api/xdr/rbac/users",
    "collectors": "/api/xdr/collectors",
}
WRITES = {
    "api_keys": ("/api/xdr/api-keys",
                 {"confirm_tenant_id": TEN, "name": f"gate-{_S}",
                  "scopes": []}, "api_keys.create"),
    "secrets":  ("/api/xdr/secrets",
                 {"name": f"gate-{_S}", "kind": "api_key", "value": "v"},
                 "secrets.create"),
    "webhooks": ("/api/xdr/webhooks",
                 {"name": f"gate-{_S}", "url": "https://example.test/h",
                  "events": ["audit.*"]}, "webhooks.create"),
    "audit":    ("/api/xdr/audit-log/emit",
                 {"action": "GATE_FORGED", "resource_kind": "test",
                  "resource_id": "z"}, "audit.write"),
    "rbac":     ("/api/xdr/rbac/roles",
                 {"name": f"gate_{_S}", "display_name": "Gate",
                  "permissions": []}, "roles.create"),
    "collectors": ("/api/xdr/collectors",
                   {"name": f"gate-col-{_S}", "protocol": "rest",
                    "transport": "https"}, "collectors.create"),
}
READ_PERMISSIONS = ["api_keys.read", "secrets.read", "webhooks.read",
                    "audit.read", "users.read", "collectors.read"]

_T: dict[str, str] = {}
PLANES = sorted(READS)


def _denied(status: int) -> bool:
    return status in (401, 403)


@pytest.fixture(scope="module", autouse=True)
def gate():
    if rb._db() is None:
        pytest.skip("MONGO_URL not configured")
    with TestClient(app) as c:
        _T["admin"] = admin_token(c)
        register_tenants(TEN, OTHER, label="gate")
        admin = hdrs(_T["admin"], TEN)

        r = c.post("/api/xdr/rbac/roles", headers=admin,
                   json={"name": f"gate_reader_{_S}",
                         "display_name": "Gate reader",
                         "permissions": READ_PERMISSIONS})
        assert r.status_code == 200, r.text
        reader_role = r.json()["data"]["id"]

        r = c.post("/api/xdr/rbac/roles", headers=admin,
                   json={"name": f"gate_narrow_{_S}",
                         "display_name": "Gate narrow",
                         "permissions": ["lolbas.read"]})
        assert r.status_code == 200, r.text
        narrow_role = r.json()["data"]["id"]

        for email, role in ((READER, reader_role), (NARROW, narrow_role)):
            provision_session_user(email, TEN)
            r = c.post("/api/xdr/rbac/users", headers=admin,
                       json={"email": email, "display_name": email,
                             "initial_roles": [role]})
            assert r.status_code == 200, r.text
            _T[email] = login(c, email)

        globals()["client"] = c
        yield c


# ── 1 · unauthenticated → DENY ────────────────────────────────────
@pytest.mark.parametrize("plane", PLANES)
def test_unauthenticated_read_is_denied(gate, plane):
    r = gate.get(READS[plane])
    assert _denied(r.status_code), f"{plane}: {r.status_code} anonymously"


@pytest.mark.parametrize("plane", PLANES)
def test_unauthenticated_write_is_denied(gate, plane):
    path, body, _ = WRITES[plane]
    r = gate.post(path, json=body)
    assert _denied(r.status_code), f"{plane}: {r.status_code} anonymously"


# ── 2 · malformed / tampered bearer → DENY ────────────────────────
@pytest.mark.parametrize("plane", PLANES)
def test_tampered_bearer_is_denied(gate, plane):
    real = _T[READER]
    tampered = real[:-4] + ("aaaa" if not real.endswith("aaaa") else "bbbb")
    for token in ("not-a-jwt", tampered):
        r = gate.get(READS[plane],
                     headers={"Authorization": f"Bearer {token}",
                              "X-Tenant-Id": TEN})
        assert _denied(r.status_code), f"{plane}: {r.status_code} for {token[:12]}"


# ── 3 · expired JWT → DENY ────────────────────────────────────────
@pytest.mark.parametrize("plane", PLANES)
def test_expired_jwt_is_denied(gate, plane):
    past = datetime.now(timezone.utc) - timedelta(hours=3)
    expired = jwt.encode({"sub": READER, "iat": past,
                          "exp": past + timedelta(minutes=1)},
                         deps.JWT_SECRET, algorithm=deps.JWT_ALG)
    r = gate.get(READS[plane], headers={"Authorization": f"Bearer {expired}",
                                        "X-Tenant-Id": TEN})
    assert _denied(r.status_code), f"{plane}: {r.status_code} for expired JWT"


# ── 4 · wrong tenant → DENY ───────────────────────────────────────
@pytest.mark.parametrize("plane", PLANES)
def test_wrong_tenant_is_denied(gate, plane):
    """READER holds the permission — in ITS tenant. Naming another one is
    not a permission problem, it is a tenancy refusal, and the permission
    must not rescue it."""
    r = gate.get(READS[plane], headers=hdrs(_T[READER], OTHER))
    assert r.status_code == 403, f"{plane}: {r.status_code} cross-tenant"
    code = r.json().get("detail", {})
    code = code.get("code") if isinstance(code, dict) else None
    assert code in ("TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL", "ACCESS_DENIED"), \
        f"{plane}: {r.text}"


# ── 5 · authenticated but permission-short → DENY ─────────────────
@pytest.mark.parametrize("plane", PLANES)
def test_insufficient_permission_is_denied(gate, plane):
    r = gate.get(READS[plane], headers=hdrs(_T[NARROW], TEN))
    assert r.status_code == 403, f"{plane}: {r.status_code} for narrow role"
    assert r.json()["detail"]["code"] == "ACCESS_DENIED", r.text


@pytest.mark.parametrize("plane", PLANES)
def test_read_permission_does_not_grant_write(gate, plane):
    """READER holds every READ. A read is not a licence to write."""
    path, body, permission = WRITES[plane]
    r = gate.post(path, json=body, headers=hdrs(_T[READER], TEN))
    assert r.status_code == 403, f"{plane}: {r.status_code} for reader write"
    detail = r.json()["detail"]
    assert detail["code"] == "ACCESS_DENIED", detail
    assert detail["permission"] == permission, detail


# ── 6 · authorized principal + authorized tenant → ALLOW ──────────
@pytest.mark.parametrize("plane", PLANES)
def test_authorized_read_is_allowed(gate, plane):
    r = gate.get(READS[plane], headers=hdrs(_T[READER], TEN))
    assert r.status_code == 200, f"{plane}: {r.text}"


# ── 7 · the two 2026-06 defects, pinned permanently ───────────────
def test_audit_permission_is_actually_evaluated(gate):
    """REGRESSION · the audit router's permission dependency was a sync
    function calling an async dependency, so the returned coroutine was
    never awaited and `audit.read` / `audit.write` were not enforced on ANY
    audit route. A principal without them must be refused."""
    r = gate.get("/api/xdr/audit-log", headers=hdrs(_T[NARROW], TEN))
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["permission"] == "audit.read", r.text

    r = gate.post("/api/xdr/audit-log/emit", headers=hdrs(_T[NARROW], TEN),
                  json={"action": "GATE_FORGED", "resource_kind": "test",
                        "resource_id": "z"})
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["permission"] == "audit.write", r.text


def test_audit_chain_of_another_tenant_is_unreadable(gate):
    """REGRESSION · the audit router resolved the tenant through the registry
    only and never authorized the principal for it, so a principal holding
    `audit.read` in tenant A could read tenant B's entire chain. Proven by
    reading 18 foreign events before the repair."""
    r = gate.get("/api/xdr/audit-log", headers=hdrs(_T[READER], OTHER))
    assert r.status_code == 403, r.text
    r = gate.get(f"/api/xdr/audit-log?tenant={OTHER}",
                 headers=hdrs(_T[READER], TEN))
    if r.status_code == 200:
        for e in r.json()["data"]["events"]:
            assert e["tenant_id"] == TEN, \
                f"cross-tenant leak via ?tenant=: {e['tenant_id']}"
    else:
        assert r.status_code == 403, r.text


def test_client_supplied_identity_header_is_never_an_identity(gate):
    """`X-Principal-Id` was the 2026-09-09 fail-open defect. Presenting it
    with NO bearer must remain a denial on every plane."""
    for path in READS.values():
        r = gate.get(path, headers={"X-Tenant-Id": TEN,
                                    "X-Principal-Id": os.environ["ADMIN_EMAIL"],
                                    "X-Principal-Kind": "user"})
        assert _denied(r.status_code), f"{path} honoured a header identity"
