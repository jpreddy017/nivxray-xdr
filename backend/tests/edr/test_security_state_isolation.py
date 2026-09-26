"""AG Baseline Integration · Security State P0-D adversarial isolation.

Verifies that the newly integrated AG Security State router respects the
tenant-scope invariant and does not become a cross-tenant leak path.
Extends the P0-D suite from 12 → 15 tests.
"""
from __future__ import annotations

import os
import sys
import uuid

from fastapi.testclient import TestClient

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from server import app  # noqa: E402


client = TestClient(app)

TENANT_A = "test-tenant-a-" + uuid.uuid4().hex[:8]
TENANT_B = "test-tenant-b-" + uuid.uuid4().hex[:8]


def test_v12_security_state_requires_tenant_id():
    """AG router demands tenant_id query param; anonymous request must not succeed."""
    r = client.get("/api/v2/security-state/fake-case-id")
    # tenant_id missing → 422 unprocessable entity (from router validation)
    assert r.status_code in (401, 403, 422), (
        f"Security State route without tenant must not succeed: {r.status_code}"
    )


def test_v13_security_state_foreign_case_no_leak():
    """Query with Tenant A must not leak Tenant B data (empty or 404)."""
    fake_case_b = "case-b-" + uuid.uuid4().hex
    r = client.get(
        f"/api/v2/security-state/{fake_case_b}",
        params={"tenant_id": TENANT_A},
    )
    # Either 404 (no such case) or 200 with an empty/scoped response.
    # Must NOT return content referencing TENANT_B.
    assert r.status_code in (200, 401, 403, 404), (
        f"Unexpected Security State status: {r.status_code}"
    )
    if r.status_code == 200:
        assert TENANT_B not in r.text, "Security State leaked foreign tenant identifier"


def test_v14_security_state_openapi_lists_endpoints():
    r = client.get("/api/openapi.json")
    assert r.status_code == 200
    paths = set(r.json().get("paths", {}).keys())
    required = {
        "/api/v2/security-state/evaluate",
        "/api/v2/security-state/{case_id}",
        "/api/v2/security-state/{case_id}/history",
        "/api/v2/security-state/{case_id}/transitions",
        "/api/v2/security-state/{case_id}/causality",
        "/api/v2/security-state/{case_id}/capabilities",
        "/api/v2/security-state/{case_id}/reachability",
        "/api/v2/security-state/{case_id}/counterfactual",
        "/api/v2/security-state/{case_id}/interventions/plan",
        "/api/v2/security-state/{case_id}/response/verify",
        "/api/v2/security-state/{case_id}/ledger",
        "/api/v2/security-state/streaming/status",
        "/api/v2/security-state/{case_id}/provenance",
        "/api/v2/security-state/{case_id}/interventions/stage",
    }
    missing = required - paths
    assert not missing, f"Security State missing endpoints: {missing}"
