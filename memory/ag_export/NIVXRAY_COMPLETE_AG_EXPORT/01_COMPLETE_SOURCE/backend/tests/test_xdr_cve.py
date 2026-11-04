"""XDR CVE / Vulnerability Exposure pillar — pytest.

Covers the six exposure states + the non-negotiable semantic invariant:
    CVE ≠ vulnerable ≠ exploitable ≠ exploited ≠ compromised
"""
from __future__ import annotations

import os
import uuid

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("XDR_AUDIT_MASTER_SECRET", "test-master-secret")
os.environ.setdefault("XDR_SECRETS_MASTER", "test-secrets-master-passphrase")

from routers import xdr_cve as cve
from routers import xdr_rbac as rb
from server import app

client = TestClient(app)

TEN    = f"cve-{uuid.uuid4().hex[:8]}"
ADMIN  = "root@cve"


def _hdrs(email=ADMIN, tenant=None):
    return {"X-Tenant-Id": tenant or TEN,
                "X-Principal-Id": email,
                "X-Principal-Kind": "user"}


def _skip():
    if cve._db() is None:
        pytest.skip("MONGO_URL not configured")


@pytest.fixture(scope="module", autouse=True)
def _seed():
    _skip()
    for c in (rb._c_users, rb._c_roles, rb._c_groups, rb._c_assignments):
        if c() is not None:
            c().delete_many({"tenant_id": TEN})
    for c in (cve._c_assets, cve._c_software, cve._c_exposures):
        if c() is not None:
            c().delete_many({"tenant_id": TEN})
    client.post("/api/xdr/rbac/users", headers=_hdrs(),
                     json={"email": ADMIN, "initial_roles": ["platform_admin"]})
    cve.ensure_synced(("t", ADMIN, "user"))
    yield


def test_cve_bundle_populated():
    _skip()
    r = client.get("/api/xdr/cve/status", headers=_hdrs())
    assert r.status_code == 200
    d = r.json()["data"]
    assert d["total_cves"] >= 12
    assert d["kev_listed"] >= 10
    assert "CVE ≠ vulnerable" in d["semantic_contract"]
    assert d["exposure_states"] == cve.EXPOSURE_STATES


def test_cve_list_and_get():
    _skip()
    r = client.get("/api/xdr/cve/list?kev=true&severity=CRITICAL",
                              headers=_hdrs())
    cves = r.json()["data"]["cves"]
    assert cves, "expected KEV-listed CRITICAL CVEs"
    for c in cves:
        assert c["kev"]["listed"] is True
        assert c["cvss_v3"]["severity"] == "CRITICAL"
    r = client.get(f"/api/xdr/cve/{cves[0]['cve_id']}", headers=_hdrs())
    assert r.status_code == 200


def test_exposure_state_machine_never_infers_higher_states():
    """The critical semantic contract: CVE_PRESENT alone must NEVER
    escalate to VULNERABLE / EXPLOITABLE without independent evidence."""
    _skip()
    # 1) Register an asset with NO software matching any CVE.
    r = client.post("/api/xdr/cve/assets", headers=_hdrs(),
                          json={"name": "empty-host", "kind": "endpoint"})
    empty_asset = r.json()["data"]["id"]

    # 2) Register an asset running vulnerable Log4j.
    r = client.post("/api/xdr/cve/assets", headers=_hdrs(),
                          json={"name": "web-01", "kind": "endpoint",
                                    "network_reachable": True})
    web_asset = r.json()["data"]["id"]
    r = client.post("/api/xdr/cve/software", headers=_hdrs(),
                          json={"asset_id": web_asset, "vendor": "apache",
                                    "product": "log4j", "version": "2.14.1",
                                    "patched": False})
    assert r.status_code == 200

    # 3) A second asset with the SAME software but PATCHED — should NOT
    #    escalate to VULNERABLE_ASSET.
    r = client.post("/api/xdr/cve/assets", headers=_hdrs(),
                          json={"name": "web-02", "kind": "endpoint"})
    patched_asset = r.json()["data"]["id"]
    client.post("/api/xdr/cve/software", headers=_hdrs(),
                     json={"asset_id": patched_asset, "vendor": "apache",
                                "product": "log4j", "version": "2.17.1",
                                "patched": True})

    # 4) Compute exposures
    r = client.post("/api/xdr/cve/exposures/compute", headers=_hdrs())
    d = r.json()["data"]

    # Empty asset produced ZERO exposure evidence.
    er = client.get("/api/xdr/cve/exposures?asset_id="
                              + empty_asset, headers=_hdrs())
    assert er.json()["data"]["count"] == 0, \
        "asset with no matching software must have NO exposures"

    # The vulnerable web-01 host produced at least one EXPLOITABLE
    # exposure for Log4Shell — because KEV is listed for that CVE.
    er = client.get(f"/api/xdr/cve/exposures?asset_id={web_asset}",
                              headers=_hdrs())
    rows = er.json()["data"]["exposures"]
    log4shell = [x for x in rows if x["cve_id"] == "CVE-2021-44228"]
    assert log4shell, "expected Log4Shell exposure on web-01"
    ex = log4shell[0]
    # Independent evidence recorded for each transition — never
    # inferred from a lower state alone.
    assert "AFFECTED_SOFTWARE" in ex["evidence"]
    assert "VULNERABLE_ASSET"  in ex["evidence"]
    assert "EXPLOITABLE"       in ex["evidence"]
    assert ex["state"] == "EXPLOITABLE"
    # NEVER escalates automatically to EXPLOITATION_OBSERVED
    # or COMPROMISE_EVIDENCE without their own evidence buckets.
    assert "EXPLOITATION_OBSERVED" not in ex["evidence"]
    assert "COMPROMISE_EVIDENCE"   not in ex["evidence"]
    assert ex["capability_not_verdict"] is True

    # The patched host — even though software matches — is NOT VULNERABLE.
    er = client.get(f"/api/xdr/cve/exposures?asset_id={patched_asset}",
                              headers=_hdrs())
    rows = er.json()["data"]["exposures"]
    p = [x for x in rows if x["cve_id"] == "CVE-2021-44228"]
    assert p, "expected AFFECTED_SOFTWARE exposure on patched host"
    assert p[0]["state"] == "AFFECTED_SOFTWARE"
    assert "VULNERABLE_ASSET" not in p[0]["evidence"]

    # by_state summary matches state machine order (no fabricated states)
    for s in d["by_state"]:
        assert s in cve.EXPOSURE_STATES


def test_scoped_user_denied_on_mutations():
    _skip()
    scoped = f"scoped-{uuid.uuid4().hex[:6]}@x"
    r = client.post("/api/xdr/rbac/roles", headers=_hdrs(),
                          json={"name": f"cve_ro_{uuid.uuid4().hex[:6]}",
                                    "display_name": "cve ro",
                                    "permissions": ["detections.read"]})
    role_id = r.json()["data"]["id"]
    client.post("/api/xdr/rbac/users", headers=_hdrs(),
                     json={"email": scoped, "initial_roles": [role_id]})
    for method, path in [("POST", "/api/xdr/cve/sync"),
                                    ("POST", "/api/xdr/cve/exposures/compute"),
                                    ("POST", "/api/xdr/cve/assets"),
                                    ("POST", "/api/xdr/cve/software")]:
        r = getattr(client, method.lower())(
            path, headers=_hdrs(scoped),
            json={"name": "x", "asset_id": "x", "vendor": "v", "product": "p"})
        assert r.status_code == 403, (path, r.text)


def test_idempotent_sync():
    _skip()
    r1 = client.post("/api/xdr/cve/ensure-synced", headers=_hdrs())
    r2 = client.post("/api/xdr/cve/ensure-synced", headers=_hdrs())
    assert r2.json()["data"].get("already_synced") \
        or r2.json()["data"].get("idempotent_skip")
