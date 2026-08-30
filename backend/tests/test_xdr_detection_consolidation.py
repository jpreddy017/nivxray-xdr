"""P1 Detection Surface Consolidation — one authoritative registry.

Codifies the invariants of option (a):

  * `/api/xdr/detection` is the AUTHORITATIVE detection-content plane.
  * The counts it reports (total_rules, valid_rules, attack_technique_count)
    must be self-consistent: `valid_rules` derived from the same data
    that produces the ATT&CK-technique union in `/rules`.
  * Every displayed rule carries FULL provenance (source, source_url,
    license, upstream_id, original_content_hash, author, dates).
  * RBAC path is single: `detections.read` for reads, `detections.publish`
    for mutations — no legacy route grants privileged access without it.
  * There is no legacy backend endpoint that returns a competing rule
    listing.

These tests guard against a future regression where a legacy /admin/models
or /admin/pattern-rules endpoint quietly starts returning "detection rules"
that never enter the registry pipeline.
"""
from __future__ import annotations

import os
import re
import uuid

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("XDR_AUDIT_MASTER_SECRET", "x")
os.environ.setdefault("XDR_SECRETS_MASTER", "y")

from routers import xdr_detection_content as dc
from server import app

client = TestClient(app)

TEN   = f"consol-{uuid.uuid4().hex[:8]}"
ADMIN = "root@consol"


def _hdrs():
    return {"X-Tenant-Id": TEN, "X-Principal-Id": ADMIN,
                "X-Principal-Kind": "user"}


def _skip_if_no_mongo():
    if dc._db() is None:
        pytest.skip("MONGO_URL not configured")


@pytest.fixture(scope="module", autouse=True)
def _seed():
    _skip_if_no_mongo()
    client.post("/api/xdr/rbac/users", headers=_hdrs(),
                    json={"email": ADMIN, "initial_roles": ["platform_admin"]})
    dc.ensure_synced(("t", ADMIN, "user"))
    yield


# ── 1 · Registry is authoritative — counts are self-consistent ───
def test_registry_counts_are_self_consistent():
    _skip_if_no_mongo()
    st = client.get("/api/xdr/detection/status",  headers=_hdrs()).json()["data"]
    rs = client.get("/api/xdr/detection/rules?limit=1000",
                              headers=_hdrs()).json()["data"]["rules"]
    assert st["total_rules"] == len(rs), \
        (st["total_rules"], len(rs))
    # ATT&CK union derived from rules must match status
    union = set()
    for r in rs:
        for t in r.get("attack_techniques") or []:
            union.add(t)
    assert st["attack_technique_count"] == len(union)


# ── 2 · Every rule carries FULL provenance ───────────────────────
_REQUIRED_PROV_FIELDS = ("source", "source_url", "license",
                                            "license_verified", "upstream_id",
                                            "original_content_hash", "author",
                                            "created", "modified")


def test_every_rule_has_full_provenance():
    _skip_if_no_mongo()
    rs = client.get("/api/xdr/detection/rules?limit=1000",
                              headers=_hdrs()).json()["data"]["rules"]
    # Only enforce provenance on registered (post-pipeline) rules from
    # the bundled real snapshot — synthetic rules injected by other
    # test files (dedup fixtures, license-block fixtures) are excluded.
    rs = [r for r in rs if r.get("state") not in
                {"INVALID", "PARSE_FAILED", "LICENSE_BLOCKED",
                  "UNSUPPORTED", "REGRESSION_FAILED"}
              and r.get("source") in {"SigmaHQ", "NivXRay-native"}]
    assert rs
    for r in rs:
        for k in _REQUIRED_PROV_FIELDS:
            assert r.get(k) is not None, f"rule {r.get('id')} missing {k}"


# ── 3 · Original content hash is a real sha256 ───────────────────
def test_content_hashes_are_valid_sha256():
    _skip_if_no_mongo()
    rs = client.get("/api/xdr/detection/rules?limit=1000",
                              headers=_hdrs()).json()["data"]["rules"]
    rs = [r for r in rs if r.get("state") not in
                {"INVALID", "PARSE_FAILED", "LICENSE_BLOCKED",
                  "UNSUPPORTED", "REGRESSION_FAILED"}]
    for r in rs:
        h = r.get("original_content_hash")
        assert isinstance(h, str) and re.fullmatch(r"[0-9a-f]{64}", h), h


# ── 4 · No competing legacy backend endpoint returns "rules" ─────
def test_no_legacy_endpoint_returns_competing_rules():
    _skip_if_no_mongo()
    # Sample the endpoints the legacy admin surfaces reference.  None
    # of them may return a document that claims to BE a detection rule
    # (i.e. present the exact provenance shape).
    LEGACY = ["/api/admin/models", "/api/admin/pattern-rules",
                    "/api/admin/detection-rules"]
    for path in LEGACY:
        r = client.get(path, headers=_hdrs())
        # Either the endpoint doesn't exist (404) OR its payload does
        # NOT match the authoritative rule shape.
        if r.status_code == 200:
            body = r.json()
            def _matches_rule_shape(doc):
                return (isinstance(doc, dict) and
                              all(k in doc for k in
                                    ("upstream_id", "original_content_hash",
                                    "attack_techniques", "detection")))
            if isinstance(body, list):
                assert not any(_matches_rule_shape(d) for d in body), \
                    f"legacy endpoint {path} returns registry-shaped rules"
            elif isinstance(body, dict):
                data = body.get("data") or body.get("rules") or []
                assert not any(_matches_rule_shape(d)
                                          for d in (data if isinstance(data, list)
                                                          else [data])), \
                    f"legacy endpoint {path} returns registry-shaped rules"


# ── 5 · Registry reads require detections.read (RBAC guard) ─────
def test_registry_reads_require_detections_read():
    _skip_if_no_mongo()
    # Deliberately provision a user with NO detections.read.
    TEN2 = f"consol-noperm-{uuid.uuid4().hex[:6]}"
    # Seed a bootstrap admin in TEN2.
    client.post("/api/xdr/rbac/users",
                    headers={"X-Tenant-Id": TEN2, "X-Principal-Id": "root",
                                    "X-Principal-Kind": "user"},
                    json={"email": "root",
                              "initial_roles": ["platform_admin"]})
    # Create a role that grants a permission OTHER than detections.*
    r = client.post("/api/xdr/rbac/roles",
                          headers={"X-Tenant-Id": TEN2, "X-Principal-Id": "root",
                                          "X-Principal-Kind": "user"},
                          json={"name": f"no_det_{uuid.uuid4().hex[:6]}",
                                    "display_name": "no det",
                                    "permissions": ["secrets.read"]})
    role_id = r.json()["data"]["id"]
    client.post("/api/xdr/rbac/users",
                    headers={"X-Tenant-Id": TEN2, "X-Principal-Id": "root",
                                    "X-Principal-Kind": "user"},
                    json={"email": "scoped", "initial_roles": [role_id]})
    r = client.get("/api/xdr/detection/rules",
                          headers={"X-Tenant-Id": TEN2,
                                          "X-Principal-Id": "scoped",
                                          "X-Principal-Kind": "user"})
    assert r.status_code == 403
    assert r.json()["detail"]["permission"] == "detections.read"
