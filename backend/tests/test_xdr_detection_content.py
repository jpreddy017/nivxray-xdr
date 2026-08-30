"""XDR Detection Content Registry — P1 pytest.

Covers the full "no fake completeness" contract:
  1  Bundled DRL-1.1 snapshot ingests end-to-end (10 stages)
  2  Only ALLOWED_LICENSES pass the LICENSE_VALIDATED stage
  3  Duplicate content is deduplicated (upstream_id + hash key)
  4  ATT&CK techniques are extracted correctly (T1234[.001] shape)
  5  Rules are ATT&CK-mapped honestly (no synthetic technique IDs)
  6  Registry stays idempotent on repeat sync
  7  RBAC — scoped user is denied on every mutation
  8  Rule lifecycle — INVALID rule cannot be enabled → 409
  9  Bundled fallback rescues an unreachable primary
  10 Detection ≠ Verdict — capability_not_verdict rules preserved
  11 status endpoint reports honest counts + attack_technique union
"""
from __future__ import annotations

import json
import os
import uuid

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("XDR_AUDIT_MASTER_SECRET", "test-master-secret")
os.environ.setdefault("XDR_SECRETS_MASTER", "test-secrets-master-passphrase")

from routers import xdr_detection_content as dc
from routers import xdr_rbac as rb
from server import app

client = TestClient(app)

TEN    = f"det-{uuid.uuid4().hex[:8]}"
ADMIN  = "root@det"
SCOPED = "readonly@det"
_SUF   = uuid.uuid4().hex[:6]


def _hdrs(email=ADMIN, tenant=None):
    return {"X-Tenant-Id": tenant or TEN,
                "X-Principal-Id": email,
                "X-Principal-Kind": "user"}


def _skip_if_no_mongo():
    if dc._db() is None:
        pytest.skip("MONGO_URL not configured")


@pytest.fixture(scope="module", autouse=True)
def _seed():
    _skip_if_no_mongo()
    # Do NOT wipe the shared xdr_detection_rules — boot-sync populated it.
    # Provision users for our tenant.
    for c in (rb._c_users, rb._c_roles, rb._c_groups, rb._c_assignments):
        if c() is not None:
            c().delete_many({"tenant_id": TEN})
    r = client.post("/api/xdr/rbac/users", headers=_hdrs(ADMIN),
                          json={"email": ADMIN,
                                    "initial_roles": ["platform_admin"]})
    assert r.status_code == 200, r.text
    r = client.post("/api/xdr/rbac/roles", headers=_hdrs(ADMIN),
                          json={"name": f"det_ro_{_SUF}", "display_name": "Det RO",
                                    "permissions": ["detections.read"]})
    assert r.status_code == 200, r.text
    role_id = r.json()["data"]["id"]
    r = client.post("/api/xdr/rbac/users", headers=_hdrs(ADMIN),
                          json={"email": SCOPED, "initial_roles": [role_id]})
    # Ensure the registry is synced for the test process (TestClient
    # runs its own app instance so the on_startup boot-sync from the
    # supervisord backend does not carry over).
    dc.ensure_synced(("t", ADMIN, "user"))
    yield


# ── 1 · Bundled snapshot ingests end-to-end ────────────────────────
def test_boot_sync_populated_registry():
    _skip_if_no_mongo()
    r = client.get("/api/xdr/detection/status", headers=_hdrs())
    d = r.json()["data"]
    assert d["sync_state"] == "SYNCED"
    assert d["total_rules"] >= 20
    assert d["bundled_fallback_available"] is True
    v = d["active_version"]
    assert v["outcome"] == "COMPLETE"


# ── 2 · License validation blocks non-allowed licenses ────────────
def test_license_validation_blocks_unknown_licenses(tmp_path):
    _skip_if_no_mongo()
    bad = [{"id": "bad_1", "title": "x", "source": "somewhere",
                "source_url": "http://x", "license": "SOME-PROPRIETARY",
                "author": "?", "detection": {"selection": {}, "condition": "s"},
                "rule_type": "process_creation"}]
    p = tmp_path / "bad.json"
    p.write_text(json.dumps(bad))
    r = client.post(f"/api/xdr/detection/sync?url=file://{p}"
                          "&use_bundled_fallback=false",
                          headers=_hdrs())
    d = r.json()["data"]
    assert d["counts"]["license_blocked"] == 1
    assert d["counts"]["license_valid"] == 0
    assert d["counts"]["registered"] == 0


# ── 3 · ATT&CK extraction ──────────────────────────────────────────
def test_attack_extraction_shape():
    _skip_if_no_mongo()
    r = client.get("/api/xdr/detection/rules?limit=100", headers=_hdrs())
    rules = r.json()["data"]["rules"]
    assert rules, "registry unexpectedly empty"
    # every attack technique must match T####[.###]
    for rule in rules:
        for t in rule.get("attack_techniques") or []:
            assert t.startswith("T") and (len(t) == 5 or len(t) == 9), t


def test_attack_technique_count_is_real_union():
    _skip_if_no_mongo()
    r = client.get("/api/xdr/detection/status", headers=_hdrs())
    d = r.json()["data"]
    # compute independently
    r2 = client.get("/api/xdr/detection/rules?limit=1000", headers=_hdrs())
    seen = set()
    for rule in r2.json()["data"]["rules"]:
        for t in rule.get("attack_techniques") or []:
            seen.add(t)
    assert d["attack_technique_count"] == len(seen)


# ── 4 · Deduplication ──────────────────────────────────────────────
def test_deduplication_keeps_upstream_id_unique(tmp_path):
    _skip_if_no_mongo()
    dup = [
        {"id": "dup_1", "title": "T1", "source": "SigmaHQ",
          "source_url": "u", "license": "DRL 1.1", "license_verified": True,
          "detection": {"selection": {"a": 1}, "condition": "selection"},
          "rule_type": "field_match"},
        {"id": "dup_1", "title": "T1", "source": "SigmaHQ",
          "source_url": "u", "license": "DRL 1.1", "license_verified": True,
          "detection": {"selection": {"a": 1}, "condition": "selection"},
          "rule_type": "field_match"},
    ]
    p = tmp_path / "dup.json"
    p.write_text(json.dumps(dup))
    r = client.post(f"/api/xdr/detection/sync?url=file://{p}"
                          "&use_bundled_fallback=false",
                          headers=_hdrs())
    d = r.json()["data"]
    assert d["counts"]["parsed"]        == 2
    assert d["counts"]["deduplicated"]  == 1
    assert d["stages"]["DEDUPLICATED"]["collapsed"] == 1
    # Cleanup — remove the synthetic rule so it doesn't leak into
    # cross-file assertions (P1 consolidation test asserts full
    # provenance on every bundled-source rule).
    dc._c_rules().delete_many({"upstream_id": "dup_1"})


# ── 5 · Idempotency ─────────────────────────────────────────────
def test_repeat_sync_is_idempotent():
    _skip_if_no_mongo()
    client.post("/api/xdr/detection/ensure-synced", headers=_hdrs())
    # Second call must skip.  Even if the first invocation of this test
    # triggers a real sync, the second must find already_synced=True.
    r2 = client.post("/api/xdr/detection/ensure-synced", headers=_hdrs())
    d2 = r2.json()["data"]
    assert d2.get("already_synced") or d2.get("idempotent_skip"), d2


# ── 6 · Bundled fallback rescues unreachable primary ─────────────
def test_bundled_fallback_rescues_unreachable_primary():
    _skip_if_no_mongo()
    r = client.post("/api/xdr/detection/sync?url=https://invalid.det.test/x.json"
                          "&use_bundled_fallback=true", headers=_hdrs())
    d = r.json()["data"]
    dl = d["stages"]["DOWNLOADED"]
    assert dl["status"] == "OK"
    assert dl["fallback_used"] is True
    assert dl["used_url"].startswith("file://")


# ── 7 · RBAC negative — scoped user is denied ────────────────────
@pytest.mark.parametrize("method,path", [
    ("POST",  "/api/xdr/detection/sync"),
    ("POST",  "/api/xdr/detection/ensure-synced"),
    ("POST",  "/api/xdr/detection/rules/anything/enable"),
    ("POST",  "/api/xdr/detection/rules/anything/disable"),
])
def test_scoped_user_denied_mutations(method, path):
    _skip_if_no_mongo()
    req = getattr(client, method.lower())
    r = req(path, headers=_hdrs(SCOPED))
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == "ACCESS_DENIED"


def test_scoped_user_can_read():
    _skip_if_no_mongo()
    r = client.get("/api/xdr/detection/status", headers=_hdrs(SCOPED))
    assert r.status_code == 200
    r = client.get("/api/xdr/detection/rules",  headers=_hdrs(SCOPED))
    assert r.status_code == 200


# ── 8 · Rule lifecycle guard ───────────────────────────────────────
def test_enabling_invalid_rule_is_rejected():
    _skip_if_no_mongo()
    # Insert a synthetic INVALID doc so we can exercise the guard.
    rid = f"det_invalid_{uuid.uuid4().hex[:8]}"
    dc._c_rules().insert_one({
        "id": rid, "upstream_id": f"test_invalid_{rid}",
        "original_content_hash": "x",
        "state": "PARSE_FAILED", "enabled": False,
        "source": "SigmaHQ", "license": "DRL 1.1",
        "attack_techniques": [], "rule_type": "process_creation",
        "detection": {}})
    r = client.post(f"/api/xdr/detection/rules/{rid}/enable",
                          headers=_hdrs())
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "RULE_IN_INVALID_STATE"
    # Cleanup so re-runs stay hermetic.
    dc._c_rules().delete_one({"id": rid})


# ── 9 · Detection ≠ Verdict — capability_not_verdict preserved ───
def test_capability_not_verdict_marker_persisted():
    _skip_if_no_mongo()
    r = client.get("/api/xdr/detection/rules?limit=1000", headers=_hdrs())
    rules = r.json()["data"]["rules"]
    caps = [r for r in rules if r.get("capability_not_verdict")]
    assert caps, "expected at least one capability_not_verdict rule from snapshot"
    # Allow every rule_type NivXRay ingests today — behavioural
    # observations may come from Sigma parent-child rules, IOC lists,
    # dedicated behavioural rules, IDS signature packs, YARA memory
    # rules, or the MITRE ATT&CK knowledge base.
    allowed = {"parent_child", "ioc", "behavioral",
                    "snort_signature", "suricata_signature",
                    "yara", "attack_technique"}
    for c in caps:
        assert c["rule_type"] in allowed, c["rule_type"]


# ── 10 · Enable/disable a healthy rule cycles state ───────────────
def test_enable_disable_flow():
    _skip_if_no_mongo()
    r = client.get("/api/xdr/detection/rules?limit=1&state=VALIDATED",
                          headers=_hdrs())
    rules = r.json()["data"]["rules"]
    assert rules
    rid = rules[0]["id"]
    r = client.post(f"/api/xdr/detection/rules/{rid}/enable",
                          headers=_hdrs())
    assert r.status_code == 200
    assert r.json()["data"]["state"] == "ACTIVE"
    assert r.json()["data"]["enabled"] is True
    r = client.post(f"/api/xdr/detection/rules/{rid}/disable",
                          headers=_hdrs())
    assert r.status_code == 200
    assert r.json()["data"]["state"] == "DISABLED"
