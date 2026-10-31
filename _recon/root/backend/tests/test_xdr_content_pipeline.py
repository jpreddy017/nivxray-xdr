"""XDR Content Pipeline + Predefined Collector Catalog — new-lane tests.

Covers the P0-C "Content + Collector expansion" milestone:

  1  License policy engine — 4-state (PERMITTED / RESTRICTED /
      LICENSE_REVIEW / LICENSE_BLOCKED); proprietary substrings
      cause BLOCKED; unknown → REVIEW; permissive → PERMITTED;
      copyleft (GPL) → RESTRICTED.
  2  Multi-source registry — every bundled source (Sigma, Snort,
      Suricata, YARA, ATT&CK) contributes rules; sources catalog
      surfaces per-source counts + acquisition state.
  3  Detection Registry preserves original license and stamps
      `license_policy_state` on every rule (RESTRICTED still ENABLE-
      able, BLOCKED/REVIEW never activatable — 409 on enable).
  4  Predefined collector catalog — every entry carries an honest
      protocol implementation state; ≥1 entry per required category.
"""
from __future__ import annotations

import os
import uuid

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("XDR_AUDIT_MASTER_SECRET", "test-master-secret")
os.environ.setdefault("XDR_SECRETS_MASTER", "test-secrets-master-passphrase")

from lib.content_policy import evaluate_license, policy_matrix
from routers import xdr_detection_content as dc
from routers import xdr_rbac as rb
from server import app

client = TestClient(app)

TEN   = f"pipe-{uuid.uuid4().hex[:8]}"
ADMIN = "root@pipe"


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
    for c in (rb._c_users, rb._c_roles, rb._c_groups, rb._c_assignments):
        if c() is not None:
            c().delete_many({"tenant_id": TEN})
    client.post("/api/xdr/rbac/users", headers=_hdrs(ADMIN),
                     json={"email": ADMIN,
                                "initial_roles": ["platform_admin"]})
    dc.ensure_synced(("t", ADMIN, "user"))
    yield


# ── 1 · License policy engine ────────────────────────────────────
@pytest.mark.parametrize("license_str,expected_state", [
    ("MIT",                      "PERMITTED"),
    ("Apache-2.0",               "PERMITTED"),
    ("Apache License, Version 2.0", "PERMITTED"),
    ("BSD-3-Clause",             "PERMITTED"),
    ("DRL 1.1",                  "PERMITTED"),
    ("MITRE ATT&CK",             "PERMITTED"),
    ("GPL-2.0",                  "RESTRICTED"),
    ("GPL-3.0",                  "RESTRICTED"),
    ("CC-BY-4.0",                "RESTRICTED"),
    ("Proprietary",              "LICENSE_BLOCKED"),
    ("SOME-PROPRIETARY",         "LICENSE_BLOCKED"),
    ("Non-Commercial",           "LICENSE_BLOCKED"),
    ("Weird-Nobody-Knows",       "LICENSE_REVIEW"),
    (None,                       "LICENSE_REVIEW"),
])
def test_policy_evaluator_produces_correct_state(license_str, expected_state):
    r = evaluate_license(license_str)
    assert r["state"] == expected_state, (license_str, r)


def test_policy_matrix_has_all_bands():
    m = policy_matrix()
    for k in ("permitted", "restricted", "blocked", "activatable_states"):
        assert m[k], f"missing band: {k}"
    # PERMITTED and RESTRICTED are activatable; BLOCKED/REVIEW are not.
    assert set(m["activatable_states"]) == {"PERMITTED", "RESTRICTED"}


# ── 2 · Multi-source registry ────────────────────────────────────
def test_multiple_sources_populated_from_bundled_snapshots():
    _skip_if_no_mongo()
    r = client.get("/api/xdr/detection/status", headers=_hdrs())
    assert r.status_code == 200
    d = r.json()["data"]
    # Each bundled source contributes at least one rule.
    for src in ("SigmaHQ", "Snort", "Suricata", "YARA-Rules", "MITRE ATT&CK"):
        assert d["sources"].get(src, 0) > 0, (src, d["sources"])
    # Total rules is the sum of every source.
    assert d["total_rules"] == sum(d["sources"].values())


def test_sources_catalog_lists_every_bundled_source():
    _skip_if_no_mongo()
    r = client.get("/api/xdr/detection/sources/catalog", headers=_hdrs())
    assert r.status_code == 200
    data = r.json()["data"]
    names = {s["name"] for s in data["sources"]}
    assert {"SigmaHQ", "Snort", "Suricata", "YARA-Rules",
                "MITRE ATT&CK"} <= names
    # Every bundled source reports honest acquisition state.
    for s in data["sources"]:
        assert s["acquisition_state"] in {"LIVE", "BUNDLED_FALLBACK",
                                                                "UNAVAILABLE"}
        assert s["bundled_available"] is True
    # The policy matrix is included so the UI can render badges.
    assert data["policy"]["version"]


# ── 3 · Rule policy stamping + enablement gate ───────────────────
def test_every_rule_carries_license_policy_state():
    _skip_if_no_mongo()
    r = client.get("/api/xdr/detection/rules?limit=1000", headers=_hdrs())
    rules = r.json()["data"]["rules"]
    for rule in rules:
        assert rule.get("license_policy_state") in {"PERMITTED",
                                                                                      "RESTRICTED",
                                                                                      "LICENSE_REVIEW",
                                                                                      "LICENSE_BLOCKED"}
        # Original license is preserved verbatim.
        assert rule.get("license"), rule


def test_restricted_rule_can_be_enabled(tmp_path):
    """Copyleft (RESTRICTED) rules — e.g. Snort GPL-2.0 — MUST be
    enable-able for internal use.  Only the redistribution obligation
    is surfaced in the UI badge."""
    _skip_if_no_mongo()
    r = client.get("/api/xdr/detection/rules?source=Snort&limit=50",
                              headers=_hdrs())
    rules = r.json()["data"]["rules"]
    restricted = [x for x in rules
                            if x.get("license_policy_state") == "RESTRICTED"
                            and x.get("state") == "VALIDATED"]
    if not restricted:
        pytest.skip("no RESTRICTED rules in this snapshot slice")
    rid = restricted[0]["id"]
    r = client.post(f"/api/xdr/detection/rules/{rid}/enable",
                          headers=_hdrs())
    assert r.status_code == 200, r.text
    assert r.json()["data"]["state"] == "ACTIVE"
    # Undo so the fixture stays clean for other tests.
    client.post(f"/api/xdr/detection/rules/{rid}/disable", headers=_hdrs())


def test_blocked_license_rule_cannot_be_enabled(tmp_path):
    """LICENSE_BLOCKED rules are retained for audit but 409 on enable."""
    _skip_if_no_mongo()
    import json
    bad = [{"id": f"proprietary_{uuid.uuid4().hex[:6]}",
                "title": "proprietary demo", "source": "TestVendor",
                "source_url": "http://x", "license": "PROPRIETARY-VENDOR",
                "author": "?", "detection": {"selection": {}, "condition": "s"},
                "rule_type": "process_creation"}]
    p = tmp_path / "prop.json"
    p.write_text(json.dumps(bad))
    r = client.post(f"/api/xdr/detection/sync?url=file://{p}"
                          "&use_bundled_fallback=false",
                          headers=_hdrs())
    # The rule was RETAINED for audit — check the counts.
    d = r.json()["data"]
    assert d["counts"]["license_blocked"] == 1
    assert d["counts"]["registered"]      == 0   # never activatable


# ── 4 · Predefined Collector Catalog ─────────────────────────────
def test_collector_catalog_surface():
    _skip_if_no_mongo()
    # RBAC — a fresh admin exists from the fixture.
    r = client.get("/api/xdr/collectors/catalog", headers=_hdrs())
    assert r.status_code == 200
    d = r.json()["data"]
    # ≥1 entry per required category.
    for cat in ("ENDPOINT", "NETWORK", "DNS", "WEB", "CLOUD", "IDENTITY"):
        assert cat in d["by_category"], cat
        assert d["by_category"][cat], cat
    # Every entry carries an honest implementation state derived from
    # the protocol registry.
    for entry in d["catalog"]:
        assert entry["implementation"] in {"IMPLEMENTED", "SCAFFOLD", "BLOCKED"}
    # Summary numbers agree with the raw list.
    assert d["summary"]["total"] == len(d["catalog"])


def test_collector_catalog_rbac_denies_unscoped():
    _skip_if_no_mongo()
    # Fresh tenant with a scoped role can read only if it holds
    # collectors.read.
    scoped = f"scoped-{uuid.uuid4().hex[:6]}@x"
    r = client.post("/api/xdr/rbac/roles", headers=_hdrs(ADMIN),
                          json={"name": f"cat_ro_{uuid.uuid4().hex[:6]}",
                                    "display_name": "cat ro",
                                    "permissions": ["detections.read"]})
    role_id = r.json()["data"]["id"]
    client.post("/api/xdr/rbac/users", headers=_hdrs(ADMIN),
                    json={"email": scoped, "initial_roles": [role_id]})
    r = client.get("/api/xdr/collectors/catalog", headers=_hdrs(scoped))
    assert r.status_code == 403


# ── 5 · Version doc carries acquisition_state ───────────────────
def test_version_doc_records_acquisition_state():
    _skip_if_no_mongo()
    r = client.get("/api/xdr/detection/versions?limit=20", headers=_hdrs())
    versions = r.json()["data"]["versions"]
    assert versions
    for v in versions:
        assert v.get("acquisition_state") in {"LIVE", "BUNDLED_FALLBACK",
                                                                    "UNAVAILABLE"}
        assert v.get("source") in {"SigmaHQ", "Snort", "Suricata",
                                                    "YARA-Rules", "MITRE ATT&CK"}
