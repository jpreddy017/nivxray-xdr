"""XDR Rule Studio (Step 1 + Step 2) — pytest.

Covers:
  * Nine-lane taxonomy surfaced by /lanes endpoint
  * Every rule persisted in the unified store has architectural stamps
        emits='OBSERVATION', emits_verdict=False, capability_not_verdict=True
  * Lifecycle transitions honour the authorised transition table
  * ACTIVE transition is IMPOSSIBLE unless every gate check PASSes
  * Regression gate is deterministic; SKIP counts do NOT satisfy the gate
  * Correlation rules are surfaced with lane='correlation'
  * No synthetic rules are injected — the store size does NOT grow at boot
    unless real content or correlation rules exist
  * RBAC — mutations refused for read-only principals
"""
from __future__ import annotations

import os
import uuid

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("XDR_AUDIT_MASTER_SECRET", "test-master-secret")
os.environ.setdefault("XDR_SECRETS_MASTER", "test-secrets-master-passphrase")

from routers import xdr_rule_studio as rs
from routers import xdr_rbac as rb
from server import app

client = TestClient(app)

TEN   = f"rs-{uuid.uuid4().hex[:8]}"
ADMIN = "root@rs"


def _hdrs(email=ADMIN, tenant=None):
    return {"X-Tenant-Id": tenant or TEN,
                "X-Principal-Id": email,
                "X-Principal-Kind": "user"}


def _skip():
    if rs._db() is None:
        pytest.skip("MONGO_URL not configured")


@pytest.fixture(scope="module", autouse=True)
def _seed():
    _skip()
    for c in (rb._c_users, rb._c_roles, rb._c_groups, rb._c_assignments):
        if c() is not None:
            c().delete_many({"tenant_id": TEN})
    # Studio uses the shared tenant-less xdr_detection_rules store — only
    # clean our tenant-scoped studio-authored rows.
    rs._c_rules().delete_many({"tenant_id": TEN})
    client.post("/api/xdr/rbac/users", headers=_hdrs(),
                     json={"email": ADMIN, "initial_roles": ["platform_admin"]})
    rs.ensure_studio_ready()
    yield


def test_status_exposes_taxonomy():
    _skip()
    r = client.get("/api/xdr/rule-studio/status", headers=_hdrs())
    assert r.status_code == 200
    d = r.json()["data"]
    assert d["lanes"] == rs.LANES
    assert d["lifecycle_states"] == rs.LIFECYCLE_STATES
    assert d["gate_checks"] == rs.GATE_CHECKS
    assert len(d["gate_checks"]) == 11, "owner-locked 11-check gate"
    assert "OBSERVATION" in d["semantic_contract"]
    assert d["verdict_owned_by"] == "Verdict Engine"


def test_nine_lanes_are_locked():
    _skip()
    r = client.get("/api/xdr/rule-studio/lanes", headers=_hdrs())
    lanes = [l["key"] for l in r.json()["data"]["lanes"]]
    assert set(lanes) == set(rs.LANES) == {
        "event", "endpoint", "ioc", "network", "dns_proxy",
        "cve_exposure", "correlation", "behavior", "content",
    }


def test_create_rule_stamps_semantic_invariants():
    _skip()
    r = client.post("/api/xdr/rule-studio/rules", headers=_hdrs(),
                          json={"lane": "endpoint",
                                    "title": "Rundll32 with remote payload",
                                    "description": "LOLBIN capability observation",
                                    "logsource": {"category": "process_creation",
                                                          "product": "windows"},
                                    "detection": {"selection": {"Image|endswith":
                                                                      "\\rundll32.exe"},
                                                          "condition": "selection"},
                                    "attack_techniques": ["T1218.011"]})
    assert r.status_code == 200, r.text
    d = r.json()["data"]
    # Architectural stamps — NON-NEGOTIABLE
    assert d["emits"]                  == "OBSERVATION"
    assert d["emits_verdict"]          is False
    assert d["verdict_capable"]        is False
    assert d["capability_not_verdict"] is True
    assert d["lane"]                   == "endpoint"
    assert d["lifecycle_state"]        == "DRAFT"
    assert d["gate_state"]["pass"]     is False
    # Lifecycle history recorded
    assert d["lifecycle_history"][0]["to"] == "DRAFT"
    return d["id"]


def test_lifecycle_transition_table_enforced():
    _skip()
    r = client.post("/api/xdr/rule-studio/rules", headers=_hdrs(),
                          json={"lane": "content", "title": "lifecycle test",
                                    "detection": {"selection": {"x": 1},
                                                          "condition": "selection"}})
    rid = r.json()["data"]["id"]
    # DRAFT → ACTIVE is NOT in the transition table
    r = client.post(f"/api/xdr/rule-studio/rules/{rid}/transition",
                          headers=_hdrs(), json={"to": "ACTIVE"})
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "LIFECYCLE_TRANSITION_REFUSED"
    # DRAFT → TESTING is allowed
    r = client.post(f"/api/xdr/rule-studio/rules/{rid}/transition",
                          headers=_hdrs(), json={"to": "TESTING"})
    assert r.status_code == 200
    # TESTING → VALIDATED → ENABLED → ACTIVE …
    r = client.post(f"/api/xdr/rule-studio/rules/{rid}/transition",
                          headers=_hdrs(), json={"to": "VALIDATED"})
    assert r.status_code == 200
    r = client.post(f"/api/xdr/rule-studio/rules/{rid}/transition",
                          headers=_hdrs(), json={"to": "ENABLED"})
    assert r.status_code == 200
    # …but ACTIVE demands the gate
    r = client.post(f"/api/xdr/rule-studio/rules/{rid}/transition",
                          headers=_hdrs(), json={"to": "ACTIVE"})
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "REGRESSION_GATE_FAILED"


def test_active_promotion_refused_when_gate_fails():
    """The critical architectural invariant."""
    _skip()
    r = client.post("/api/xdr/rule-studio/rules", headers=_hdrs(),
                          json={"lane": "endpoint",
                                    "title": "gate refusal candidate",
                                    "detection": {"selection": {"Image": "x"},
                                                          "condition": "selection"}})
    rid = r.json()["data"]["id"]
    # Walk to ENABLED then attempt ACTIVE
    for target in ("TESTING", "VALIDATED", "ENABLED"):
        assert client.post(f"/api/xdr/rule-studio/rules/{rid}/transition",
                                    headers=_hdrs(),
                                    json={"to": target}).status_code == 200
    r = client.post(f"/api/xdr/rule-studio/rules/{rid}/promote",
                          headers=_hdrs())
    assert r.status_code == 409
    detail = r.json()["detail"]
    assert detail["code"] == "REGRESSION_GATE_FAILED"
    gate = detail["gate"]
    # Every failed check has a deterministic reason
    for name, check in gate["checks"].items():
        assert "status" in check and "reason" in check
    # Gate has NEVER passed for a fresh rule
    assert gate["pass"] is False
    # And SKIPs (missing tests) do NOT count as PASS
    failed = [n for n, c in gate["checks"].items() if c["status"] != "PASS"]
    assert failed, "expected at least one non-PASS check"


def test_dry_run_gate_never_transitions_state():
    _skip()
    r = client.post("/api/xdr/rule-studio/rules", headers=_hdrs(),
                          json={"lane": "content", "title": "dry-run test",
                                    "detection": {"selection": {"x": 1},
                                                          "condition": "selection"}})
    rid = r.json()["data"]["id"]
    r = client.post(f"/api/xdr/rule-studio/rules/{rid}/gate",
                          headers=_hdrs())
    assert r.status_code == 200
    # State is still DRAFT
    r = client.get("/api/xdr/rule-studio/rules",
                              headers=_hdrs(),
                              params={"q": "dry-run test"})
    rows = [x for x in r.json()["data"]["rules"] if x["id"] == rid]
    assert rows and rows[0]["lifecycle_state"] == "DRAFT"


def test_existing_content_stays_in_place_no_synthetic_inflation():
    """Rule Studio MUST NOT synthetically create rules.  The total
    rule count belongs to the content pipeline + explicit studio
    authoring only."""
    _skip()
    before = rs._c_rules().count_documents({})
    rs.ensure_studio_ready()   # idempotent
    after  = rs._c_rules().count_documents({})
    assert after == before, "backfill must be metadata-only, never a row insert"


def test_read_only_principal_denied_on_mutations():
    _skip()
    scoped = f"ro-{uuid.uuid4().hex[:6]}@x"
    r = client.post("/api/xdr/rbac/roles", headers=_hdrs(),
                          json={"name": f"studio_ro_{uuid.uuid4().hex[:6]}",
                                    "display_name": "studio ro",
                                    "permissions": ["detections.read"]})
    role_id = r.json()["data"]["id"]
    client.post("/api/xdr/rbac/users", headers=_hdrs(),
                     json={"email": scoped, "initial_roles": [role_id]})
    for path in ("/api/xdr/rule-studio/rules",
                        "/api/xdr/rule-studio/rules/x/transition",
                        "/api/xdr/rule-studio/rules/x/promote"):
        r = client.post(path, headers=_hdrs(scoped),
                                json={"lane": "content", "title": "x", "to": "TESTING"})
        assert r.status_code == 403, path
    # Read paths still work
    r = client.get("/api/xdr/rule-studio/status", headers=_hdrs(scoped))
    assert r.status_code == 200


def test_correlation_rules_surface_in_unified_store_when_present():
    _skip()
    # Insert a correlation rule the "old" way then re-adopt.
    if rs._c_corr_rules() is None:
        pytest.skip("correlation rules collection not available")
    cid = f"cor_{uuid.uuid4().hex[:8]}"
    rs._c_corr_rules().insert_one({"id": cid, "name": "cross-source test",
                                                          "enabled": False,
                                                          "expression": {"op": "sequence",
                                                                                  "steps": []},
                                                          "attack_techniques": ["T1059.001"]})
    try:
        rs._adopt_correlation_rules()
        row = rs._c_rules().find_one({"upstream_id": cid})
        assert row is not None
        assert row["lane"] == "correlation"
        assert row["emits"] == "OBSERVATION"
        assert row["capability_not_verdict"] is True
        # Re-run — idempotent
        counts = rs._adopt_correlation_rules()
        assert counts["adopted"] == 0
    finally:
        rs._c_corr_rules().delete_one({"id": cid})
        rs._c_rules().delete_one({"upstream_id": cid})
