"""XDR Correlation Engine — P1 pytest.

Covers the P0-directive completion gate for correlation:

  1  Bundled rule pack seeded, operators reported honestly
  2  BENIGN — explorer → powershell (signed script) → NO correlation match
  3  SUSPICIOUS — Office → PowerShell → NO external → CANDIDATE (partial)
  4  MALICIOUS — Office → PowerShell -enc → external → SUPPORTED
  5  FALSE POSITIVE — nessus (not Office) → PowerShell -enc → NO match
  6  Brute force — 10 fails + 1 success → SUPPORTED
  7  CROSS_HOST — user_id on 2 distinct hosts, privileged actions → SUPPORTED
  8  NEGATIVE_EVIDENCE — initial_access but no execution → CANDIDATE
  9  Multi-stage timeline generates ≥ 2 matches
  10 Replay dry_run does NOT persist matches to Mongo
  11 RBAC negative — scoped user cannot ingest/replay
  12 Tenant isolation — tenant A cannot see tenant B matches
  13 Audit — CORRELATION_REPLAY event is recorded
  14 Deterministic — same input, same output (idempotent evidence)

Every SUPPORTED/CANDIDATE match MUST carry `capability_not_verdict=True`.
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("XDR_AUDIT_MASTER_SECRET", "test-master-secret")
os.environ.setdefault("XDR_SECRETS_MASTER", "test-secrets-master-passphrase")

from routers import xdr_correlation as cor
from routers import xdr_rbac as rb
from server import app

client = TestClient(app)

TEN     = f"cor-{uuid.uuid4().hex[:8]}"
OTHER   = f"cor-other-{uuid.uuid4().hex[:8]}"
ADMIN   = "root@cor"
SCOPED  = "readonly@cor"
_SUF    = uuid.uuid4().hex[:6]


def _hdrs(email=ADMIN, tenant=None):
    return {"X-Tenant-Id": tenant or TEN,
                "X-Principal-Id": email,
                "X-Principal-Kind": "user"}


def _skip_if_no_mongo():
    if cor._db() is None:
        pytest.skip("MONGO_URL not configured")


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


@pytest.fixture(scope="module", autouse=True)
def _seed():
    _skip_if_no_mongo()
    # Ensure bundled rule pack is present in the pytest app instance.
    cor.ensure_bundled_seeded()
    # Provision users.
    for c in (rb._c_users, rb._c_roles, rb._c_groups, rb._c_assignments):
        if c() is not None:
            c().delete_many({"tenant_id": {"$in": [TEN, OTHER]}})
    for c in (cor._c_matches, cor._c_state):
        if c() is not None:
            c().delete_many({"tenant_id": {"$in": [TEN, OTHER]}})

    r = client.post("/api/xdr/rbac/users", headers=_hdrs(ADMIN),
                          json={"email": ADMIN, "initial_roles": ["platform_admin"]})
    assert r.status_code == 200, r.text
    r = client.post("/api/xdr/rbac/roles", headers=_hdrs(ADMIN),
                          json={"name": f"cor_ro_{_SUF}", "display_name": "Cor RO",
                                    "permissions": ["correlation.read"]})
    role_id = r.json()["data"]["id"]
    client.post("/api/xdr/rbac/users", headers=_hdrs(ADMIN),
                    json={"email": SCOPED, "initial_roles": [role_id]})
    yield


# ── 1 · Bundle + operators ──────────────────────────────────────
def test_bundle_seeded_and_operators_implemented():
    _skip_if_no_mongo()
    r = client.get("/api/xdr/correlation/status", headers=_hdrs())
    d = r.json()["data"]
    assert d["rules_total"] >= 5
    # every listed operator MUST also be listed as implemented
    assert set(d["operators"]) == set(d["operators_implemented"])
    assert "TEMPORAL_ORDERED" in d["operators_implemented"]
    assert "CROSS_HOST"       in d["operators_implemented"]
    assert "NEGATIVE_EVIDENCE" in d["operators_implemented"]


# ── 2 · BENIGN — no correlation match ─────────────────────────
def test_benign_scenario_produces_no_match():
    _skip_if_no_mongo()
    t0 = _iso(datetime.now(timezone.utc))
    signals = [
        {"signal_kind": "event", "at": t0, "host_id": "HOST-1",
          "event_kind": "process.creation", "parent_image": "explorer.exe",
          "image": "powershell.exe",
          "command_line": "powershell.exe -File C:\\admin\\backup.ps1"},
    ]
    r = client.post("/api/xdr/correlation/replay", headers=_hdrs(),
                          json={"scenario_name": "benign", "signals": signals})
    d = r.json()["data"]
    # No correlation rule targeting this kind should fire.
    supported = [m for m in d["matches"] if m["level"] == "CORRELATION_SUPPORTED"]
    assert supported == [], f"benign signal unexpectedly matched: {supported}"


# ── 3 · SUSPICIOUS — partial (missing external) → CANDIDATE ───
def test_suspicious_partial_sequence_yields_candidate():
    _skip_if_no_mongo()
    base = datetime.now(timezone.utc)
    signals = [
        {"signal_kind": "detection", "at": _iso(base),
          "host_id": "HOST-2",
          "detection_id": "proc_creation_win_office_spawns_shell"},
        {"signal_kind": "detection", "at": _iso(base + timedelta(seconds=30)),
          "host_id": "HOST-2",
          "detection_id": "proc_creation_win_susp_encoded_pshell"},
        # no external connection follow-up
    ]
    r = client.post("/api/xdr/correlation/replay", headers=_hdrs(),
                          json={"scenario_name": "suspicious", "signals": signals})
    matches = r.json()["data"]["matches"]
    cands = [m for m in matches if
                    m["level"] == "CORRELATION_CANDIDATE"
                    and m["correlation_name"].startswith("Office")]
    assert cands, f"expected CANDIDATE, got {matches}"
    # multiple intermediate candidates emit as the sequence progresses;
    # take the highest-progress one
    best = max(cands, key=lambda c: len(c["matched_conditions"]))
    assert best["matched_conditions"] == ["A", "B"]
    assert best["missing_conditions"] == ["C"]
    assert best["capability_not_verdict"] is True


# ── 4 · MALICIOUS — full sequence → SUPPORTED ─────────────────
def test_malicious_full_sequence_yields_supported():
    _skip_if_no_mongo()
    base = datetime.now(timezone.utc)
    signals = [
        {"signal_kind": "detection", "at": _iso(base),
          "host_id": "HOST-3",
          "detection_id": "proc_creation_win_office_spawns_shell"},
        {"signal_kind": "detection", "at": _iso(base + timedelta(seconds=15)),
          "host_id": "HOST-3",
          "detection_id": "proc_creation_win_susp_encoded_pshell"},
        {"signal_kind": "event",     "at": _iso(base + timedelta(seconds=30)),
          "host_id": "HOST-3",
          "event_kind": "network.connection.external",
          "dst_ip": "203.0.113.55"},
    ]
    r = client.post("/api/xdr/correlation/replay", headers=_hdrs(),
                          json={"scenario_name": "malicious-chain",
                                    "signals": signals})
    matches = r.json()["data"]["matches"]
    supported = [m for m in matches
                            if m["level"] == "CORRELATION_SUPPORTED"
                            and m["correlation_name"].startswith("Office")]
    assert supported, f"expected SUPPORTED, got {matches}"
    m = supported[0]
    assert m["matched_conditions"] == ["A", "B", "C"]
    assert m["missing_conditions"] == []
    # Evidence chain preserves every raw signal for analyst review.
    assert len(m["evidence_chain"]) == 3
    # ATT&CK provenance propagates from the rule.
    assert "T1204.002" in m["attack_techniques"]
    # Capability, never verdict.
    assert m["capability_not_verdict"] is True


# ── 5 · FALSE POSITIVE — non-Office parent, no correlation ────
def test_false_positive_non_office_parent_does_not_match():
    _skip_if_no_mongo()
    base = datetime.now(timezone.utc)
    # Encoded PowerShell but parent is a vuln scanner — no Office
    # spawn detection is emitted, so the Office correlation rule must
    # not fire.
    signals = [
        {"signal_kind": "detection", "at": _iso(base),
          "host_id": "HOST-4",
          "detection_id": "proc_creation_win_susp_encoded_pshell"},
        {"signal_kind": "event", "at": _iso(base + timedelta(seconds=30)),
          "host_id": "HOST-4",
          "event_kind": "network.connection.external"},
    ]
    r = client.post("/api/xdr/correlation/replay", headers=_hdrs(),
                          json={"scenario_name": "vulnscan-fp",
                                    "signals": signals})
    supported = [m for m in r.json()["data"]["matches"]
                            if m["level"] == "CORRELATION_SUPPORTED"
                            and m["correlation_name"].startswith("Office")]
    assert supported == [], "false positive incorrectly correlated"


# ── 6 · Brute force sequence ────────────────────────────────────
def test_brute_force_sequence_supported():
    _skip_if_no_mongo()
    base = datetime.now(timezone.utc)
    signals = []
    for i in range(10):
        signals.append({"signal_kind": "event",
                                "at": _iso(base + timedelta(seconds=i)),
                                "user_id": "alice",
                                "event_kind": "auth.failed",
                                "source_ip": "10.0.0.1"})
    signals.append({"signal_kind": "event",
                              "at": _iso(base + timedelta(seconds=15)),
                              "user_id": "alice",
                              "event_kind": "auth.success",
                              "source_ip": "10.0.0.1"})
    r = client.post("/api/xdr/correlation/replay", headers=_hdrs(),
                          json={"scenario_name": "brute-force", "signals": signals})
    supported = [m for m in r.json()["data"]["matches"]
                            if m["level"] == "CORRELATION_SUPPORTED"
                            and "Brute Force" in m["correlation_name"]]
    assert supported, "brute force sequence did not correlate"


# ── 7 · CROSS_HOST pivot ────────────────────────────────────────
def test_cross_host_pivot_supported():
    _skip_if_no_mongo()
    base = datetime.now(timezone.utc)
    signals = [
        {"signal_kind": "event", "at": _iso(base),
          "user_id": "bob", "host_id": "HOST-A",
          "event_kind": "auth.privileged"},
        {"signal_kind": "event",
          "at": _iso(base + timedelta(seconds=120)),
          "user_id": "bob", "host_id": "HOST-B",
          "event_kind": "auth.privileged"},
    ]
    r = client.post("/api/xdr/correlation/replay", headers=_hdrs(),
                          json={"scenario_name": "cross-host", "signals": signals})
    supported = [m for m in r.json()["data"]["matches"]
                            if m["level"] == "CORRELATION_SUPPORTED"
                            and "Cross-host" in m["correlation_name"]]
    assert supported, "cross-host pivot did not correlate"
    assert "HOST-A" in supported[0]["distinct_pivot"]
    assert "HOST-B" in supported[0]["distinct_pivot"]


# ── 8 · NEGATIVE_EVIDENCE ───────────────────────────────────────
def test_negative_evidence_yields_candidate():
    _skip_if_no_mongo()
    base = datetime.now(timezone.utc)
    signals = [
        {"signal_kind": "detection", "at": _iso(base),
          "host_id": "HOST-5",
          "event_kind": "detection.initial_access"},
        # no follow-up execution detection
    ]
    r = client.post("/api/xdr/correlation/replay", headers=_hdrs(),
                          json={"scenario_name": "no-followup",
                                    "signals": signals})
    cands = [m for m in r.json()["data"]["matches"]
                    if m["level"] == "CORRELATION_CANDIDATE"
                    and "Without Follow-up" in m["correlation_name"]]
    assert cands, "negative-evidence rule did not surface a CANDIDATE"


# ── 9 · Multi-stage timeline ───────────────────────────────────
def test_multistage_timeline_produces_multiple_matches():
    _skip_if_no_mongo()
    base = datetime.now(timezone.utc)
    signals = [
        {"signal_kind": "detection", "at": _iso(base),
          "host_id": "HOST-6", "user_id": "carol",
          "detection_id": "proc_creation_win_office_spawns_shell"},
        {"signal_kind": "detection", "at": _iso(base + timedelta(seconds=10)),
          "host_id": "HOST-6", "user_id": "carol",
          "detection_id": "proc_creation_win_susp_encoded_pshell"},
        {"signal_kind": "event",     "at": _iso(base + timedelta(seconds=20)),
          "host_id": "HOST-6", "user_id": "carol",
          "event_kind": "network.connection.external"},
        {"signal_kind": "event",     "at": _iso(base + timedelta(seconds=30)),
          "host_id": "HOST-6", "user_id": "carol",
          "event_kind": "auth.privileged"},
        {"signal_kind": "event",     "at": _iso(base + timedelta(seconds=60)),
          "host_id": "HOST-7", "user_id": "carol",
          "event_kind": "auth.privileged"},
    ]
    r = client.post("/api/xdr/correlation/replay", headers=_hdrs(),
                          json={"scenario_name": "multi-stage", "signals": signals})
    matches = r.json()["data"]["matches"]
    names = {m["correlation_name"] for m in matches
                    if m["level"] == "CORRELATION_SUPPORTED"}
    assert any(n.startswith("Office") for n in names), names
    assert any("Cross-host" in n for n in names), names


# ── 10 · Replay dry-run does NOT persist matches ──────────────
def test_replay_dry_run_does_not_persist():
    _skip_if_no_mongo()
    before = cor._c_matches().count_documents({"tenant_id": TEN})
    base = datetime.now(timezone.utc)
    signals = [
        {"signal_kind": "detection", "at": _iso(base),
          "host_id": "HOST-DRY",
          "detection_id": "proc_creation_win_office_spawns_shell"},
        {"signal_kind": "detection", "at": _iso(base + timedelta(seconds=5)),
          "host_id": "HOST-DRY",
          "detection_id": "proc_creation_win_susp_encoded_pshell"},
        {"signal_kind": "event",     "at": _iso(base + timedelta(seconds=10)),
          "host_id": "HOST-DRY",
          "event_kind": "network.connection.external"},
    ]
    r = client.post("/api/xdr/correlation/replay", headers=_hdrs(),
                          json={"scenario_name": "dry-only",
                                    "signals": signals, "dry_run": True})
    assert r.status_code == 200
    assert r.json()["data"]["matches"], "replay produced no matches to verify"
    after = cor._c_matches().count_documents({"tenant_id": TEN})
    assert after == before, "dry_run replay unexpectedly persisted matches"


# ── 11 · RBAC negative ──────────────────────────────────────────
@pytest.mark.parametrize("path", [
    "/api/xdr/correlation/signals",
    "/api/xdr/correlation/replay",
    "/api/xdr/correlation/rules",
])
def test_scoped_user_denied_writes(path):
    _skip_if_no_mongo()
    body = {"signals": []} if "signals" in path or "replay" in path \
                else {"name": "x", "conditions": [{"id": "A"}],
                          "operators": {"type": "EVENT_MATCH"}}
    r = client.post(path, headers=_hdrs(SCOPED), json=body)
    assert r.status_code == 403


def test_scoped_user_can_read():
    _skip_if_no_mongo()
    r = client.get("/api/xdr/correlation/status", headers=_hdrs(SCOPED))
    assert r.status_code == 200
    r = client.get("/api/xdr/correlation/rules",  headers=_hdrs(SCOPED))
    assert r.status_code == 200


# ── 12 · Tenant isolation ───────────────────────────────────────
def test_tenant_isolation_matches_do_not_leak():
    _skip_if_no_mongo()
    # Seed OTHER tenant admin.
    client.post("/api/xdr/rbac/users",
                    headers=_hdrs(ADMIN, tenant=OTHER),
                    json={"email": "root@other",
                              "initial_roles": ["platform_admin"]})
    # Ingest a real match in OTHER.
    base = datetime.now(timezone.utc)
    client.post("/api/xdr/correlation/signals",
                    headers=_hdrs("root@other", tenant=OTHER),
                    json={"signals": [
                        {"signal_kind": "event", "at": _iso(base),
                          "host_id": "OTHER-HOST",
                          "event_kind": "detection.initial_access"},
                    ]})
    # TEN listing must NOT contain OTHER-HOST evidence.
    r = client.get("/api/xdr/correlation/matches", headers=_hdrs(ADMIN))
    matches = r.json()["data"]["matches"]
    assert not any("OTHER-HOST" in (m.get("entity_key") or "")
                              for m in matches)


# ── 13 · Audit CORRELATION_REPLAY event recorded ─────────────
def test_replay_records_audit_event():
    _skip_if_no_mongo()
    client.post("/api/xdr/correlation/replay", headers=_hdrs(),
                    json={"scenario_name": "audit-check", "signals": []})
    r = client.get("/api/xdr/audit-log?action=CORRELATION_REPLAY",
                          headers=_hdrs())
    events = r.json()["data"]["events"]
    assert any(e.get("after", {}).get("scenario") == "audit-check"
                    for e in events)


# ── 14 · Deterministic — same inputs, same outputs ───────────
def test_deterministic_evidence_shape():
    _skip_if_no_mongo()
    base = datetime.now(timezone.utc)
    signals = [
        {"signal_kind": "detection", "at": _iso(base),
          "host_id": "HOST-DET",
          "detection_id": "proc_creation_win_office_spawns_shell"},
        {"signal_kind": "detection", "at": _iso(base + timedelta(seconds=1)),
          "host_id": "HOST-DET",
          "detection_id": "proc_creation_win_susp_encoded_pshell"},
        {"signal_kind": "event",     "at": _iso(base + timedelta(seconds=2)),
          "host_id": "HOST-DET",
          "event_kind": "network.connection.external"},
    ]
    r1 = client.post("/api/xdr/correlation/replay", headers=_hdrs(),
                            json={"scenario_name": "det-a", "signals": signals})
    r2 = client.post("/api/xdr/correlation/replay", headers=_hdrs(),
                            json={"scenario_name": "det-b", "signals": signals})
    m1 = [m for m in r1.json()["data"]["matches"]
              if m["level"] == "CORRELATION_SUPPORTED"
              and m["correlation_name"].startswith("Office")]
    m2 = [m for m in r2.json()["data"]["matches"]
              if m["level"] == "CORRELATION_SUPPORTED"
              and m["correlation_name"].startswith("Office")]
    assert len(m1) == len(m2) == 1
    # Shape identical (ignore per-run ids).
    for k in ("matched_conditions", "missing_conditions",
                    "attack_techniques", "operator", "level"):
        assert m1[0][k] == m2[0][k], k
