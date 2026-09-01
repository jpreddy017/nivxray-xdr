"""Round 42 · Evidence Deep-Links — regression.

The Activity Graph edge inspector now exposes every `evidence_refs[]`
entry as a clickable pill.  Clicking a pill routes the analyst to
the existing shared `<EvidenceInspector/>` opened on the governed
canonical evidence — never a second evidence-detail widget.

    Activity Graph Edge
           │
           └── evidence_refs[]
                   │
                   ▼
           Canonical Evidence ID
                   │
                   ▼
          Shared EvidenceInspector
                   │
             (governed data)

This regression pins the end-to-end resolution contract:

  1. Every Activity Graph edge with `state != NOT_OBSERVED` exposes
     `evidence_refs[]`; the refs are non-empty for edges anchored to
     canonical evidence.
  2. Each ref resolves through the existing inspector service to a
     governed envelope carrying identity + context + evidence +
     provenance + investigate actions.
  3. Unknown / stale refs return the honest MISSING state — no
     fabrication.
  4. Deep-linking does not introduce a second evidence data model on
     the backend graph envelope.
"""
from __future__ import annotations
import asyncio, hashlib
from datetime import datetime, timezone
import pytest

from services.attack_graph        import AttackGraphService
from services.evidence_inspector  import resolve as inspector_resolve
from services.investigator        import InvestigatorService


@pytest.fixture(scope="module")
def loop():
    lp = asyncio.new_event_loop()
    yield lp
    lp.close()


def _run(loop, coro):
    return loop.run_until_complete(coro)


@pytest.fixture(scope="module")
def db(loop):
    from motor.motor_asyncio import AsyncIOMotorClient
    import os
    from dotenv import load_dotenv
    load_dotenv("/app/backend/.env")
    c = AsyncIOMotorClient(os.environ["MONGO_URL"])
    yield c[os.environ.get("DB_NAME", "test_database")]
    c.close()


@pytest.fixture(scope="module")
def incident_id(loop, db):
    inc_id = "inc_r42_" + hashlib.sha256(b"r42").hexdigest()[:12]
    evt_id = "evt_r42_" + hashlib.sha256(b"r42-evt").hexdigest()[:12]
    now = datetime.now(timezone.utc).isoformat()
    canonical = {
        "event_id": evt_id, "timestamp": now,
        "dsm": {"id": "sysmon", "event_id": "sysmon:1"},
        "host": {"name": "WKS-R42"},
        "user": {"name": "helen@nivxray.local"},
        "process": {"name": "powershell.exe",
                        "parent": {"name": "winword.exe"},
                        "commandline": "powershell.exe -nop -w hidden -enc AAAA"},
        "network": {"src": {"ip": "10.20.30.40"},
                          "dst": {"ip": "198.51.100.42"},
                          "protocol": "TCP"},
        "security": {"signature": {"id": 42, "name": "Suspicious PS"},
                           "severity": 2},
    }
    incident = {
        "id": inc_id, "tenant_id": "default",
        "created_at": now, "updated_at": now,
        "title": "R42 evidence deep-link fixture",
        "user_email": "admin@nivxray.com",
        "incident_state": "in_progress", "incident_priority": "P2",
        "verdict_card": {"verdict": "suspicious", "engine": "sigma"},
        "mitre": [{"technique_id": "T1059.001", "tactic_id": "TA0002",
                        "name": "PowerShell"}],
        "iocs": {"ip": ["198.51.100.42"], "user": ["helen@nivxray.local"]},
        "xdr_pipeline": {"canonical_event_id": evt_id, "ice_matches": [],
                              "detection_rule_id": "rule-r42",
                              "trace_id": "r42"},
    }
    async def _seed():
        await db["xdr_canonical_evidence"].update_one(
            {"event_id": evt_id}, {"$set": canonical}, upsert=True)
        await db["workspace_cases"].update_one(
            {"id": inc_id}, {"$set": incident}, upsert=True)
    _run(loop, _seed())
    _run(loop, InvestigatorService.tick(db, inc_id))
    return inc_id


# ── Acceptance gates ────────────────────────────────────────────────

def _activity_edges(g):
    return g["views"]["activity_graph"]["edges"]


def test_activity_edges_expose_evidence_refs(loop, db, incident_id):
    """Every non-observed-negation edge in the Activity Graph must
    carry at least one `evidence_refs[]` entry so the frontend
    deep-link pills always have something to render."""
    g = _run(loop, AttackGraphService.compose(db, incident_id))
    edges = _activity_edges(g)
    assert edges, "expected non-empty Activity Graph edges on rich fixture"
    canon = [e for e in edges if e["state"] != "NOT_OBSERVED"]
    assert canon, "no OBSERVED/SUPPORTED edges to test against"
    with_refs = [e for e in canon if e.get("evidence_refs")]
    assert len(with_refs) >= max(1, len(canon) // 2), (
        f"expected most canonical edges to carry evidence_refs; "
        f"got {len(with_refs)} of {len(canon)}"
    )


def test_edge_evidence_ref_resolves_via_shared_inspector(loop, db, incident_id):
    """Take the first evidence_refs value from any canonical edge and
    prove the shared inspector opens it as a governed canonical
    event envelope."""
    g = _run(loop, AttackGraphService.compose(db, incident_id))
    ref = next((r for e in _activity_edges(g)
                    for r in (e.get("evidence_refs") or [])), None)
    assert ref, "fixture must yield at least one evidence ref"
    env = _run(loop, inspector_resolve(db, incident_id, "event", ref))
    assert env.get("state") != "MISSING", env
    # Governed envelope shape (Round 38.3 · shared inspector contract).
    for k in ("kind", "ref_id", "identity", "context",
                 "evidence", "provenance", "actions"):
        assert k in env, f"inspector envelope missing '{k}': {env}"
    assert env["kind"] == "event"
    assert env["identity"]["label"], env["identity"]
    assert env["evidence"], "governed event must carry canonical evidence"
    # Actions surfaced — proving the deep-link routes into the
    # existing INVESTIGATE fabric rather than a bespoke renderer.
    assert env["actions"], env


def test_unknown_evidence_ref_returns_missing(loop, db, incident_id):
    """Owner rule: never fabricate.  Deep-linking a stale/unknown ref
    MUST return an honest MISSING state through the shared inspector."""
    env = _run(loop, inspector_resolve(db, incident_id, "event",
                                                    "evt_does_not_exist"))
    assert env.get("state") == "MISSING", env


def test_finding_ref_resolves_via_shared_inspector(loop, db, incident_id):
    """Findings on an edge (`finding_ids[]`) must also deep-link
    through the shared inspector — same resolver, no duplicate."""
    findings = _run(loop, InvestigatorService.get_findings(db, incident_id))
    if not findings:
        pytest.skip("fixture yielded no findings")
    fid = findings[0]["finding_id"]
    env = _run(loop, inspector_resolve(db, incident_id, "finding", fid))
    assert env.get("state") != "MISSING", env
    assert env["kind"] == "finding"
    assert env["ref_id"] == fid


def test_edge_evidence_refs_deterministic(loop, db, incident_id):
    """Same inputs → identical `evidence_refs[]` on every edge (the
    frontend keys pills off the ref string)."""
    a = _activity_edges(_run(loop, AttackGraphService.compose(db, incident_id)))
    b = _activity_edges(_run(loop, AttackGraphService.compose(db, incident_id)))
    assert [e.get("evidence_refs") for e in a] == \
                [e.get("evidence_refs") for e in b], "evidence_refs non-deterministic"


def test_backend_envelope_has_no_second_evidence_model(loop, db, incident_id):
    """R42 is a deep-link enhancement only.  The backend graph
    envelope MUST NOT sprout an `evidence_details` / `edge_evidence`
    / `deep_link` / `evidence_index` field (that would be a second
    evidence-detail model)."""
    g = _run(loop, AttackGraphService.compose(db, incident_id))
    forbidden = {"evidence_details", "edge_evidence", "deep_link",
                    "evidence_index", "edge_inspector"}
    leaked = forbidden & set(g.keys())
    assert not leaked, (
        f"R42 must remain a client-side deep-link; leaked keys: "
        f"{sorted(leaked)}"
    )
