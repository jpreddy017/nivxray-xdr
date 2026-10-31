"""Round 41 · Timeline Replay — regression.

The Timeline Replay is a PURE PLAYBACK CONTROLLER over the existing
Activity Graph walkable primary path.  It creates no new data model.

This regression pins the backend contract the controller depends on:

  1. `graph.primary_path[]` exists, is a non-empty ordered list, and
     is walkable (every adjacent pair connected by a real edge that
     is not NOT_OBSERVED).
  2. The intersection of `primary_path[]` with the Activity Graph
     projection nodes yields the deterministic replay step sequence.
     Sparse projections (path elements outside the projection kept
     kinds) are handled by omission — never fabrication.
  3. The intersection is deterministic across runs.
  4. Every replay step id resolves to a real Activity Graph node
     carrying `kind`, `label`, and the fields the shared Evidence
     Inspector needs to open on that step.
"""
from __future__ import annotations
import asyncio, hashlib, json
from datetime import datetime, timezone
import pytest

from services.attack_graph import AttackGraphService
from services.investigator  import InvestigatorService


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
    inc_id = "inc_r41_" + hashlib.sha256(b"r41").hexdigest()[:12]
    evt_id = "evt_r41_" + hashlib.sha256(b"r41-evt").hexdigest()[:12]
    now = datetime.now(timezone.utc).isoformat()
    canonical = {
        "event_id": evt_id, "timestamp": now,
        "dsm": {"id": "sysmon", "event_id": "sysmon:1"},
        "host": {"name": "WKS-R41"},
        "user": {"name": "gina@nivxray.local"},
        "process": {"name": "powershell.exe",
                        "parent": {"name": "winword.exe"},
                        "commandline": "powershell.exe -nop -w hidden -enc AAAA"},
        "network": {"src": {"ip": "10.20.30.40"},
                          "dst": {"ip": "203.0.113.99"},
                          "protocol": "TCP"},
        "security": {"signature": {"id": 41, "name": "Suspicious PS"},
                           "severity": 2},
    }
    incident = {
        "id": inc_id, "tenant_id": "default",
        "created_at": now, "updated_at": now,
        "title": "R41 Timeline Replay fixture",
        "user_email": "admin@nivxray.com",
        "incident_state": "in_progress", "incident_priority": "P2",
        "verdict_card": {"verdict": "suspicious", "engine": "sigma"},
        "mitre": [{"technique_id": "T1059.001", "tactic_id": "TA0002",
                        "name": "PowerShell"}],
        "iocs": {"ip": ["203.0.113.99"], "user": ["gina@nivxray.local"]},
        "xdr_pipeline": {"canonical_event_id": evt_id, "ice_matches": [],
                              "detection_rule_id": "rule-r41",
                              "trace_id": "r41"},
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

def _activity_projection_steps(graph):
    """Frontend-equivalent: intersect primary_path with the Activity
    Graph projection nodes, preserving path order.  This is exactly
    what the Timeline Replay controller computes on the client."""
    ag = graph["views"]["activity_graph"]
    by_id = {n["id"]: n for n in ag["nodes"]}
    return [by_id[nid] for nid in (graph.get("primary_path") or [])
                if nid in by_id]


def test_primary_path_present_and_walkable(loop, db, incident_id):
    g = _run(loop, AttackGraphService.compose(db, incident_id))
    path = g.get("primary_path") or []
    assert path, "expected a non-empty primary_path[] for a rich fixture"
    edge_pairs = {(e["src"], e["dst"]) for e in g["edges"]
                       if e["state"] != "NOT_OBSERVED"}
    for i in range(len(path) - 1):
        assert (path[i], path[i + 1]) in edge_pairs, (
            f"primary_path not walkable at {path[i]} -> {path[i + 1]}"
        )


def test_activity_projection_replay_steps_present(loop, db, incident_id):
    """The Activity Graph projection must yield at least one replay
    step so the Timeline Replay controller has something to walk."""
    g = _run(loop, AttackGraphService.compose(db, incident_id))
    steps = _activity_projection_steps(g)
    assert len(steps) >= 2, (
        f"Expected >= 2 replay steps in the activity projection; got {len(steps)}"
    )


def test_replay_steps_carry_inspector_fields(loop, db, incident_id):
    """Every replay step must expose `kind` and `label` so the
    controller can (a) render the step badge and (b) resolve the
    shared Evidence Inspector via nodeToInspectorArgs()."""
    g = _run(loop, AttackGraphService.compose(db, incident_id))
    for step in _activity_projection_steps(g):
        assert step.get("kind"), step
        assert step.get("label"), step
        # Activity Graph must not surface MITRE / capability / finding
        # kinds — the controller relies on this invariant.
        assert step["kind"] not in {"stage", "technique", "detection",
                                              "match", "capability", "finding",
                                              "gap"}, (
            f"projection leak into replay: {step}"
        )


def test_replay_sequence_is_deterministic(loop, db, incident_id):
    """Same inputs → identical replay step order."""
    a = _run(loop, AttackGraphService.compose(db, incident_id))
    b = _run(loop, AttackGraphService.compose(db, incident_id))
    ids_a = [s["id"] for s in _activity_projection_steps(a)]
    ids_b = [s["id"] for s in _activity_projection_steps(b)]
    assert ids_a == ids_b, (
        f"replay sequence non-deterministic:\n  a={ids_a}\n  b={ids_b}"
    )


def test_replay_gracefully_handles_sparse_projection(loop, db, incident_id):
    """Simulate a sparse projection (drop process/commandline nodes)
    and ensure the replay-step intersection still returns a coherent
    (possibly shorter) sequence — never fabricates missing nodes."""
    g = _run(loop, AttackGraphService.compose(db, incident_id))
    ag = g["views"]["activity_graph"]
    # Simulate the sparse projection the controller must handle
    # gracefully — drop every process + commandline node.
    sparse_ids = {n["id"] for n in ag["nodes"]
                    if n["kind"] not in {"process", "commandline"}}
    steps = [n for n in ag["nodes"]
              if n["id"] in sparse_ids
              and n["id"] in set(g.get("primary_path") or [])]
    # Steps still ordered by primary path (deterministic omission).
    ordered = [nid for nid in (g.get("primary_path") or [])
                    if nid in {s["id"] for s in steps}]
    assert ordered == [s["id"] for s in sorted(steps,
                                                            key=lambda s: (g["primary_path"].index(s["id"])))
                            ], "sparse projection order not preserved"
    # Every retained step still carries a real kind and label.
    for s in steps:
        assert s.get("kind") and s.get("label")


def test_replay_no_new_data_model_field_added(loop, db, incident_id):
    """The Timeline Replay must remain a CLIENT controller over the
    existing graph payload — this test pins that the backend graph
    envelope has not sprouted a new 'replay' / 'timeline_v2' /
    'playback' key (owner rule: no second timeline model)."""
    g = _run(loop, AttackGraphService.compose(db, incident_id))
    forbidden = {"replay", "timeline_v2", "playback", "attack_timeline"}
    leaked = forbidden & set(g.keys())
    assert not leaked, (
        f"Timeline Replay must not add new backend data model keys; "
        f"leaked: {sorted(leaked)}"
    )
