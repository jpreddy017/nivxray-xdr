"""Round 39 · Step 4 · Attack Graph Cleanup regression.

Acceptance gates (explicit user requirements):

  1. Activity Graph MUST expose finding *annotations* on parent
     entity nodes (not as separate finding boxes).
  2. Capability nodes MUST NOT appear on the Activity Graph canvas.
  3. Process Tree remains inside Attack Graph.
  4. Every kept Activity Graph node carries an `annotations.findings`
     list (possibly empty) — never None / undefined.
  5. Event nodes expose `attrs.event_id` so the frontend can resolve
     the shared Evidence Inspector.
  6. Finding nodes expose `attrs.finding_id` so the frontend can
     resolve the shared Evidence Inspector.
  7. Determinism: same inputs → identical projection output.
"""
from __future__ import annotations
import asyncio, hashlib, json
import pytest
from datetime import datetime, timezone

from services.attack_graph      import AttackGraphService
from services.investigator      import InvestigatorService
from services.evidence_inspector import resolve as inspector_resolve


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
    inc_id = "inc_r39s4_" + hashlib.sha256(b"r39s4").hexdigest()[:12]
    evt_id = "evt_r39s4_" + hashlib.sha256(b"r39s4-evt").hexdigest()[:12]
    now = datetime.now(timezone.utc).isoformat()
    canonical = {
        "event_id": evt_id, "timestamp": now,
        "dsm": {"id": "sysmon", "event_id": "sysmon:1"},
        "host": {"name": "WKS-R39S4"},
        "user": {"name": "diana@nivxray.local"},
        "process": {"name": "powershell.exe",
                        "parent": {"name": "winword.exe"},
                        "commandline": "powershell.exe -nop -w hidden -enc AAAA"},
        "network": {"src": {"ip": "10.10.10.5"},
                          "dst": {"ip": "203.0.113.44"},
                          "protocol": "TCP"},
        "security": {"signature": {"id": 42, "name": "Suspicious PS"},
                           "severity": 2},
    }
    incident = {
        "id": inc_id, "tenant_id": "default",
        "created_at": now, "updated_at": now,
        "title": "R39 Step4 fixture",
        "user_email": "admin@nivxray.com",
        "incident_state": "new", "incident_priority": "P2",
        "verdict_card": {"verdict": "suspicious", "engine": "sigma"},
        "mitre": [{"technique_id": "T1059.001", "tactic_id": "TA0002",
                        "name": "PowerShell"}],
        "iocs": {"ip": ["203.0.113.44"], "user": ["diana@nivxray.local"]},
        "xdr_pipeline": {"canonical_event_id": evt_id, "ice_matches": [],
                              "detection_rule_id": "rule-r39s4",
                              "trace_id": "r39s4"}
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

def test_activity_graph_excludes_capability_nodes(loop, db, incident_id):
    g = _run(loop, AttackGraphService.compose(db, incident_id))
    v = g["views"]["activity_graph"]
    kinds = {n["kind"] for n in v["nodes"]}
    assert "capability" not in kinds, (
        f"Capability nodes leaked onto Activity Graph: {sorted(kinds)}"
    )


def test_activity_graph_excludes_finding_nodes(loop, db, incident_id):
    g = _run(loop, AttackGraphService.compose(db, incident_id))
    v = g["views"]["activity_graph"]
    kinds = {n["kind"] for n in v["nodes"]}
    assert "finding" not in kinds, (
        f"Findings must be annotations, not canvas nodes: {sorted(kinds)}"
    )


def test_activity_graph_every_node_has_annotations_object(loop, db, incident_id):
    g = _run(loop, AttackGraphService.compose(db, incident_id))
    v = g["views"]["activity_graph"]
    for n in v["nodes"]:
        assert "annotations" in n, f"node {n['id']} missing annotations field"
        assert "findings" in n["annotations"], (
            f"node {n['id']} annotations missing 'findings' list"
        )
        assert isinstance(n["annotations"]["findings"], list)


def test_activity_graph_finding_annotations_on_parent_entities(loop, db, incident_id):
    """At least one entity node must carry a finding annotation."""
    g = _run(loop, AttackGraphService.compose(db, incident_id))
    v = g["views"]["activity_graph"]
    total = sum(len(n["annotations"]["findings"]) for n in v["nodes"])
    assert total >= 1, (
        f"Expected at least one finding annotation on an entity node, "
        f"got 0 (findings should always anchor to something in this fixture)"
    )
    assert v["totals"]["finding_annotations"] == total, (
        f"totals.finding_annotations={v['totals']['finding_annotations']} "
        f"does not match sum={total}"
    )


def test_annotations_carry_required_fields(loop, db, incident_id):
    g = _run(loop, AttackGraphService.compose(db, incident_id))
    v = g["views"]["activity_graph"]
    for n in v["nodes"]:
        for a in n["annotations"]["findings"]:
            for k in ("finding_id", "state", "summary"):
                assert k in a, f"annotation missing '{k}': {a}"


def test_event_node_exposes_event_id(loop, db, incident_id):
    g = _run(loop, AttackGraphService.compose(db, incident_id))
    ev_nodes = [n for n in g["nodes"] if n["kind"] == "event"]
    assert ev_nodes, "expected at least one event node"
    for n in ev_nodes:
        assert (n.get("attrs") or {}).get("event_id"), (
            f"event node missing attrs.event_id: {n}"
        )


def test_finding_node_exposes_finding_id(loop, db, incident_id):
    g = _run(loop, AttackGraphService.compose(db, incident_id))
    f_nodes = [n for n in g["nodes"] if n["kind"] == "finding"]
    for n in f_nodes:
        assert (n.get("attrs") or {}).get("finding_id"), (
            f"finding node missing attrs.finding_id: {n}"
        )


def test_process_tree_still_present(loop, db, incident_id):
    g = _run(loop, AttackGraphService.compose(db, incident_id))
    assert "process_tree" in g["views"]
    assert g["views"]["process_tree"]["totals"]["processes"] >= 2


def test_projections_deterministic_after_annotation(loop, db, incident_id):
    a = _run(loop, AttackGraphService.compose(db, incident_id))["views"]
    b = _run(loop, AttackGraphService.compose(db, incident_id))["views"]
    for k in ("mitre_chain", "process_tree", "activity_graph"):
        assert (json.dumps(a[k], sort_keys=True)
                    == json.dumps(b[k], sort_keys=True)), (
            f"{k} projection is non-deterministic after Step 4 changes"
        )


# ── Inspector integration ───────────────────────────────────────────

def test_inspector_resolves_host_from_activity_graph(loop, db, incident_id):
    """The frontend calls the shared inspector with node.label as
    refId — the inspector MUST resolve host / user / ip kinds."""
    env = _run(loop, inspector_resolve(db, incident_id, "host", "WKS-R39S4"))
    assert env.get("state") != "MISSING", env
    assert env["identity"]["label"] == "WKS-R39S4"


def test_inspector_resolves_user_from_activity_graph(loop, db, incident_id):
    env = _run(loop, inspector_resolve(db, incident_id, "user",
                                                   "diana@nivxray.local"))
    assert env.get("state") != "MISSING", env
    assert env["identity"]["label"] == "diana@nivxray.local"


def test_inspector_resolves_ip_from_activity_graph(loop, db, incident_id):
    env = _run(loop, inspector_resolve(db, incident_id, "ip", "203.0.113.44"))
    assert env.get("state") != "MISSING", env
    assert env["identity"]["label"] == "203.0.113.44"
    # Ensure INVESTIGATE actions expose network_pivot / ioc_pivot.
    action_ids = {a["id"] for a in env["actions"]}
    assert "network_pivot" in action_ids, env["actions"]


def test_inspector_returns_missing_for_unknown_host(loop, db, incident_id):
    env = _run(loop, inspector_resolve(db, incident_id, "host", "nowhere"))
    assert env.get("state") == "MISSING", env
