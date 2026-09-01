"""Round 35 · Operational Attack Graph regression."""
from __future__ import annotations
import asyncio, os, uuid, hashlib
from datetime import datetime, timezone
import pytest
from dotenv import load_dotenv
load_dotenv("/app/backend/.env")
from motor.motor_asyncio import AsyncIOMotorClient

from detection_content.xdr_pipeline import process_event_through_pipeline
from detection_content.collector_runtime import GOLDEN_SNORT_EVENT
from services.attack_graph import AttackGraphService, get_event_intel
from services.attack_story.attack_cycle import STAGES


@pytest.fixture(scope="module")
def loop():
    lp = asyncio.new_event_loop()
    yield lp
    lp.close()


@pytest.fixture(scope="module")
def db(loop):
    c = AsyncIOMotorClient(os.environ["MONGO_URL"])
    yield c[os.environ.get("DB_NAME", "test_database")]
    c.close()


def _run(loop, coro):
    return loop.run_until_complete(coro)


@pytest.fixture(scope="module")
def incident_id(loop, db):
    r = _run(loop, process_event_through_pipeline(
        db, dict(GOLDEN_SNORT_EVENT), str(uuid.uuid4()),
        integration_id="integration-snort-ref",
        collector_id="collector-snort-ref"))
    inc = r.get("incident") or {}
    assert inc.get("created")
    return inc["incident_id"]


@pytest.fixture(scope="module")
def edr_incident_id(loop, db):
    inc_id = "inc_r35_edr_" + hashlib.sha256(b"r35-edr").hexdigest()[:12]
    evt_id = "evt_r35_edr_" + hashlib.sha256(b"r35-edr-evt").hexdigest()[:12]
    now = datetime.now(timezone.utc).isoformat()
    canonical = {
        "event_id": evt_id, "timestamp": now,
        "dsm": {"id": "sysmon", "event_id": "sysmon:1"},
        "host": {"name": "WKS-R35"},
        "user": {"name": "carol@nivxray.local"},
        "process": {
            "name": "powershell.exe",
            "parent": {"name": "winword.exe"},
            "commandline": "powershell.exe -nop -w hidden -enc AAAA",
        },
        "network": {
            "src": {"ip": "10.99.99.30"},
            "dst": {"ip": "185.199.108.201"},
            "protocol": "TCP",
        },
        "security": {"signature": {"id": 77777, "name": "Suspicious PS"},
                        "severity": 2},
    }
    incident = {
        "id": inc_id, "tenant_id": "default",
        "created_at": now, "updated_at": now,
        "name": "R35 EDR incident", "title": "R35 EDR incident",
        "user_email": "admin@nivxray.com",
        "incident_state": "new", "incident_priority": "P2",
        "verdict_card": {"verdict": "suspicious", "confidence": 65,
                            "engine": "nivxray::detection_content::nivxray_native_sigma"},
        "mitre": [
            {"technique_id": "T1059.001", "tactic_id": "TA0002"},
            {"technique_id": "T1218.011", "tactic_id": "TA0005"},
        ],
        "iocs": {"ip": ["185.199.108.201"], "hash": ["c" * 64],
                    "user": ["carol@nivxray.local"]},
        "xdr_pipeline": {
            "engine_id": "nivxray::detection_content::xdr_incident",
            "trace_id": "r35-fixture",
            "canonical_event_id": evt_id,
            "detection_rule_id": "rule-r35",
            "ice_matches": [],
            "veee": {"label": "SUSPICIOUS", "score": 65,
                        "engine_id": "nivxray::veee::v1"},
        },
    }
    async def _seed():
        await db["xdr_canonical_evidence"].update_one(
            {"event_id": evt_id}, {"$set": canonical}, upsert=True)
        await db["workspace_cases"].update_one(
            {"id": inc_id}, {"$set": incident}, upsert=True)
    _run(loop, _seed())
    from services.investigator import InvestigatorService
    _run(loop, InvestigatorService.tick(db, inc_id))
    return inc_id


# ── 1 · Envelope + schema ───────────────────────────────────────────
def test_attack_graph_envelope_shape(loop, db, incident_id):
    g = _run(loop, AttackGraphService.compose(db, incident_id))
    for k in ("schema_version", "nodes", "edges", "primary_path",
                "alternative_paths", "attack_stages", "timeline",
                "metrics", "evidence_summary", "mitre_summary",
                "investigation_gaps"):
        assert k in g
    assert g["schema_version"] == "attack-graph.v1"
    assert len(g["nodes"]) > 0
    assert len(g["edges"]) > 0


# ── 2 · Deterministic node/edge ids ─────────────────────────────────
def test_ids_are_deterministic_across_calls(loop, db, incident_id):
    a = _run(loop, AttackGraphService.compose(db, incident_id))
    b = _run(loop, AttackGraphService.compose(db, incident_id))
    a_nids = sorted(n["id"] for n in a["nodes"])
    b_nids = sorted(n["id"] for n in b["nodes"])
    assert a_nids == b_nids, "node ids must be deterministic"
    a_eids = sorted(e["id"] for e in a["edges"])
    b_eids = sorted(e["id"] for e in b["edges"])
    assert a_eids == b_eids, "edge ids must be deterministic"


# ── 3 · Every edge is evidence-anchored ─────────────────────────────
def test_every_edge_has_evidence_or_reason(loop, db, incident_id):
    g = _run(loop, AttackGraphService.compose(db, incident_id))
    for e in g["edges"]:
        # Every edge either references evidence or explains itself with
        # a governed reason (e.g. gap edges).
        assert e["reason"], f"edge {e['id']} missing reason"
        anchored = bool(e["evidence_refs"] or e["technique_id"]
                             or e["finding_ids"] or e["source"] == "iue.gap")
        assert anchored, f"edge {e['id']} not evidence-anchored: {e}"


# ── 4 · 14-stage SSOT reuse ────────────────────────────────────────
def test_stages_use_round33_ssot(loop, db, incident_id):
    g = _run(loop, AttackGraphService.compose(db, incident_id))
    stages_in_order = [s["stage"] for s in g["attack_stages"]]
    assert stages_in_order == list(STAGES)


# ── 5 · Four-state grammar ─────────────────────────────────────────
def test_four_state_grammar_present(loop, db, incident_id):
    g = _run(loop, AttackGraphService.compose(db, incident_id))
    allowed = {"OBSERVED", "SUPPORTED", "POSSIBLE", "NOT_OBSERVED"}
    for n in g["nodes"]:
        assert n["state"] in allowed, f"node {n['id']} state {n['state']} illegal"
    for e in g["edges"]:
        assert e["state"] in allowed, f"edge {e['id']} state {e['state']} illegal"


# ── 6 · Event ID intelligence lookup ────────────────────────────────
def test_event_intel_knows_common_ids():
    for evt in ("4624", "4625", "4648", "4688", "4689", "4697", "1102"):
        d = get_event_intel(evt)
        assert d, f"event id {evt} not registered"
        assert d["capabilities"]
    d = get_event_intel("sysmon:1")
    assert d and "process_ancestry" in d["capabilities"]


# ── 7 · EDR fixture reconstructs WINWORD → PowerShell chain ────────
def test_edr_fixture_reconstructs_chain(loop, db, edr_incident_id):
    g = _run(loop, AttackGraphService.compose(db, edr_incident_id))
    kinds = {n["kind"] for n in g["nodes"]}
    for expected_kind in ("incident", "event", "host", "user",
                              "process", "stage", "technique",
                              "commandline", "ip"):
        assert expected_kind in kinds, f"missing node kind {expected_kind}"
    # Parent-child edge must exist.
    labels = {n["id"]: n["label"] for n in g["nodes"]}
    parent_child_edges = [e for e in g["edges"]
                                if e["rel"] == "SPAWNED"
                                  and "winword.exe" in labels.get(e["src"], "").lower()
                                  and "powershell.exe" in labels.get(e["dst"], "").lower()]
    assert parent_child_edges, "WINWORD → PowerShell SPAWNED edge missing"
    # Command line node must be present.
    cli_nodes = [n for n in g["nodes"] if n["kind"] == "commandline"]
    assert cli_nodes, "commandline node missing"
    # T1059.001 technique observed.
    t_nodes = {n["label"]: n for n in g["nodes"] if n["kind"] == "technique"}
    assert "T1059.001" in t_nodes and t_nodes["T1059.001"]["state"] == "OBSERVED"


# ── 8 · Primary path is walkable and non-empty ──────────────────────
def test_primary_path_walkable(loop, db, edr_incident_id):
    g = _run(loop, AttackGraphService.compose(db, edr_incident_id))
    node_ids = {n["id"] for n in g["nodes"]}
    assert len(g["primary_path"]) >= 2
    for nid in g["primary_path"]:
        assert nid in node_ids, f"primary path references unknown node {nid}"


# ── 9 · Timeline temporally ordered ─────────────────────────────────
def test_timeline_is_sorted(loop, db, edr_incident_id):
    g = _run(loop, AttackGraphService.compose(db, edr_incident_id))
    times = [t["at"] for t in g["timeline"]]
    assert times == sorted(times), "timeline entries must be temporally ordered"


# ── 10 · Metrics bounded and honest ─────────────────────────────────
def test_metrics_bounded(loop, db, edr_incident_id):
    g = _run(loop, AttackGraphService.compose(db, edr_incident_id))
    for k, v in g["metrics"].items():
        assert 0 <= float(v) <= 100, f"metric {k}={v} out of bounds"


# ── 11 · Missing incident raises ────────────────────────────────────
def test_missing_incident_raises(loop, db):
    with pytest.raises(ValueError, match="incident_not_found"):
        _run(loop, AttackGraphService.compose(db, "inc_missing_r35"))


# ── 12 · Non-fabrication: NOT_OBSERVED stages remain as gaps only ─
def test_not_observed_stages_have_no_evidence_edges(loop, db, incident_id):
    """A NOT_OBSERVED stage may have zero incoming BELONGS_TO edges,
    but never a BELONGS_TO edge in state OBSERVED/SUPPORTED — that
    would be fabrication."""
    g = _run(loop, AttackGraphService.compose(db, incident_id))
    stage_states = {s["id"]: s["state"] for s in g["attack_stages"]}
    for e in g["edges"]:
        if e["rel"] != "BELONGS_TO":
            continue
        dst_state = stage_states.get(e["dst"])
        if dst_state == "NOT_OBSERVED":
            assert e["state"] == "NOT_OBSERVED", (
                f"NOT_OBSERVED stage {e['dst']} has anchored edge in state "
                f"{e['state']} — fabrication!")
