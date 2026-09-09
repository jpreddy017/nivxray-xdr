"""Round 36 · Three deterministic projections over the Attack Graph
SSOT.  Backend regression tests for the MITRE Chain, Process Tree,
and Activity Graph views.

Owner rules covered:
  * MITRE Chain surfaces only evidenced stages/techniques.
  * Process Tree renders pure parent→child ancestry.
  * Activity Graph never contains stage/technique/detection/match/
    capability/finding/gap nodes.
"""
from __future__ import annotations
import asyncio
import hashlib
import pytest
from datetime import datetime, timezone

from services.attack_graph import AttackGraphService
from services.investigator  import InvestigatorService


# ── Fixtures reused across the module ──────────────────────────────
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
def edr_incident_id(loop, db):
    inc_id = "inc_r36_edr_" + hashlib.sha256(b"r36-edr").hexdigest()[:12]
    evt_id = "evt_r36_edr_" + hashlib.sha256(b"r36-edr-evt").hexdigest()[:12]
    now = datetime.now(timezone.utc).isoformat()
    canonical = {
        "event_id": evt_id, "timestamp": now,
        "dsm": {"id": "sysmon", "event_id": "sysmon:1"},
        "host": {"name": "WKS-R36"},
        "user": {"name": "carol@nivxray.local"},
        "process": {"name": "powershell.exe",
                        "parent": {"name": "winword.exe"},
                        "commandline": "powershell.exe -nop -w hidden -enc AAAA"},
        "network": {"src": {"ip": "10.99.99.30"},
                          "dst": {"ip": "185.199.108.201"},
                          "protocol": "TCP"},
        "security": {"signature": {"id": 77777, "name": "Suspicious PS"},
                           "severity": 2},
    }
    incident = {
        "id": inc_id, "tenant_id": "default",
        "created_at": now, "updated_at": now,
        "name": "R36 EDR", "title": "R36 EDR",
        "user_email": "admin@nivxray.com",
        "incident_state": "new", "incident_priority": "P2",
        "verdict_card": {"verdict": "suspicious", "confidence": 65,
                              "engine": "nivxray::detection_content::sigma"},
        "mitre": [{"technique_id": "T1059.001", "tactic_id": "TA0002",
                       "name": "PowerShell"},
                    {"technique_id": "T1218.011", "tactic_id": "TA0005",
                       "name": "Signed Binary: Rundll32"}],
        "iocs": {"ip": ["185.199.108.201"], "hash": ["c" * 64],
                    "user": ["carol@nivxray.local"]},
        "xdr_pipeline": {"engine_id": "nivxray::detection_content::xdr_incident",
                              "trace_id": "r36-fixture",
                              "canonical_event_id": evt_id,
                              "detection_rule_id": "rule-r36",
                              "ice_matches": [],
                              "veee": {"label": "SUSPICIOUS", "score": 65,
                                          "engine_id": "nivxray::veee::v1"}}
    }
    async def _seed():
        await db["xdr_canonical_evidence"].update_one(
            {"event_id": evt_id}, {"$set": canonical}, upsert=True)
        await db["workspace_cases"].update_one(
            {"id": inc_id}, {"$set": incident}, upsert=True)
    _run(loop, _seed())
    _run(loop, InvestigatorService.tick(db, inc_id))
    return inc_id


# ── MITRE CHAIN VIEW ────────────────────────────────────────────────
def test_mitre_chain_view_present(loop, db, edr_incident_id):
    g = _run(loop, AttackGraphService.compose(db, edr_incident_id))
    v = g["views"]["mitre_chain"]
    assert v["totals"]["stages_shown"] >= 2, (
        f"Expected at least 2 stages, got {v['totals']['stages_shown']}"
    )
    assert v["totals"]["techniques_observed"] >= 2, (
        f"Expected at least 2 observed techniques, "
        f"got {v['totals']['techniques_observed']}"
    )


def test_mitre_chain_view_only_evidenced_stages(loop, db, edr_incident_id):
    g = _run(loop, AttackGraphService.compose(db, edr_incident_id))
    v = g["views"]["mitre_chain"]
    for s in v["stages"]:
        assert s["techniques"], f"Stage {s['name']} has no evidenced techniques"
        for t in s["techniques"]:
            assert t["state"] in ("OBSERVED", "SUPPORTED", "POSSIBLE")


def test_mitre_chain_technique_has_evidence(loop, db, edr_incident_id):
    g = _run(loop, AttackGraphService.compose(db, edr_incident_id))
    v = g["views"]["mitre_chain"]
    # Every observed technique on the EDR fixture must expose supporting
    # processes AND events reverse-walked from the technique node.
    for s in v["stages"]:
        for t in s["techniques"]:
            if t["state"] != "OBSERVED":
                continue
            ev = t["evidence"]
            assert ev["processes"], (
                f"{t['tid']} · missing process evidence: {ev}"
            )
            assert ev["events"] or ev["detection_rules"], (
                f"{t['tid']} · missing event or detection evidence: {ev}"
            )


# ── PROCESS TREE VIEW ───────────────────────────────────────────────
def test_process_tree_view_present(loop, db, edr_incident_id):
    g = _run(loop, AttackGraphService.compose(db, edr_incident_id))
    v = g["views"]["process_tree"]
    assert v["totals"]["processes"] >= 2, v["totals"]
    assert v["totals"]["roots"] >= 1, v["totals"]


def test_process_tree_winword_spawns_powershell(loop, db, edr_incident_id):
    g = _run(loop, AttackGraphService.compose(db, edr_incident_id))
    v = g["views"]["process_tree"]
    root_names = {r["name"] for r in v["roots"]}
    assert "winword.exe" in root_names, (
        f"Expected winword.exe as tree root; got {root_names}"
    )
    root = next(r for r in v["roots"] if r["name"] == "winword.exe")
    child_names = {c["name"] for c in root["children"]}
    assert "powershell.exe" in child_names, (
        f"Expected powershell.exe as child of winword.exe; got {child_names}"
    )


def test_process_tree_powershell_carries_commandline(loop, db, edr_incident_id):
    g = _run(loop, AttackGraphService.compose(db, edr_incident_id))
    v = g["views"]["process_tree"]
    root = next(r for r in v["roots"] if r["name"] == "winword.exe")
    ps = next(c for c in root["children"] if c["name"] == "powershell.exe")
    assert len(ps["commandlines"]) >= 1, (
        f"powershell.exe must carry its commandline: got {ps['commandlines']}"
    )
    assert "-enc" in (ps["commandlines"][0].get("full") or ps["commandlines"][0]["label"]).lower(), (
        f"Encoded flag must be present in commandline: {ps['commandlines']}"
    )


# ── ACTIVITY GRAPH VIEW ─────────────────────────────────────────────
def test_activity_graph_excludes_mitre_and_capabilities(loop, db, edr_incident_id):
    """R36 · Activity Graph is the entity/evidence relationship view.

    It must NEVER contain stages/techniques/detections/matches (MITRE
    concepts belong on MITRE Chain view) nor `capability` or
    `finding` nodes (NivXRay tools & derived conclusions belong on
    the Evidence Inspector).
    """
    g = _run(loop, AttackGraphService.compose(db, edr_incident_id))
    v = g["views"]["activity_graph"]
    forbidden_kinds = {"stage", "technique", "detection", "match", "gap",
                            "capability", "finding"}
    seen_kinds = {n["kind"] for n in v["nodes"]}
    assert not (seen_kinds & forbidden_kinds), (
        f"Activity Graph contains forbidden kinds: "
        f"{sorted(seen_kinds & forbidden_kinds)}"
    )


def test_activity_graph_contains_core_entities(loop, db, edr_incident_id):
    g = _run(loop, AttackGraphService.compose(db, edr_incident_id))
    v = g["views"]["activity_graph"]
    kinds = {n["kind"] for n in v["nodes"]}
    for expected in ("incident", "host", "user", "process"):
        assert expected in kinds, (
            f"Activity Graph missing core kind {expected!r}; "
            f"got {sorted(kinds)}"
        )


def test_activity_graph_edges_reference_kept_nodes(loop, db, edr_incident_id):
    g = _run(loop, AttackGraphService.compose(db, edr_incident_id))
    v = g["views"]["activity_graph"]
    ids = {n["id"] for n in v["nodes"]}
    for e in v["edges"]:
        assert e["src"] in ids, f"dangling edge src: {e}"
        assert e["dst"] in ids, f"dangling edge dst: {e}"
        assert e["state"] != "NOT_OBSERVED", (
            f"Activity Graph must exclude NOT_OBSERVED edges: {e}"
        )


# ── PROJECTION DETERMINISM ──────────────────────────────────────────
def test_projections_are_deterministic(loop, db, edr_incident_id):
    """Same inputs → byte-identical projections (owner rule)."""
    import json
    a = _run(loop, AttackGraphService.compose(db, edr_incident_id))["views"]
    b = _run(loop, AttackGraphService.compose(db, edr_incident_id))["views"]
    for k in ("mitre_chain", "process_tree", "activity_graph"):
        assert (json.dumps(a[k], sort_keys=True)
                    == json.dumps(b[k], sort_keys=True)), (
            f"{k} projection is non-deterministic"
        )
