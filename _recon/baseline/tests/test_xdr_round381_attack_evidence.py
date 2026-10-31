"""Round 38.1 · AttackTechniqueEvidence canonical SSOT regression."""
from __future__ import annotations
import asyncio, hashlib
from datetime import datetime, timezone
import pytest

from services.attack_evidence import compose_attack_evidence


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
    inc_id = "inc_r381_" + hashlib.sha256(b"r381").hexdigest()[:12]
    evt_id = "evt_r381_" + hashlib.sha256(b"r381-evt").hexdigest()[:12]
    now = datetime.now(timezone.utc).isoformat()
    canonical = {
        "event_id": evt_id, "timestamp": now,
        "dsm": {"id": "sysmon", "event_id": "sysmon:1"},
        "host": {"name": "WKS-R381"},
        "user": {"name": "carol@nivxray.local"},
        "process": {"name": "powershell.exe",
                        "parent": {"name": "winword.exe"},
                        "commandline": "powershell.exe -nop -enc AAAA"},
    }
    incident = {
        "id": inc_id, "tenant_id": "default",
        "created_at": now, "updated_at": now,
        "name": "R38.1 evidence contract",
        "title": "R38.1 evidence contract",
        "user_email": "admin@nivxray.com",
        "incident_state": "new", "incident_priority": "P2",
        "verdict_card": {"verdict": "suspicious", "confidence": 65,
                              "engine": "nivxray::detection_content::sigma"},
        "mitre": [{"technique_id": "T1059.001", "tactic_id": "TA0002",
                        "name": "PowerShell"},
                    {"technique_id": "T1218.011", "tactic_id": "TA0005"}],
        "iocs": {"ip": ["185.199.108.201"]},
        "xdr_pipeline": {"engine_id": "nivxray::detection_content::xdr_incident",
                              "trace_id": "r381-fix",
                              "canonical_event_id": evt_id,
                              "detection_rule_id": "rule-r381",
                              "ice_matches": []}
    }
    async def _seed():
        await db["xdr_canonical_evidence"].update_one(
            {"event_id": evt_id}, {"$set": canonical}, upsert=True)
        await db["workspace_cases"].update_one(
            {"id": inc_id}, {"$set": incident}, upsert=True)
    _run(loop, _seed())
    return inc_id


def test_envelope_shape(loop, db, incident_id):
    r = _run(loop, compose_attack_evidence(db, incident_id))
    for k in ("incident_id", "techniques", "counts", "tactics_present"):
        assert k in r, f"missing {k!r}"


def test_incident_mitre_becomes_observed(loop, db, incident_id):
    """Detection engine + canonical evidence → OBSERVED with high confidence."""
    r = _run(loop, compose_attack_evidence(db, incident_id))
    by_id = {t["technique_id"]: t for t in r["techniques"]}
    assert "T1059.001" in by_id, r
    t = by_id["T1059.001"]
    assert t["state"] == "OBSERVED", t
    assert t["confidence"] >= 0.9
    assert t["technique_name"] == "PowerShell"
    assert t["tactic_id"] == "TA0002"
    assert t["tactic_name"] == "Execution"
    assert any("canonical:" in e for e in t["evidence_ids"])


def test_tactic_id_and_name_resolve(loop, db, incident_id):
    r = _run(loop, compose_attack_evidence(db, incident_id))
    by_id = {t["technique_id"]: t for t in r["techniques"]}
    assert by_id["T1218.011"]["tactic_id"] == "TA0005"
    assert by_id["T1218.011"]["tactic_name"] == "Defense Evasion"
    # Fallback name from hint table.
    assert "Rundll32" in by_id["T1218.011"]["technique_name"]


def test_provenance_is_present(loop, db, incident_id):
    r = _run(loop, compose_attack_evidence(db, incident_id))
    for t in r["techniques"]:
        assert t["provenance"], f"technique {t['technique_id']} missing provenance"
        for p in t["provenance"]:
            assert "source" in p
            assert "evidence_id" in p


def test_no_fabrication_when_no_evidence(loop, db):
    """Owner rule §11 — an incident with no MITRE input yields no techniques."""
    inc_id = "inc_r381_empty"
    async def _seed():
        await db["workspace_cases"].update_one(
            {"id": inc_id},
            {"$set": {"id": inc_id, "tenant_id": "default",
                        "user_email": "admin@nivxray.com",
                        "title": "empty", "mitre": []}},
            upsert=True)
    _run(loop, _seed())
    r = _run(loop, compose_attack_evidence(db, inc_id))
    assert r["techniques"] == [], (
        f"Empty incident must not surface techniques; got {r['techniques']}"
    )


def test_state_lattice_promotes_correctly(loop, db):
    """Same technique attributed by both correlation (SUPPORTED) and
    detection engine (OBSERVED) resolves to OBSERVED — the higher
    rung of the state lattice."""
    inc_id = "inc_r381_promote"
    evt_id = "evt_r381_promote"
    now = datetime.now(timezone.utc).isoformat()
    async def _seed():
        await db["xdr_canonical_evidence"].update_one(
            {"event_id": evt_id},
            {"$set": {"event_id": evt_id, "timestamp": now,
                        "host": {"name": "H"}, "user": {"name": "U"},
                        "process": {"name": "powershell.exe"}}},
            upsert=True)
        await db["xdr_correlation_matches"].update_one(
            {"match_id": "m-r381"},
            {"$set": {"match_id": "m-r381", "rule_name": "PS Correlation",
                        "mitre": [{"technique_id": "T1059.001",
                                       "tactic_id": "TA0002"}]}},
            upsert=True)
        await db["workspace_cases"].update_one(
            {"id": inc_id},
            {"$set": {"id": inc_id, "tenant_id": "default",
                        "user_email": "admin@nivxray.com",
                        "title": "promote",
                        "mitre": [{"technique_id": "T1059.001",
                                       "tactic_id": "TA0002",
                                       "name": "PowerShell"}],
                        "xdr_pipeline": {"canonical_event_id": evt_id,
                                              "ice_matches": ["m-r381"]}}},
            upsert=True)
    _run(loop, _seed())
    r = _run(loop, compose_attack_evidence(db, inc_id))
    t = next(x for x in r["techniques"] if x["technique_id"] == "T1059.001")
    assert t["state"] == "OBSERVED"
    sources = {p["source"] for p in t["provenance"]}
    assert "detection_engine" in sources
    assert "correlation_engine" in sources


def test_determinism(loop, db, incident_id):
    import json
    a = _run(loop, compose_attack_evidence(db, incident_id))
    b = _run(loop, compose_attack_evidence(db, incident_id))
    def _strip(x):
        x = dict(x); x.pop("generated_at", None)
        return x
    assert (json.dumps(_strip(a), sort_keys=True, default=str)
                == json.dumps(_strip(b), sort_keys=True, default=str))
