"""Round 38.3 · Shared Evidence Inspector regression."""
from __future__ import annotations
import asyncio, hashlib
from datetime import datetime, timezone
import pytest

from services.evidence_inspector import resolve


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
    inc_id = "inc_r383_" + hashlib.sha256(b"r383").hexdigest()[:12]
    evt_id = "evt_r383_" + hashlib.sha256(b"r383-evt").hexdigest()[:12]
    now = datetime.now(timezone.utc).isoformat()
    canonical = {
        "event_id": evt_id, "timestamp": now,
        "dsm": {"id": "sysmon"},
        "host": {"name": "WKS-R383"},
        "user": {"name": "carol@nivxray.local"},
        "process": {"name": "powershell.exe",
                        "parent": {"name": "winword.exe"},
                        "commandline": "powershell.exe -nop -enc AAAA"},
        "security": {"signature": {"id": 999, "name": "PS"}},
    }
    incident = {
        "id": inc_id, "tenant_id": "default",
        "created_at": now, "updated_at": now,
        "title": "R38.3 inspector",
        "user_email": "admin@nivxray.com",
        "incident_state": "new", "incident_priority": "P2",
        "verdict_card": {"verdict": "suspicious", "engine": "sigma"},
        "mitre": [{"technique_id": "T1059.001", "tactic_id": "TA0002",
                        "name": "PowerShell"}],
        "xdr_pipeline": {"canonical_event_id": evt_id, "ice_matches": []}
    }
    async def _seed():
        await db["xdr_canonical_evidence"].update_one(
            {"event_id": evt_id}, {"$set": canonical}, upsert=True)
        await db["workspace_cases"].update_one(
            {"id": inc_id}, {"$set": incident}, upsert=True)
    _run(loop, _seed())
    return inc_id


def test_resolve_technique(loop, db, incident_id):
    env = _run(loop, resolve(db, incident_id, "technique", "T1059.001"))
    assert env.get("state") != "MISSING", env
    assert "PowerShell" in env["identity"]["label"]
    assert env["identity"]["subtitle"].startswith("TA0002")
    # Every observed technique must carry canonical evidence refs.
    assert any(e["source_ref"].startswith("canonical:")
                  for e in env["evidence"])
    assert env["attack"]["techniques"]


def test_resolve_process(loop, db, incident_id):
    env = _run(loop, resolve(db, incident_id, "process", "powershell.exe"))
    assert env["identity"]["label"] == "powershell.exe"
    labels = {r["label"] for r in env["context"]["relationships"]}
    assert "COMMANDLINE" in labels or "HOST" in labels


def test_resolve_event(loop, db, incident_id):
    inc = _run(loop, db["workspace_cases"].find_one({"id": incident_id},
                                                                     {"_id": 0}))
    evt = inc["xdr_pipeline"]["canonical_event_id"]
    env = _run(loop, resolve(db, incident_id, "event", evt))
    assert env["identity"]["label"] == evt
    assert env["evidence"][0]["source_ref"] == evt


def test_resolve_commandline(loop, db, incident_id):
    env = _run(loop, resolve(db, incident_id, "commandline", "AAAA"))
    assert env.get("state") != "MISSING"
    assert env["identity"]["subtitle"] == "COMMAND LINE"


def test_resolve_incident(loop, db, incident_id):
    env = _run(loop, resolve(db, incident_id, "incident", incident_id))
    assert env["identity"]["label"] == "R38.3 inspector"
    assert any(b["label"].startswith("SUSPICIOUS")
                  for b in env["identity"]["badges"])


def test_resolve_missing_returns_missing_not_fabricated(loop, db, incident_id):
    env = _run(loop, resolve(db, incident_id, "technique", "T9999.999"))
    assert env.get("state") == "MISSING", (
        "Owner rule §11 — resolver must not fabricate an object that "
        "does not exist in the AttackTechniqueEvidence contract."
    )


def test_actions_hint_present_for_known_kinds(loop, db, incident_id):
    env = _run(loop, resolve(db, incident_id, "process", "powershell.exe"))
    action_ids = {a["id"] for a in env["actions"]}
    assert "commandline_decode" in action_ids
    assert "process_ancestry"   in action_ids
