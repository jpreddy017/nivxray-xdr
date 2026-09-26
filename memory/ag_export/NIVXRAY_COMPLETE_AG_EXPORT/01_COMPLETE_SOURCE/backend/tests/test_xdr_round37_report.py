"""Round 37 · Investigation Report Contract regression."""
from __future__ import annotations
import asyncio, hashlib
from datetime import datetime, timezone
import pytest

from services import report as report_svc


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
    inc_id = "inc_r37_" + hashlib.sha256(b"r37").hexdigest()[:12]
    evt_id = "evt_r37_" + hashlib.sha256(b"r37-evt").hexdigest()[:12]
    now = datetime.now(timezone.utc).isoformat()
    canonical = {
        "event_id": evt_id, "timestamp": now,
        "dsm": {"id": "sysmon", "event_id": "sysmon:1"},
        "host": {"name": "WKS-R37", "fqdn": "wks-r37.nivxray.local"},
        "user": {"name": "carol@nivxray.local"},
        "process": {"name": "powershell.exe", "pid": 4428,
                        "parent": {"name": "winword.exe", "pid": 3120},
                        "commandline": "powershell.exe -nop -w hidden -enc AAAA"},
        "file":    {"name": "PDFMaestroUpdater.exe",
                        "path": "C:\\Users\\carol\\AppData\\Roaming\\SB\\PM\\PDFMaestroUpdater.exe",
                        "size": 371824, "signer": "Secure PC Software LLC",
                        "hash": {"sha256": "a" * 64, "sha1": "b" * 40,
                                     "md5": "c" * 32}},
        "network": {"src": {"ip": "10.99.99.30", "port": 51544},
                          "dst": {"ip": "185.199.108.201", "port": 443},
                          "protocol": "TCP"},
        "security": {"signature": {"id": 77777, "name": "Suspicious PS"},
                           "severity": 2},
    }
    incident = {
        "id": inc_id, "tenant_id": "default",
        "created_at": now, "updated_at": now,
        "name": "R37 report fixture", "title": "R37 report fixture",
        "user_email": "admin@nivxray.com",
        "incident_state": "new", "incident_priority": "P2",
        "verdict_card": {"verdict": "suspicious", "confidence": 65,
                              "engine": "nivxray::detection_content::sigma"},
        "mitre": [{"technique_id": "T1059.001", "tactic_id": "TA0002",
                       "name": "PowerShell"}],
        "iocs": {"ip": ["185.199.108.201"], "hash": ["c" * 64]},
        "xdr_pipeline": {"engine_id": "nivxray::detection_content::xdr_incident",
                              "trace_id": "r37-fixture",
                              "canonical_event_id": evt_id,
                              "detection_rule_id": "rule-r37",
                              "ice_matches": []},
    }
    async def _seed():
        await db["xdr_canonical_evidence"].update_one(
            {"event_id": evt_id}, {"$set": canonical}, upsert=True)
        await db["workspace_cases"].update_one(
            {"id": inc_id}, {"$set": incident}, upsert=True)
        await db["xdr_report_blocks"].delete_many({"incident_id": inc_id})
    _run(loop, _seed())
    return inc_id


# ── 1 · Envelope ────────────────────────────────────────────────────
def test_report_envelope_shape(loop, db, incident_id):
    r = _run(loop, report_svc.compose(db, incident_id))
    for k in ("incident_id", "tenant_id", "header", "sections",
                "ownership_matrix", "generated_at"):
        assert k in r, f"missing {k!r} in report"
    for s in report_svc.SECTIONS:
        assert s in r["sections"], f"section {s!r} missing"


# ── 2 · Technical Summary is 100% evidence-derived, read-only ─────
def test_technical_summary_is_read_only(loop, db, incident_id):
    r = _run(loop, report_svc.compose(db, incident_id))
    tech = r["sections"]["technical_summary"]
    assert tech["origin"] == "SYSTEM"
    assert tech["editable"] is False
    assert tech["read_only"] is True
    assert tech["provenance"] == "Evidence-derived"
    group_names = {g["name"] for g in tech["groups"]}
    assert "Detection" in group_names
    assert "File" in group_names
    assert "Execution" in group_names
    assert "MITRE ATT&CK" in group_names


def test_technical_summary_rejects_analyst_add(loop, db, incident_id):
    with pytest.raises(report_svc.TechnicalSummaryReadOnly):
        _run(loop, report_svc.add_block(
            db, incident_id, "technical_summary",
            "should be refused", "analyst@nivxray.local"))


# ── 3 · Executive Summary ownership ─────────────────────────────────
def test_executive_summary_ownership(loop, db, incident_id):
    r = _run(loop, report_svc.compose(db, incident_id))
    es = r["sections"]["executive_summary"]
    assert es["analyst_writable"] is True
    assert len(es["system_blocks"]) >= 1
    for b in es["system_blocks"]:
        assert b["origin"] == "SYSTEM"
        assert b["section"] == "executive_summary"
        assert b["provenance"] in {"NivXRay generated", "Evidence-derived"}


def test_analyst_can_add_executive_block(loop, db, incident_id):
    b = _run(loop, report_svc.add_block(
        db, incident_id, "executive_summary",
        "Analyst conclusion: customer should confirm authorization.",
        "carol@nivxray.local", title="Analyst Assessment"))
    assert b["origin"] == "ANALYST"
    assert b["provenance"] == "Analyst added"
    r = _run(loop, report_svc.compose(db, incident_id))
    ab_ids = [x["block_id"] for x in
                 r["sections"]["executive_summary"]["analyst_blocks"]]
    assert b["block_id"] in ab_ids


def test_analyst_can_edit_own_block(loop, db, incident_id):
    b = _run(loop, report_svc.add_block(
        db, incident_id, "recommendations", "Isolate the endpoint.",
        "carol@nivxray.local", priority="P1",
        title="Endpoint containment"))
    edited = _run(loop, report_svc.edit_block(
        db, b["block_id"], "Isolate the endpoint immediately.",
        "carol@nivxray.local"))
    assert edited["content"] == "Isolate the endpoint immediately."
    assert edited["provenance"] == "Analyst edited"
    assert edited["modified_by"] == "carol@nivxray.local"


def test_analyst_delete_does_not_touch_ssot(loop, db, incident_id):
    """Analyst deleting a report block must NEVER delete canonical
    evidence.  This is the single most important owner rule of the
    Report Contract."""
    # Snapshot canonical count before.
    before = _run(loop, db["xdr_canonical_evidence"].count_documents({}))
    b = _run(loop, report_svc.add_block(
        db, incident_id, "supporting_evidence",
        "Analyst screenshot reference.",
        "carol@nivxray.local", title="External capture"))
    assert _run(loop, report_svc.remove_block(db, b["block_id"])) is True
    after = _run(loop, db["xdr_canonical_evidence"].count_documents({}))
    assert before == after, ("Analyst delete leaked into SSOT: "
                                     f"{before} → {after}")


# ── 4 · Ownership matrix is honest ─────────────────────────────────
def test_ownership_matrix_reflects_rules(loop, db, incident_id):
    r = _run(loop, report_svc.compose(db, incident_id))
    m = r["ownership_matrix"]
    assert m["technical_summary"] == {"auto": True, "analyst": False,
                                                    "editable": False}
    for s in ("executive_summary", "supporting_evidence",
                "recommendations"):
        assert m[s]["auto"] is True
        assert m[s]["analyst"] is True
        assert m[s]["editable"] is True


# ── 5 · Determinism ────────────────────────────────────────────────
def test_system_blocks_are_deterministic(loop, db, incident_id):
    import json
    a = _run(loop, report_svc.compose(db, incident_id))
    b = _run(loop, report_svc.compose(db, incident_id))
    def _strip(x):
        # generated_at differs between runs by design; strip it.
        x = dict(x); x.pop("generated_at", None)
        for sec in x["sections"].values():
            if isinstance(sec, dict):
                if "generated_at" in sec: sec.pop("generated_at", None)
                for bl in (sec.get("system_blocks") or []):
                    bl.pop("created_at", None)
                    bl.pop("updated_at", None)
        return x
    assert (json.dumps(_strip(a), sort_keys=True, default=str)
                == json.dumps(_strip(b), sort_keys=True, default=str)), (
        "SYSTEM composition must be deterministic")


# ── 6 · Header carries the incident identity ───────────────────────
def test_header_reflects_incident(loop, db, incident_id):
    r = _run(loop, report_svc.compose(db, incident_id))
    h = r["header"]
    assert h["title"] == "R37 report fixture"
    assert h["priority"] == "P2"
    assert h["host"] == "WKS-R37"
    assert h["verdict"] == "suspicious"
