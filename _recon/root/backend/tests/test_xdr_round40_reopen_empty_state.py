"""Round 40 · Reopen Empty-State Polish · regression.

The frontend AutoInvestigationTab now renders sparse findings
(empty summary, empty reasoning, zero confidence) with an honest
kind·subject fallback rather than blank cells.

This regression pins the backend contract the polish relies on:

  * A Finding model always exposes `kind`, `subject_kind`,
    `subject_value` — even when `summary` is an empty string.
  * The findings API surfaces those fields untouched.
  * A CONVERGED investigation that is re-ticked with new evidence
    reopens cleanly (Round 35.3.1 fix preserved) and the resulting
    findings still expose the required identity fields for the
    empty-state polish.
"""
from __future__ import annotations
import asyncio, hashlib
from datetime import datetime, timezone
import pytest

from services.investigator.models import Finding
from services.investigator import InvestigatorService


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
    inc_id = "inc_r40_" + hashlib.sha256(b"r40").hexdigest()[:12]
    evt_id = "evt_r40_" + hashlib.sha256(b"r40-evt").hexdigest()[:12]
    now = datetime.now(timezone.utc).isoformat()
    canonical = {
        "event_id": evt_id, "timestamp": now,
        "dsm": {"id": "sysmon"},
        "host": {"name": "WKS-R40"},
        "user": {"name": "frank@nivxray.local"},
        "process": {"name": "powershell.exe",
                        "parent": {"name": "winword.exe"},
                        "commandline": "powershell.exe -nop -w hidden -enc AAAA"},
        "security": {"signature": {"id": 40, "name": "PS"}, "severity": 2},
    }
    incident = {
        "id": inc_id, "tenant_id": "default",
        "created_at": now, "updated_at": now,
        "title": "R40 empty-summary polish",
        "user_email": "admin@nivxray.com",
        "incident_state": "new", "incident_priority": "P3",
        "verdict_card": {"verdict": "suspicious", "engine": "sigma"},
        "mitre": [{"technique_id": "T1059.001", "tactic_id": "TA0002",
                        "name": "PowerShell"}],
        "xdr_pipeline": {"canonical_event_id": evt_id, "ice_matches": [],
                              "detection_rule_id": "rule-r40",
                              "trace_id": "r40"},
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

def test_finding_model_accepts_empty_summary():
    """The Finding contract MUST accept an empty summary; empty
    summaries are what the R40 empty-state UI polish handles."""
    now = datetime.now(timezone.utc).isoformat()
    f = Finding(
        finding_id="f-empty-1", tenant_id="default",
        incident_id="inc-x", execution_id="exec-x",
        capability="process_ancestry", engine="nivxray::investigator::pa",
        kind="prior_sighting",
        subject_kind="process", subject_value="powershell.exe",
        state="CORRELATED",
        confidence=0,
        summary="",                   # ← empty
        reasoning="",                 # ← empty
        evidence_refs=[], created_at=now,
    )
    assert f.summary == "" and f.reasoning == ""
    assert f.kind == "prior_sighting"
    # Frontend fallback identity components must be present:
    assert f.subject_kind and f.subject_value


def test_findings_api_exposes_identity_fields(loop, db, incident_id):
    """Every persisted finding surfaces the four fields the frontend
    R40 polish uses as fallback identity: kind · subject_kind ·
    subject_value · capability."""
    findings = _run(loop, InvestigatorService.get_findings(db, incident_id))
    assert findings, "expected at least one finding on fixture"
    for f in findings:
        for k in ("kind", "subject_kind", "subject_value", "capability"):
            assert k in f, f"finding missing {k!r}: {f}"


def test_converged_reopen_preserves_finding_identity_fields(loop, db, incident_id):
    """R35.3.1 (CONVERGED → REOPENED) preserved: after reopen, every
    finding still carries the fallback identity fields."""
    # Force a reopen by invalidating the IUE fingerprint (Round 35.3.1
    # invariant): edit the incident so a new tick reopens the loop.
    async def _touch():
        await db["workspace_cases"].update_one(
            {"id": incident_id},
            {"$set": {"iocs": {"ip": ["10.99.99.99"]}}})
    _run(loop, _touch())
    _run(loop, InvestigatorService.tick(db, incident_id))
    findings = _run(loop, InvestigatorService.get_findings(db, incident_id))
    assert findings, "reopen still yields findings"
    # Every finding usable by the frontend empty-state polish.
    for f in findings:
        assert f.get("kind"), f
        # If summary is empty, subject_kind + subject_value MUST be
        # populated so the fallback identity renders.
        if not (f.get("summary") or "").strip():
            assert f.get("subject_kind") and f.get("subject_value"), (
                f"empty-summary finding lacks fallback identity: {f}"
            )
