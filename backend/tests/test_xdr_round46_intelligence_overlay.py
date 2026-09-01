"""Round 46 · Analyst Intelligence Overlay — regression.

Owner-locked acceptance gates:

  · Overlay creation stores author_id + author_email + reason + version
  · Effective value = analyst_value ?? machine_value
  · Machine value never mutated
  · machine_source_hash captured; drift surfaces as MACHINE-SOURCE-UPDATED
  · Every create / edit / revert appends an audit entry in the
    IMMUTABLE audit collection (no unbounded embedded array)
  · Revert preserves history; effective returns machine value
  · Version conflict → 409
  · Reason mandatory
  · Analyst identity mandatory
  · Finding overlay only accepts summary; ATT&CK / evidence refs /
    confidence / identity locked
  · No overlay → backward-compatible machine behaviour
  · Presentation badge is NEVER "EVIDENCE-DERIVED" or claims analyst
    provenance for canonical evidence
  · Full R21→R46 cumulative suite still green
"""
from __future__ import annotations
import asyncio, hashlib, os
import pytest
from dotenv import load_dotenv

from services import intelligence_overlay as ov
from services.intelligence_overlay import OverlayError


@pytest.fixture(scope="module")
def loop():
    lp = asyncio.new_event_loop()
    asyncio.set_event_loop(lp)
    yield lp
    lp.close()


def _run(loop, coro):
    return loop.run_until_complete(coro)


@pytest.fixture(scope="module")
def db(loop):
    from motor.motor_asyncio import AsyncIOMotorClient
    load_dotenv("/app/backend/.env")
    c = AsyncIOMotorClient(os.environ["MONGO_URL"], io_loop=loop)
    d = c[os.environ.get("DB_NAME", "test_database")]
    _run(loop, d[ov.OVERLAY_COLL].delete_many({"incident_id":
                                                                {"$regex": "^inc_r46_"}}))
    _run(loop, d[ov.AUDIT_COLL].delete_many({"incident_id":
                                                              {"$regex": "^inc_r46_"}}))
    yield d
    c.close()


INC = "inc_r46_"
ANALYST = {"id": "usr_janardhan", "email": "janardhan@nivxray.com"}
ANALYST2 = {"id": "usr_ivy",       "email": "ivy@nivxray.com"}


# ── Governance gates ────────────────────────────────────────────────

def test_effective_no_overlay_returns_machine(loop, db):
    assert ov.effective(None, "machine text") == "machine text"


def test_reason_mandatory(loop, db):
    with pytest.raises(OverlayError) as ei:
        _run(loop, ov.upsert_overlay(
            db, INC + "a", "finding", "f-1", "summary",
            machine_value="mach", analyst_value="anal",
            reason="", author_id=ANALYST["id"],
            author_email=ANALYST["email"]))
    assert ei.value.code == "reason_required"
    assert ei.value.status == 400


def test_analyst_identity_mandatory(loop, db):
    with pytest.raises(OverlayError) as ei:
        _run(loop, ov.upsert_overlay(
            db, INC + "a", "finding", "f-1", "summary",
            machine_value="m", analyst_value="a",
            reason="test", author_id=None, author_email=None))
    assert ei.value.code == "analyst_required"


def test_unsupported_target_rejected(loop, db):
    for target, field in (("evidence", "id"), ("attack_graph", "label"),
                                ("technique", "confidence")):
        with pytest.raises(OverlayError) as ei:
            _run(loop, ov.get_overlay(db, INC + "a", target, "x", field))
        assert ei.value.code == "unsupported_target"


def test_finding_locked_to_summary(loop, db):
    for locked in ("confidence", "evidence_refs", "attack_technique",
                        "kind", "subject_kind", "reasoning"):
        with pytest.raises(OverlayError) as ei:
            _run(loop, ov.get_overlay(db, INC + "a", "finding",
                                                    "f-1", locked))
        assert ei.value.code == "unsupported_field"


def test_create_overlay_stores_full_governance_shape(loop, db):
    inc = INC + "create"
    doc = _run(loop, ov.upsert_overlay(
        db, inc, "exec_summary", "root", "content",
        machine_value="PowerShell executed EncodedCommand.",
        analyst_value="Initial execution associated with the phishing "
                          "attachment.",
        reason="Added analyst context from EDR telemetry",
        author_id=ANALYST["id"], author_email=ANALYST["email"]))
    assert doc["version"] == 1
    assert doc["author_id"] == ANALYST["id"]
    assert doc["author_email"] == ANALYST["email"]
    assert doc["reason"] == "Added analyst context from EDR telemetry"
    assert doc["machine_source_hash"] == hashlib.sha256(
        b"PowerShell executed EncodedCommand.").hexdigest()
    assert doc["machine_value"] == "PowerShell executed EncodedCommand."
    assert doc["analyst_value"].startswith("Initial execution")


def test_effective_value_uses_analyst_when_hash_matches(loop, db):
    inc = INC + "eff1"
    _run(loop, ov.upsert_overlay(
        db, inc, "attack_story", "step-2", "narrative",
        machine_value="Downloaded remote payload.",
        analyst_value="Assessed as staging step for ransomware.",
        reason="Correlated with EDR telemetry",
        author_id=ANALYST["id"], author_email=ANALYST["email"]))
    overlay = _run(loop, ov.get_overlay(db, inc, "attack_story",
                                                     "step-2", "narrative"))
    assert (ov.effective(overlay, "Downloaded remote payload.")
                == "Assessed as staging step for ransomware.")


def test_effective_value_falls_back_when_machine_source_drifts(loop, db):
    """MACHINE-SOURCE-UPDATED: machine text changed after overlay
    was created — the overlay is stale and effective returns
    machine value."""
    inc = INC + "drift"
    _run(loop, ov.upsert_overlay(
        db, inc, "attack_story", "step-9", "narrative",
        machine_value="Original machine narrative.",
        analyst_value="Analyst interpretation.",
        reason="Initial edit",
        author_id=ANALYST["id"], author_email=ANALYST["email"]))
    overlay = _run(loop, ov.get_overlay(db, inc, "attack_story",
                                                     "step-9", "narrative"))
    # Machine text changed underneath.
    updated_machine = "Machine narrative REGENERATED with new evidence."
    assert ov.effective(overlay, updated_machine) == updated_machine
    badge = ov.presentation_badge(overlay, updated_machine)
    assert badge["badge"] == "MACHINE SOURCE UPDATED"
    assert badge["drift"] is True


def test_presentation_badge_never_claims_evidence_derived(loop, db):
    inc = INC + "badge"
    _run(loop, ov.upsert_overlay(
        db, inc, "exec_summary", "root", "content",
        machine_value="m", analyst_value="a",
        reason="edit", author_id=ANALYST["id"],
        author_email=ANALYST["email"]))
    overlay = _run(loop, ov.get_overlay(db, inc, "exec_summary",
                                                     "root", "content"))
    for machine in ("m", "regenerated machine text"):
        badge = ov.presentation_badge(overlay, machine)
        # Analyst overlays must never masquerade as canonical evidence.
        assert badge["badge"] != "EVIDENCE-DERIVED"
        assert badge["badge"] != "NIVXRAY GENERATED"


def test_edit_increments_version_and_audit_entry(loop, db):
    inc = INC + "audit"
    _run(loop, ov.upsert_overlay(
        db, inc, "finding", "f-abc", "summary",
        machine_value="Machine finding summary.",
        analyst_value="v1",
        reason="Initial interpretation",
        author_id=ANALYST["id"], author_email=ANALYST["email"]))
    _run(loop, ov.upsert_overlay(
        db, inc, "finding", "f-abc", "summary",
        machine_value="Machine finding summary.",
        analyst_value="v2 refined",
        reason="Clarified attack progression",
        author_id=ANALYST["id"], author_email=ANALYST["email"],
        expected_version=1))
    doc = _run(loop, ov.get_overlay(db, inc, "finding",
                                                  "f-abc", "summary"))
    assert doc["version"] == 2
    assert doc["analyst_value"] == "v2 refined"
    audit = _run(loop, ov.history(db, inc, "finding",
                                                    "f-abc", "summary"))
    assert [e["version"] for e in audit] == [1, 2]
    assert audit[0]["action"] == "created"
    assert audit[1]["action"] == "edited"
    assert audit[1]["previous_value"] == "v1"
    assert audit[1]["new_value"] == "v2 refined"
    # Immutable audit: history entries are in the audit collection,
    # NOT embedded on the overlay doc.
    assert "audit_history" not in doc


def test_machine_value_never_mutated_across_edits(loop, db):
    inc = INC + "immut"
    original_machine = "Machine truth: PS -EncodedCommand …"
    _run(loop, ov.upsert_overlay(
        db, inc, "exec_summary", "root", "content",
        machine_value=original_machine,
        analyst_value="analyst v1",
        reason="initial",
        author_id=ANALYST["id"], author_email=ANALYST["email"]))
    _run(loop, ov.upsert_overlay(
        db, inc, "exec_summary", "root", "content",
        machine_value=original_machine,
        analyst_value="analyst v2",
        reason="refined",
        author_id=ANALYST2["id"], author_email=ANALYST2["email"],
        expected_version=1))
    doc = _run(loop, ov.get_overlay(db, inc, "exec_summary",
                                                  "root", "content"))
    assert doc["machine_value"] == original_machine, (
        "R46 hard invariant: the stored machine_value MUST NEVER be "
        "mutated by an analyst edit."
    )


def test_version_conflict_returns_409(loop, db):
    inc = INC + "conflict"
    _run(loop, ov.upsert_overlay(
        db, inc, "finding", "f-x", "summary",
        machine_value="mach", analyst_value="v1",
        reason="init",
        author_id=ANALYST["id"], author_email=ANALYST["email"]))
    with pytest.raises(OverlayError) as ei:
        _run(loop, ov.upsert_overlay(
            db, inc, "finding", "f-x", "summary",
            machine_value="mach", analyst_value="v2",
            reason="edit",
            author_id=ANALYST["id"], author_email=ANALYST["email"],
            expected_version=999))
    assert ei.value.status == 409
    assert ei.value.code == "conflict"
    assert ei.value.extra["stored_version"] == 1


def test_revert_preserves_history_and_effective_returns_machine(loop, db):
    inc = INC + "revert"
    _run(loop, ov.upsert_overlay(
        db, inc, "finding", "f-r", "summary",
        machine_value="machine finding",
        analyst_value="analyst finding",
        reason="init",
        author_id=ANALYST["id"], author_email=ANALYST["email"]))
    _run(loop, ov.revert_overlay(
        db, inc, "finding", "f-r", "summary",
        machine_value="machine finding",
        reason="False-positive assessment changed",
        author_id=ANALYST["id"], author_email=ANALYST["email"],
        expected_version=1))
    doc = _run(loop, ov.get_overlay(db, inc, "finding", "f-r", "summary"))
    assert doc["analyst_value"] is None
    assert doc["version"] == 2
    # Effective falls back to machine value.
    assert ov.effective(doc, "machine finding") == "machine finding"
    # History intact.
    audit = _run(loop, ov.history(db, inc, "finding", "f-r", "summary"))
    versions = [(e["version"], e["action"]) for e in audit]
    assert versions == [(1, "created"), (2, "reverted")]


def test_revert_without_active_overlay_fails(loop, db):
    inc = INC + "revertfail"
    with pytest.raises(OverlayError) as ei:
        _run(loop, ov.revert_overlay(
            db, inc, "finding", "nope", "summary",
            machine_value="m", reason="attempt",
            author_id=ANALYST["id"], author_email=ANALYST["email"]))
    assert ei.value.status == 404
    assert ei.value.code == "not_found"


def test_report_and_pdf_still_work_backwards_compatible(loop, db):
    """R46 must remain fully backward-compatible: when no overlay
    exists, the existing report contract + PDF export must behave
    identically to R43 output."""
    from services import report as report_svc
    from datetime import datetime, timezone
    import hashlib as _h
    inc_id = INC + "compat_" + _h.sha256(b"compat").hexdigest()[:8]
    evt_id = "evt_r46_compat"
    now = datetime.now(timezone.utc).isoformat()
    canonical = {"event_id": evt_id, "timestamp": now,
                     "dsm": {"id": "sysmon"},
                     "host": {"name": "WKS-R46"},
                     "process": {"name": "powershell.exe"},
                     "security": {"signature": {"id": 46, "name": "PS"}}}
    incident = {"id": inc_id, "tenant_id": "default",
                    "created_at": now, "updated_at": now,
                    "title": "R46 compat", "user_email": "admin@nivxray.com",
                    "incident_state": "in_progress", "incident_priority": "P2",
                    "verdict_card": {"verdict": "suspicious", "engine": "sigma"},
                    "mitre": [{"technique_id": "T1059.001",
                                    "tactic_id": "TA0002", "name": "PS"}],
                    "xdr_pipeline": {"canonical_event_id": evt_id,
                                            "ice_matches": [],
                                            "detection_rule_id": "rule-r46",
                                            "trace_id": "r46"}}
    _run(loop, db["xdr_canonical_evidence"].update_one(
        {"event_id": evt_id}, {"$set": canonical}, upsert=True))
    _run(loop, db["workspace_cases"].update_one(
        {"id": inc_id}, {"$set": incident}, upsert=True))
    r = _run(loop, report_svc.compose(db, inc_id))
    assert set(r["sections"].keys()) == {"executive_summary",
                                                        "technical_summary",
                                                        "supporting_evidence",
                                                        "recommendations"}
    pdf = report_svc.render_pdf(r)
    assert pdf.startswith(b"%PDF-")
