"""
Round 22 · Evidence Traversal Resolver
──────────────────────────────────────

Validates the Evidence Traversability + Telemetry Neutrality
invariants:

  * Every graph node & every graph edge ref MUST resolve to a real
    document via `resolve(evidence_ref)`.
  * Missing references return state=MISSING (never fabricated).
  * `missing_fields` honestly reports absent-in-source-telemetry
    fields (Telemetry Neutrality).
  * The resolver is deterministic — same reference → same output.
"""
from __future__ import annotations
import asyncio, os, uuid, json
import pytest
from dotenv import load_dotenv
load_dotenv("/app/backend/.env")
from motor.motor_asyncio import AsyncIOMotorClient

from detection_content.xdr_evidence_traversal import (
    resolve, CANONICAL_EVENT, INCIDENT, FRAMEWORK_MAPPING,
    INTELLIGENCE_OBS, RESPONSE_EXECUTION, RECOMMENDATION, ANNOTATION,
    UNKNOWN,
)
from detection_content.xdr_attack_chain_graph import compose as compose_graph


@pytest.fixture(scope="module")
def loop():
    lp = asyncio.new_event_loop(); yield lp; lp.close()


@pytest.fixture(scope="module")
def db(loop):
    c = AsyncIOMotorClient(os.environ["MONGO_URL"])
    yield c[os.environ.get("DB_NAME", "test_database")]; c.close()


def _run(loop, coro): return loop.run_until_complete(coro)


@pytest.fixture(scope="module")
def snort_incident(loop, db):
    from detection_content.xdr_pipeline import process_event_through_pipeline
    from detection_content.collector_runtime import GOLDEN_SNORT_EVENT
    r = _run(loop, process_event_through_pipeline(
        db, dict(GOLDEN_SNORT_EVENT), str(uuid.uuid4()),
        integration_id="integration-snort-ref",
        collector_id="collector-snort-ref"))
    return (r.get("closed_loop") or {}).get("incident_id")


# ── Contract ────────────────────────────────────────────────────

def test_resolver_missing_for_unknown_ref(loop, db):
    r = _run(loop, resolve(db, "does_not_exist_" + uuid.uuid4().hex[:8]))
    assert r["state"] == "MISSING"
    assert r["kind"] == UNKNOWN
    assert "never synthesizes" in r["contract"].lower()


def test_resolver_empty_ref_is_missing(loop, db):
    r = _run(loop, resolve(db, ""))
    assert r["state"] == "MISSING"


def test_resolver_finds_incident(loop, db, snort_incident):
    r = _run(loop, resolve(db, snort_incident))
    assert r["state"] == "READY"
    assert r["kind"] == INCIDENT
    assert r["document"]["id"] == snort_incident
    assert "response_executions_count" in r["traversal"]


def test_resolver_finds_canonical_event(loop, db, snort_incident):
    inc = _run(loop, db["workspace_cases"].find_one(
        {"id": snort_incident}, {"_id": 0}))
    ce_id = (inc.get("xdr_pipeline") or {}).get("canonical_event_id")
    assert ce_id, "golden incident must have a canonical event"
    r = _run(loop, resolve(db, ce_id))
    assert r["state"] == "READY"
    assert r["kind"] == CANONICAL_EVENT
    assert r["document"]["event_id"] == ce_id
    # Reverse traversal must at least reveal the enclosing incident.
    assert any(x["id"] == snort_incident
                    for x in r["traversal"]["used_by_incidents"])
    # Must at least reveal the framework mappings.
    assert isinstance(r["traversal"]["used_by_mappings"], list)


def test_resolver_prefixed_reference_works(loop, db, snort_incident):
    """`incident:<id>` and `canonical:<id>` prefixes are accepted."""
    r = _run(loop, resolve(db, f"incident:{snort_incident}"))
    assert r["state"] == "READY"
    assert r["kind"] == INCIDENT


def test_missing_fields_reports_absent_telemetry_honestly(loop, db,
                                                                                snort_incident):
    """Snort golden event is network telemetry — process.command_line
    / process.image / user.name were NOT collected. The resolver
    must report them as 'not present in source telemetry' rather
    than synthesizing values."""
    inc = _run(loop, db["workspace_cases"].find_one(
        {"id": snort_incident}, {"_id": 0}))
    ce_id = (inc.get("xdr_pipeline") or {}).get("canonical_event_id")
    r = _run(loop, resolve(db, ce_id))
    fields = {mf["field"] for mf in r["missing_fields"]}
    assert "process.command_line" in fields, \
        "PowerShell / cmd.exe fields must be reported as absent"
    for mf in r["missing_fields"]:
        assert mf["note"] == "not present in source telemetry"


def test_resolver_source_refs_are_honestly_missing_for_kb_entries(loop, db,
                                                                                            snort_incident):
    """`signature:<sid>` and `engine:<id>` refs point to knowledge-base
    entries, NOT to evidence documents. The resolver MUST honestly
    return MISSING for them — never fabricate a record."""
    g = _run(loop, compose_graph(db, snort_incident))
    node = g["nodes"][0]
    checked = 0
    for ref in node["source_refs"]:
        if ref.startswith(("canonical:", "incident:", "mapping:",
                                    "match:", "obs:")):
            continue
        checked += 1
        r = _run(loop, resolve(db, ref))
        assert r["state"] == "MISSING", \
            f"KB reference {ref!r} MUST be honest MISSING, not fabricated"
    assert checked > 0, "at least one non-canonical KB ref expected"


def test_resolver_is_deterministic(loop, db, snort_incident):
    inc = _run(loop, db["workspace_cases"].find_one(
        {"id": snort_incident}, {"_id": 0}))
    ce_id = (inc.get("xdr_pipeline") or {}).get("canonical_event_id")
    a = _run(loop, resolve(db, ce_id))
    b = _run(loop, resolve(db, ce_id))
    assert json.dumps(a["document"],       sort_keys=True) == \
                json.dumps(b["document"],       sort_keys=True)
    assert json.dumps(a["missing_fields"], sort_keys=True) == \
                json.dumps(b["missing_fields"], sort_keys=True)


def test_every_graph_evidence_id_resolves(loop, db, snort_incident):
    """Evidence Traversability Invariant: every evidence_id cited by
    a node MUST resolve deterministically."""
    g = _run(loop, compose_graph(db, snort_incident))
    unresolved = []
    for node in g["nodes"]:
        for eid in node["evidence_ids"]:
            r = _run(loop, resolve(db, eid))
            if r["state"] != "READY":
                unresolved.append((node["id"], eid))
    assert unresolved == [], \
        f"unresolved evidence pointers: {unresolved}"


def test_telemetry_neutrality_never_requires_command_line(loop, db,
                                                                                snort_incident):
    """Telemetry Neutrality: pure network telemetry must NOT trigger
    a hard failure for missing command_line — the resolver renders
    the record honestly with the field flagged absent."""
    inc = _run(loop, db["workspace_cases"].find_one(
        {"id": snort_incident}, {"_id": 0}))
    ce_id = (inc.get("xdr_pipeline") or {}).get("canonical_event_id")
    r = _run(loop, resolve(db, ce_id))
    assert r["state"] == "READY"          # never fails
    # The document itself does NOT carry an invented process.command_line.
    doc = r["document"]
    assert (doc.get("process") or {}).get("command_line") is None
