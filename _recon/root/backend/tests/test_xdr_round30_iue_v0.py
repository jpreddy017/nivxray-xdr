"""Round 30 · IUE v0 · Investigation Understanding Engine regression.

Guarantees (owner-locked AUTONOMOUS_INVESTIGATION.md §15):
  * Six understanding artifacts materialise from a real pipeline
    incident (Snort golden).
  * Every artifact is deterministic — two runs on the same governed
    evidence yield identical ``content_hash`` and ``evidence_fingerprint``.
  * ``NOT_OBSERVED`` and ``UNKNOWN`` states are emitted honestly for
    facts the pipeline cannot observe.
  * ``xdr_iue_understanding`` never accumulates duplicate snapshots
    for the same evidence fingerprint.
  * ``latest_valid`` returns the correct snapshot for the current
    governed evidence state.
"""
from __future__ import annotations
import asyncio, os, uuid
import pytest
from dotenv import load_dotenv
load_dotenv("/app/backend/.env")
from motor.motor_asyncio import AsyncIOMotorClient

from detection_content.xdr_pipeline import process_event_through_pipeline
from detection_content.collector_runtime import GOLDEN_SNORT_EVENT
from services.iue.service import IUEService, UNDERSTANDING_COLLECTION


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
    """Fire the deterministic Snort-golden pipeline exactly once and
    return the incident id it materialised."""
    r = _run(loop, process_event_through_pipeline(
        db, dict(GOLDEN_SNORT_EVENT), str(uuid.uuid4()),
        integration_id="integration-snort-ref",
        collector_id="collector-snort-ref"))
    inc = r.get("incident") or {}
    assert inc.get("created"), (
        f"Snort-golden pipeline did not materialise an incident: {r}")
    return inc["incident_id"]


# ── 1 · six artifacts materialise ────────────────────────────────────
def test_understand_incident_emits_all_six_artifacts(loop, db, incident_id):
    rec = _run(loop, IUEService.understand_incident(db, incident_id))
    assert rec.incident_id == incident_id
    art = rec.artifacts
    # All six understanding artifacts are populated (never omitted).
    assert art.context is not None
    assert art.relationships is not None
    assert art.threat_context is not None
    assert art.historical_context is not None
    assert art.known_unknown is not None
    assert art.gaps is not None


def test_context_carries_real_pipeline_entities(loop, db, incident_id):
    rec = _run(loop, IUEService.understand_incident(db, incident_id))
    ctx = rec.artifacts.context
    # Snort golden carries an alert with src/dst IPs + signature id.
    assert ctx.canonical_event_id, "context missing canonical_event_id"
    assert len(ctx.entities) > 0
    kinds = {e.kind for e in ctx.entities}
    assert ("ipv4" in kinds) or ("ipv6" in kinds), (
        f"expected network entity in context, got kinds={kinds}")
    assert "signature" in kinds
    assert ctx.severity_band in ("INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL")
    # Verdict fields present because the pipeline gate materialised the incident.
    assert ctx.verdict_label in ("malicious", "suspicious")


def test_relationships_are_evidence_anchored(loop, db, incident_id):
    rec = _run(loop, IUEService.understand_incident(db, incident_id))
    edges = rec.artifacts.relationships.edges
    assert len(edges) > 0
    # Every edge must carry an evidence_ref — never fabricated.
    for e in edges:
        assert e.evidence_ref, f"edge missing evidence_ref: {e}"
        assert e.relation in {
            "COMMUNICATES_WITH", "TRIGGERS", "CONTAINS",
            "RESOLVES_TO", "TARGETS", "OBSERVED_ON", "ATTRIBUTED_TO",
        }, f"unexpected relation: {e.relation}"


def test_threat_context_has_signature_from_evidence(loop, db, incident_id):
    rec = _run(loop, IUEService.understand_incident(db, incident_id))
    tc = rec.artifacts.threat_context
    assert len(tc.signatures) >= 1
    # Signatures are read-only projections of canonical evidence.
    assert all(s.signature_id for s in tc.signatures)


def test_known_unknown_emits_honest_negatives(loop, db, incident_id):
    """Snort-golden is a network-only alert.  IUE must emit
    NOT_OBSERVED for endpoint facts (host, user, process) rather
    than fabricate or omit them."""
    rec = _run(loop, IUEService.understand_incident(db, incident_id))
    ku = rec.artifacts.known_unknown
    all_keys = {f.key for f in ku.observed + ku.not_observed + ku.unknown}
    for endpoint_key in ("host.name", "user.name", "process.name"):
        assert endpoint_key in all_keys, (
            f"IUE must emit endpoint fact {endpoint_key} even when absent")
    neg_keys = {f.key for f in ku.not_observed}
    assert "process.name" in neg_keys or "user.name" in neg_keys, (
        "Endpoint absence must be honestly emitted as NOT_OBSERVED, "
        "not omitted or invented.")


def test_gaps_are_derived_from_known_unknown(loop, db, incident_id):
    rec = _run(loop, IUEService.understand_incident(db, incident_id))
    gaps = rec.artifacts.gaps.gaps
    assert len(gaps) > 0
    # Every gap must have a deterministic id + suggested capability.
    for g in gaps:
        assert g.gap_id.startswith("gap_")
        assert g.suggested_capability in {
            "process_ancestry", "network_pivot", "identity_pivot",
            "file_reputation", "historical_correlation", "mitre_expansion",
        }


# ── 2 · determinism ──────────────────────────────────────────────────
def test_two_runs_yield_identical_content_hash(loop, db, incident_id):
    a = _run(loop, IUEService.understand_incident(db, incident_id))
    b = _run(loop, IUEService.understand_incident(db, incident_id))
    assert a.content_hash == b.content_hash, (
        f"IUE v0 must be deterministic — same evidence, same hash. "
        f"got {a.content_hash} != {b.content_hash}")
    assert a.evidence_fingerprint == b.evidence_fingerprint
    assert a.version == b.version, (
        "Deterministic snapshot must not create a new version when "
        "the evidence fingerprint has not changed.")


# ── 3 · persistence contract ─────────────────────────────────────────
def test_snapshot_persisted_with_stable_fingerprint(loop, db, incident_id):
    _run(loop, IUEService.understand_incident(db, incident_id))
    _run(loop, IUEService.understand_incident(db, incident_id))
    # Count snapshots for this incident.
    async def _count():
        return await db[UNDERSTANDING_COLLECTION].count_documents(
            {"incident_id": incident_id})
    count = _run(loop, _count())
    assert count == 1, (
        f"Same governed evidence must produce exactly ONE persisted "
        f"snapshot; got {count}. Duplicate snapshots break the "
        f"'latest valid' contract.")


def test_latest_valid_resolves_to_current_state(loop, db, incident_id):
    rec = _run(loop, IUEService.understand_incident(db, incident_id))
    latest = _run(loop, IUEService.latest_valid(db, incident_id))
    assert latest is not None
    assert latest.content_hash == rec.content_hash
    assert latest.evidence_fingerprint == rec.evidence_fingerprint


# ── 4 · missing / invalid incident ───────────────────────────────────
def test_missing_incident_raises(loop, db):
    with pytest.raises(ValueError, match="incident_not_found"):
        _run(loop, IUEService.understand_incident(db, "inc_does_not_exist"))


def test_latest_valid_returns_none_for_missing(loop, db):
    latest = _run(loop, IUEService.latest_valid(db, "inc_missing_xxx"))
    assert latest is None
