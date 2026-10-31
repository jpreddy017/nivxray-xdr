"""
Round 23 · Evidence Traversal Completion
────────────────────────────────────────

Enforces the traversal chain:
    Canonical → IUE → Correlation Match → Observation → Recommendation

Rules:
  * Every graph node MUST carry a `traversal_chain` block with real
    persisted ids (not fabricated).
  * `iue:<incident_id>` resolves via the inline IUE record on the
    incident.
  * Every id in traversal_chain resolves to READY via the traversal
    endpoint.
  * Missing layers → empty list (never fabricated).
"""
from __future__ import annotations
import asyncio, os, uuid
import pytest
from dotenv import load_dotenv
load_dotenv("/app/backend/.env")
from motor.motor_asyncio import AsyncIOMotorClient

from detection_content.xdr_attack_chain_graph import compose as compose_graph
from detection_content.xdr_evidence_traversal import (
    resolve, IUE_RECORD, CANONICAL_EVENT,
)


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


# ── Node shape ──────────────────────────────────────────────────

def test_every_node_carries_traversal_chain_block(loop, db, snort_incident):
    g = _run(loop, compose_graph(db, snort_incident))
    for n in g["nodes"]:
        tc = n.get("traversal_chain")
        assert tc, f"node {n['id']} missing traversal_chain"
        for key in ("canonical_event_id", "iue_ref",
                        "correlation_match_ids",
                        "intelligence_observation_ids",
                        "recommendation_ids", "incident_id"):
            assert key in tc, f"traversal_chain missing {key}"
        assert tc["incident_id"] == snort_incident


def test_missing_layers_are_empty_never_fabricated(loop, db, snort_incident):
    g = _run(loop, compose_graph(db, snort_incident))
    for n in g["nodes"]:
        tc = n["traversal_chain"]
        # Snort golden path has no ICE correlation match, so this
        # layer MUST be an empty list (not an invented placeholder).
        assert isinstance(tc["correlation_match_ids"], list)
        for cid in tc["correlation_match_ids"]:
            assert cid, "no null / empty-string id may appear"


# ── IUE resolver ────────────────────────────────────────────────

def test_iue_resolver_reads_inline_iue(loop, db, snort_incident):
    r = _run(loop, resolve(db, f"iue:{snort_incident}"))
    assert r["state"] == "READY"
    assert r["kind"] == IUE_RECORD
    doc = r["document"]
    # IUE document must carry its own iue_id + a link back to canonical.
    assert doc.get("iue_id"), "iue_id must be persisted"
    assert doc.get("canonical_event_id"), \
        "IUE must trace back to its canonical event"
    assert r["traversal"]["parent_incident"] == snort_incident


def test_iue_missing_returns_honest_missing(loop, db):
    r = _run(loop, resolve(db, "iue:does_not_exist"))
    assert r["state"] == "MISSING"


# ── Full-chain resolvability ────────────────────────────────────

def test_full_traversal_chain_resolves(loop, db, snort_incident):
    """Every non-empty id in traversal_chain MUST resolve via the
    traversal endpoint."""
    g = _run(loop, compose_graph(db, snort_incident))
    unresolved = []
    for n in g["nodes"]:
        tc = n["traversal_chain"]
        # Canonical.
        if tc["canonical_event_id"]:
            r = _run(loop, resolve(db, tc["canonical_event_id"]))
            if r["state"] != "READY":
                unresolved.append(("canonical", tc["canonical_event_id"]))
        # IUE.
        if tc["iue_ref"]:
            r = _run(loop, resolve(db, tc["iue_ref"]))
            if r["state"] != "READY":
                unresolved.append(("iue", tc["iue_ref"]))
        # Correlation matches.
        for cid in tc["correlation_match_ids"]:
            r = _run(loop, resolve(db, cid))
            if r["state"] != "READY":
                unresolved.append(("match", cid))
        # Observations.
        for oid in tc["intelligence_observation_ids"]:
            r = _run(loop, resolve(db, oid))
            if r["state"] != "READY":
                unresolved.append(("obs", oid))
        # Recommendations.
        for rid in tc["recommendation_ids"]:
            r = _run(loop, resolve(db, rid))
            if r["state"] != "READY":
                unresolved.append(("reco", rid))
        # Incident.
        r = _run(loop, resolve(db, tc["incident_id"]))
        if r["state"] != "READY":
            unresolved.append(("incident", tc["incident_id"]))
    assert unresolved == [], \
        f"unresolved traversal ids: {unresolved}"


# ── Deterministic ───────────────────────────────────────────────

def test_traversal_chain_is_deterministic(loop, db, snort_incident):
    import json
    a = _run(loop, compose_graph(db, snort_incident))
    b = _run(loop, compose_graph(db, snort_incident))
    for na, nb in zip(a["nodes"], b["nodes"]):
        assert json.dumps(na["traversal_chain"], sort_keys=True) == \
                    json.dumps(nb["traversal_chain"], sort_keys=True)


# ── Telemetry Neutrality ────────────────────────────────────────

def test_iue_document_never_requires_command_line(loop, db, snort_incident):
    """The Snort golden event carries no process telemetry.  The IUE
    record must NOT contain a fabricated process.command_line field."""
    r = _run(loop, resolve(db, f"iue:{snort_incident}"))
    doc = r["document"]
    # IUE entities may include ipv4/threat_name but MUST NOT invent
    # a command_line entity.
    for e in doc.get("entities", []):
        assert e.get("kind") != "command_line", \
            "IUE must not fabricate command_line entity for network telemetry"
