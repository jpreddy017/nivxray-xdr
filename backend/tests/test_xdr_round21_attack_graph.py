"""
Round 21 · Evidence-First ATT&CK Attack-Chain Graph
────────────────────────────────────────────────────

Enforces the Evidence-First Deterministic Principle:
  * Every node is emitted from a real framework mapping.
  * Every edge is emitted only when two nodes share an entity or
    a canonical evidence reference.
  * Confidence is a STATE (CONFIRMED / SUPPORTED / INSUFFICIENT_EVIDENCE
    / NOT_OBSERVED / UNKNOWN) — never a probability.
  * Same evidence → byte-identical output (deterministic).
"""
from __future__ import annotations
import asyncio, os, uuid, json
import pytest
from dotenv import load_dotenv
load_dotenv("/app/backend/.env")
from motor.motor_asyncio import AsyncIOMotorClient

from detection_content.xdr_attack_chain_graph import (
    compose, CONFIRMED, SUPPORTED, INSUFFICIENT_EVIDENCE,
    NOT_OBSERVED, UNKNOWN, TACTIC_ORDER,
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


# ── Contract ────────────────────────────────────────────────────

def test_graph_missing_for_unknown_incident(loop, db):
    r = _run(loop, compose(db, "inc_does_not_exist"))
    assert r["state"] == "MISSING"


def test_graph_ready_for_real_incident(loop, db, snort_incident):
    r = _run(loop, compose(db, snort_incident))
    assert r["state"] == "READY"
    assert r["engine_id"].endswith("attack_chain_graph")
    assert r["confidence_enum"] == [CONFIRMED, SUPPORTED,
                                                    INSUFFICIENT_EVIDENCE,
                                                    NOT_OBSERVED, UNKNOWN]
    assert r["tactic_order"] == TACTIC_ORDER


def test_every_node_has_evidence_first_shape(loop, db, snort_incident):
    r = _run(loop, compose(db, snort_incident))
    assert r["nodes"], "Snort golden event produces at least one node"
    for n in r["nodes"]:
        # Locked node shape.
        for k in ("id", "kind", "tactic", "confidence",
                        "why_mapped", "mapping_method", "source_refs",
                        "entities", "telemetry_sources", "evidence_ids"):
            assert k in n, f"node missing {k}: {n}"
        assert n["confidence"] in (CONFIRMED, SUPPORTED,
                                                  INSUFFICIENT_EVIDENCE,
                                                  NOT_OBSERVED, UNKNOWN)
        # NO probability, NO "likely", NO percentage.
        joined = json.dumps(n)
        for bad in ("likely", "probably", "estimated"):
            assert bad not in joined.lower(), \
                f"forbidden probabilistic phrase in node: {bad}"


def test_every_edge_has_proof_reason(loop, db, snort_incident):
    r = _run(loop, compose(db, snort_incident))
    for e in r["edges"]:
        assert e["source"] and e["target"]
        assert e.get("proof"), f"edge without proof: {e}"
        assert e["proof"].get("reason") in ("shared_entity",
                                                                "shared_evidence")


def test_graph_is_deterministic(loop, db, snort_incident):
    a = _run(loop, compose(db, snort_incident))
    b = _run(loop, compose(db, snort_incident))
    for key in ("nodes", "edges", "counts"):
        assert json.dumps(a[key], sort_keys=True) == \
                    json.dumps(b[key], sort_keys=True), key


def test_snort_graph_contains_c2_technique(loop, db, snort_incident):
    r = _run(loop, compose(db, snort_incident))
    tactics = {n["tactic"] for n in r["nodes"]}
    assert "command-and-control" in tactics, tactics


def test_confidence_never_probability(loop, db, snort_incident):
    r = _run(loop, compose(db, snort_incident))
    for n in r["nodes"]:
        assert isinstance(n["confidence"], str)
        assert not any(ch.isdigit() for ch in n["confidence"])


def test_telemetry_source_is_not_command_line_assumed(loop, db,
                                                                            snort_incident):
    """Command-line MUST NOT be an assumed source. Verify the
    telemetry_sources come from real canonical.source.vendor/product."""
    r = _run(loop, compose(db, snort_incident))
    for n in r["nodes"]:
        for src in n["telemetry_sources"]:
            assert "command" not in src.lower() \
                or "snort" in src.lower(), \
                f"command-line assumption in telemetry: {src}"


def test_honesty_note_is_present(loop, db, snort_incident):
    r = _run(loop, compose(db, snort_incident))
    assert "probability" in r["honesty_note"].lower() or \
                "state" in r["honesty_note"].lower()
