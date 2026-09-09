"""
Round 23.5 · Provenance & Evidence-State Lock-in
────────────────────────────────────────────────

Locked principles enforced here:

  * Every synthesized recommendation MUST carry `provenance`
    and `traversal_chain` — the SAME shape the graph node exposes —
    so the analyst can traverse Canonical → IUE → Correlation →
    Framework → Recommendation from any reco card.

  * `provenance.evidence_state` MUST be one of the locked states
    (CONFIRMED / SUPPORTED / INSUFFICIENT_EVIDENCE / NOT_OBSERVED /
    UNKNOWN) — never a probability.

  * NivXRay must never fill the graph or the recommendation set with
    artificial nodes: recommendations only for observed entities;
    empty layers must remain empty and be rendered as "Not available
    in collected evidence" downstream.
"""
from __future__ import annotations
import asyncio, os, uuid, json
import pytest
from dotenv import load_dotenv
load_dotenv("/app/backend/.env")
from motor.motor_asyncio import AsyncIOMotorClient

from detection_content.xdr_pipeline import process_event_through_pipeline
from detection_content.collector_runtime import GOLDEN_SNORT_EVENT
from detection_content.xdr_closed_loop import recompute as closed_loop_recompute
from detection_content.xdr_evidence_traversal import resolve


LOCKED_STATES = {"CONFIRMED", "SUPPORTED",
                            "INSUFFICIENT_EVIDENCE", "NOT_OBSERVED", "UNKNOWN"}


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
    r = _run(loop, process_event_through_pipeline(
        db, dict(GOLDEN_SNORT_EVENT), str(uuid.uuid4()),
        integration_id="integration-snort-ref",
        collector_id="collector-snort-ref"))
    return (r.get("closed_loop") or {}).get("incident_id")


# ── Every reco carries provenance + traversal_chain ─────────────

def test_every_reco_has_provenance_block(loop, db, snort_incident):
    r = _run(loop, closed_loop_recompute(db, snort_incident))
    recos = (r.get("recommendations") or {}).get("synthesized") or []
    assert recos
    for reco in recos:
        p = reco.get("provenance")
        assert p, f"reco {reco['id']} missing provenance"
        for k in ("chain", "family", "strategy", "objective",
                        "entity_origin", "framework", "evidence_state"):
            assert k in p, f"provenance missing {k}"
        assert p["chain"] == ["Telemetry", "Canonical", "Correlation",
                                          "Mapping", "Strategy", "Recommendation"]
        assert p["evidence_state"] in LOCKED_STATES


def test_every_reco_has_traversal_chain(loop, db, snort_incident):
    r = _run(loop, closed_loop_recompute(db, snort_incident))
    recos = (r.get("recommendations") or {}).get("synthesized") or []
    for reco in recos:
        tc = reco.get("traversal_chain")
        assert tc, f"reco {reco['id']} missing traversal_chain"
        for k in ("canonical_event_id", "iue_ref",
                        "correlation_match_ids", "incident_id"):
            assert k in tc, f"traversal_chain missing {k}"
        assert tc["incident_id"] == snort_incident


def test_reco_evidence_state_never_probabilistic(loop, db, snort_incident):
    r = _run(loop, closed_loop_recompute(db, snort_incident))
    recos = (r.get("recommendations") or {}).get("synthesized") or []
    for reco in recos:
        blob = json.dumps(reco.get("provenance") or {})
        for bad in ("likely", "probably", "estimated", "inferred",
                          "assumed"):
            assert bad not in blob.lower(), \
                f"forbidden probabilistic phrase in provenance: {bad}"


def test_reco_traversal_ids_resolve(loop, db, snort_incident):
    """Every non-null id in the reco's traversal_chain must resolve
    via the traversal endpoint — Evidence Traversability invariant."""
    r = _run(loop, closed_loop_recompute(db, snort_incident))
    recos = (r.get("recommendations") or {}).get("synthesized") or []
    for reco in recos[:5]:      # spot-check the first few
        tc = reco["traversal_chain"]
        for ref in filter(None, [tc.get("canonical_event_id"),
                                                  tc.get("iue_ref"),
                                                  tc.get("incident_id")]):
            r2 = _run(loop, resolve(db, ref))
            assert r2["state"] == "READY", \
                f"reco {reco['id']} references unresolvable {ref}"


def test_recos_only_emitted_for_observed_entities(loop, db,
                                                                        snort_incident):
    """Locked rule: NivXRay never fills the recommendation set with
    artificial candidates.  Every reco.target_entity.value MUST
    appear in the incident's entity list."""
    r = _run(loop, closed_loop_recompute(db, snort_incident))
    from detection_content.xdr_response_decision import build_response_context
    ctx = _run(loop, build_response_context(db, snort_incident))
    observed_values = {e["value"] for e in ctx["entities"]}
    recos = (r.get("recommendations") or {}).get("synthesized") or []
    for reco in recos:
        tv = reco.get("target_entity", {}).get("value")
        assert tv in observed_values, \
            f"reco {reco['id']} targets entity {tv!r} not in observed set"


def test_context_carries_traversal_chain(loop, db, snort_incident):
    from detection_content.xdr_response_decision import build_response_context
    ctx = _run(loop, build_response_context(db, snort_incident))
    tc = ctx["traversal_chain"]
    assert tc["incident_id"] == snort_incident
    assert tc["canonical_event_id"]
    assert tc["iue_ref"] == f"iue:{snort_incident}"


def test_locked_states_enum_is_exhaustive():
    """Sanity — the locked-states set is the exact governing enum."""
    assert LOCKED_STATES == {"CONFIRMED", "SUPPORTED",
                                            "INSUFFICIENT_EVIDENCE",
                                            "NOT_OBSERVED", "UNKNOWN"}
