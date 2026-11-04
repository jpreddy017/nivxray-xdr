"""
Phase-2 Final Integration Gate — regression coverage.

Invariants pinned:
  · NarrationKind.CROSS_LANE_STORY exists and every registered
    provider (Cloud/Offline/Deterministic) supports it.
  · Deterministic narrator handles CROSS_LANE_STORY in all three
    coverage states (no cross-lane evidence, single lane,
    multi-lane) without fabricating evidence or promoting ATT&CK.
  · Provider chain: Cloud/Offline fail → deterministic wins.
  · verdict_consumer.record_verdict_inputs_for_incident persists
    inputs + edges, idempotently, with ATT&CK-promotion=False
    baked into every edge's provenance.
  · Persisted docs are stripped of any verdict-authority field
    even if a future bridge refactor leaked one.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from services.narration import (
    NarrationContext, NarrationKind, NarrationRequest,
)
from services.narration.contracts import GenerationMode, GroundingError
from services.narration.gateway import NarrationGateway
from services.narration.providers import (
    CloudLLMProvider, OfflineLLMProvider, DeterministicProvider,
)
from services.telemetry_adapters import (
    build_verdict_inputs, build_evidence_graph_edges, correlate,
    CanonicalEvent, Provenance, SourceKind,
    record_verdict_inputs_for_incident,
)


# ---------- helpers ---------------------------------------------------
def _ev(cid, lane, actor=None, when=None):
    return CanonicalEvent(
        canonical_id=cid, source_kind=SourceKind(lane), action="x",
        actor={"id": actor} if actor else {},
        provenance=Provenance(
            source_id="t", vendor="v", adapter_name="a",
            adapter_version="0.1", raw_ref=cid,
            ingested_at="2026-08-15T00:00:00Z",
            source_event_time=when),
    )


def _ctx(*, lanes=(), cross_lane_ids=(), verdict=None, techniques=()):
    return NarrationContext(
        incident_id    = "inc-xlp-1",
        evidence_ids   = tuple(cross_lane_ids),
        technique_ids  = tuple(techniques),
        verdict        = verdict,
        severity       = "P2" if verdict else None,
        confidence     = 0.75 if verdict else None,
        composer_input = {"cross_lane": {
            "lanes":            list(lanes),
            "cross_lane_ids":   list(cross_lane_ids),
        }},
    )


# ---------- provider surface ------------------------------------------
def test_cross_lane_story_kind_registered():
    assert NarrationKind.CROSS_LANE_STORY.value == "cross_lane_story"


def test_all_providers_declare_support_for_cross_lane_story():
    for prov in (CloudLLMProvider(), OfflineLLMProvider(),
                 DeterministicProvider()):
        assert NarrationKind.CROSS_LANE_STORY in prov.supports, prov.name


# ---------- deterministic narrator honesty ----------------------------
@pytest.mark.asyncio
async def test_deterministic_cross_lane_no_evidence_is_honest():
    prov = DeterministicProvider()
    draft = await prov.draft(NarrationKind.CROSS_LANE_STORY,
                             _ctx(), None)
    assert draft.generation_mode == GenerationMode.DETERMINISTIC
    blob = " ".join(p.text.lower() for p in draft.paragraphs)
    assert "coverage gap" in blob or "coverage-gap" in blob
    # No paragraph cites an evidence id (nothing to cite).
    for p in draft.paragraphs:
        assert p.evidence_ids == ()


@pytest.mark.asyncio
async def test_deterministic_cross_lane_single_lane_stays_honest():
    prov = DeterministicProvider()
    draft = await prov.draft(
        NarrationKind.CROSS_LANE_STORY,
        _ctx(lanes=("endpoint",), cross_lane_ids=("ep-1",)),
        None,
    )
    blob = " ".join(p.text.lower() for p in draft.paragraphs)
    assert "single-lane" in blob or "endpoint lane only" in blob
    assert "verdict engine" in blob


@pytest.mark.asyncio
async def test_deterministic_cross_lane_multi_lane_cites_ids_only():
    prov = DeterministicProvider()
    ids = ("ep-1", "id-1", "cl-1")
    draft = await prov.draft(
        NarrationKind.CROSS_LANE_STORY,
        _ctx(lanes=("endpoint","identity","cloud"),
             cross_lane_ids=ids, verdict="SUSPICIOUS",
             techniques=("T1078",)),
        None,
    )
    # Verdict/severity/confidence echoed verbatim.
    assert draft.verdict     == "SUSPICIOUS"
    assert draft.severity    == "P2"
    assert draft.confidence  == 0.75
    # The multi-lane paragraph cites all governed evidence ids.
    citing = [p for p in draft.paragraphs if p.evidence_ids]
    assert citing, "expected at least one paragraph to cite evidence ids"
    for p in citing:
        for eid in p.evidence_ids:
            assert eid in ids
    blob = " ".join(p.text.lower() for p in draft.paragraphs)
    assert "not maliciousness" in blob
    assert "verdict engine" in blob


# ---------- gateway fallback with providers all failing except deterministic
class _FailingProvider:
    name = "cloud:failing"
    kind = "cloud"
    supports = {NarrationKind.CROSS_LANE_STORY}

    async def draft(self, kind, context, session_id):
        raise GroundingError("simulated failure")


@pytest.mark.asyncio
async def test_gateway_falls_back_to_deterministic_for_cross_lane():
    gw = NarrationGateway(
        providers={
            "cloud":         _FailingProvider(),
            "deterministic": DeterministicProvider(),
        },
        order=("cloud", "deterministic"),
    )
    result = await gw.render(NarrationRequest(
        kind    = NarrationKind.CROSS_LANE_STORY,
        context = _ctx(lanes=("endpoint","identity"),
                       cross_lane_ids=("ep-1","id-1")),
    ))
    assert result.generation_mode == GenerationMode.DETERMINISTIC
    assert result.provider == "deterministic"
    assert result.grounded is True


# ---------- verdict_consumer persistence -------------------------------
class _FakeCollection:
    def __init__(self):
        self.docs: list[dict] = []
    async def update_one(self, key, update, upsert=False):
        d = dict(update.get("$set") or {})
        # Idempotent behaviour — replace existing doc with same key.
        for i, existing in enumerate(self.docs):
            if all(existing.get(k) == v for k, v in key.items()):
                self.docs[i] = {**existing, **d}
                return
        if upsert:
            self.docs.append({**key, **d})


class _FakeDB:
    def __init__(self):
        self.colls: dict[str, _FakeCollection] = {}
    def __getitem__(self, name):
        return self.colls.setdefault(name, _FakeCollection())


def _sample_groups():
    evs = [
        _ev("ep-1", "endpoint", actor="alice", when="2026-08-15T10:00:00Z"),
        _ev("id-1", "identity", actor="alice", when="2026-08-15T10:05:00Z"),
        _ev("cl-1", "cloud",    actor="alice", when="2026-08-15T10:10:00Z"),
    ]
    return correlate(evs)


@pytest.mark.asyncio
async def test_verdict_consumer_persists_inputs_and_edges():
    db = _FakeDB()
    groups = _sample_groups()
    inputs = build_verdict_inputs(groups)
    edges  = build_evidence_graph_edges(groups)
    summary = await record_verdict_inputs_for_incident(
        db, "inc-77", inputs, edges,
    )
    assert summary["incident_id"] == "inc-77"
    assert summary["stored_inputs"] == 1
    assert summary["stored_edges"]  == 2       # hub-and-spoke → n-1 edges
    assert summary["authority"] == "existing-verdict-engine"
    assert summary["attck_promotion"] is False
    # Docs persisted
    assert len(db["xdr_verdict_inputs"].docs)        == 1
    assert len(db["xdr_evidence_graph_edges"].docs)  == 2
    # Every persisted edge asserts attck_promotion=False.
    for e in db["xdr_evidence_graph_edges"].docs:
        assert e["provenance"]["attck_promotion"] is False


@pytest.mark.asyncio
async def test_verdict_consumer_is_idempotent_on_rerun():
    db = _FakeDB()
    groups = _sample_groups()
    inputs = build_verdict_inputs(groups)
    edges  = build_evidence_graph_edges(groups)
    for _ in range(3):
        await record_verdict_inputs_for_incident(
            db, "inc-77", inputs, edges,
        )
    # Idempotent — same natural key each run.
    assert len(db["xdr_verdict_inputs"].docs)       == 1
    assert len(db["xdr_evidence_graph_edges"].docs) == 2


@pytest.mark.asyncio
async def test_verdict_consumer_strips_verdict_authority_fields():
    db = _FakeDB()
    # Simulate a bridge leak — pretend to hand a VerdictInput-shape
    # dict that carries verdict-authority fields.
    leaked = SimpleNamespace(
        __dataclass_fields__={"__fake__": None},  # not a real dataclass
    )
    tainted = {
        "kind": "cross_lane_correlation",
        "correlation_key": "k1",
        "verdict":              "MALICIOUS",
        "severity":             "P1",
        "maliciousness":        0.99,
        "verdict_confidence":   0.99,
        "attck_promote":        True,
    }
    await record_verdict_inputs_for_incident(
        db, "inc-77", [tainted], [],
    )
    stored = db["xdr_verdict_inputs"].docs[0]
    for forbidden in ("verdict", "severity", "maliciousness",
                      "verdict_confidence", "attck_promote"):
        assert forbidden not in stored, (
            f"leaked field {forbidden!r} was not stripped")


@pytest.mark.asyncio
async def test_verdict_consumer_requires_incident_id():
    db = _FakeDB()
    with pytest.raises(ValueError):
        await record_verdict_inputs_for_incident(db, "", [], [])


# ---------- LLM prompt honesty guard for CROSS_LANE_STORY --------------
def test_cross_lane_llm_prompt_forbids_cross_lane_claim_when_no_evidence():
    """When lanes_observed<2 or no cross-lane ids, the prompt MUST
    include an explicit HONESTY_RULES clause forbidding the LLM
    from asserting multi-lane correlation.  This prevents the
    cloud LLM from hallucinating correlation on coverage-gap
    incidents (real regression observed by the testing agent)."""
    import json as _json
    from services.narration.providers import _build_llm_user_prompt
    # Zero lanes / zero cross-lane evidence.
    prompt_empty = _build_llm_user_prompt(
        NarrationKind.CROSS_LANE_STORY, _ctx())
    parsed_empty = _json.loads(prompt_empty)
    assert parsed_empty["lanes_observed"] == []
    assert parsed_empty["cross_lane_evidence_count"] == 0
    assert any("MUST NOT assert" in r or "coverage gap" in r
               for r in parsed_empty["HONESTY_RULES"])
    # Single-lane only.
    prompt_single = _build_llm_user_prompt(
        NarrationKind.CROSS_LANE_STORY,
        _ctx(lanes=("endpoint",), cross_lane_ids=("ep-1",)))
    parsed_single = _json.loads(prompt_single)
    assert any("MUST NOT assert" in r
               for r in parsed_single["HONESTY_RULES"])
    # Multi-lane — rule flips to the "you may narrate" variant.
    prompt_multi = _build_llm_user_prompt(
        NarrationKind.CROSS_LANE_STORY,
        _ctx(lanes=("endpoint","identity"),
             cross_lane_ids=("ep-1","id-1")))
    parsed_multi = _json.loads(prompt_multi)
    joined = " ".join(parsed_multi["HONESTY_RULES"])
    assert "ONLY across the lanes listed" in joined
    assert "NEVER verdict confidence" in joined
    assert "NEVER promotes an ATT&CK technique" in joined
