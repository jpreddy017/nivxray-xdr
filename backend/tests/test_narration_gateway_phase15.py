"""
Phase-1.5 integration tests for the NivXRay XDR Narration Gateway
across the three migrated consumers (Executive Summary, Attack
Story, R46 Analyst Overlay, R48 PDF report narration).

Two invariants under test:

  1. **Provider priority transitions** — Cloud → Offline →
     Deterministic under provider failure, credit exhaustion,
     timeout, malformed response, and unavailable runtime.
     The analyst must never see a "narration unavailable" state.

  2. **Semantic invariance across providers** — the same
     `NarrationContext` produces the same governed facts
     (`evidence_ids`, `finding_ids`, `technique_ids`, `entities`,
     `verdict`, `severity`, `confidence`, `provenance`)
     regardless of which provider produced the prose.  Only
     wording may differ.
"""
from __future__ import annotations

import asyncio
import pytest

from services.narration import (
    GenerationMode, NarrationContext, NarrationKind, NarrationRequest,
)
from services.narration.contracts import (
    GroundingError, NarrationParagraph,
)
from services.narration.gateway import NarrationGateway
from services.narration.providers import (
    DeterministicProvider, NarrationDraft,
)


KINDS = [
    NarrationKind.EXECUTIVE_SUMMARY,
    NarrationKind.ATTACK_STORY,
    NarrationKind.R46_OVERLAY_SUMMARY,
    NarrationKind.R48_REPORT_NARRATION,
]


def _ctx():
    return NarrationContext(
        incident_id    = "phase15-inc-1",
        evidence_ids   = ("EV-1", "EV-2", "EV-3"),
        finding_ids    = ("FND-1",),
        technique_ids  = ("T1059.001", "T1105", "T1027.010"),
        entities       = ("HOST-01", "user@corp"),
        verdict        = "MALICIOUS",
        severity       = "P1",
        confidence     = 0.88,
        provenance     = ({"source": "workspace_cases"},),
    )


class _FakeProvider:
    def __init__(self, name, kind, draft=None, exc=None,
                          supports=None):
        self.name  = name
        self.kind  = kind
        self._draft = draft
        self._exc   = exc
        self.calls  = 0
        self.supports = supports or set(KINDS)
    async def draft(self, kind, context, session_id):
        self.calls += 1
        if self._exc is not None:
            raise self._exc
        # Adapt the fixed draft to the requested kind so the
        # grounding validator still passes.
        d = self._draft
        return d


def _valid_draft(ctx, mode):
    return NarrationDraft(
        paragraphs = [
            NarrationParagraph(
                text          = "prose 1",
                evidence_ids  = tuple(ctx.evidence_ids),
                technique_ids = tuple(ctx.technique_ids[:2]),
            ),
            NarrationParagraph(text = "prose 2"),
        ],
        verdict         = ctx.verdict,
        severity        = ctx.severity,
        confidence      = ctx.confidence,
        entities        = tuple(ctx.entities),
        generation_mode = mode,
    )


# ---------- 1. Provider-priority chain transitions --------------------
@pytest.mark.asyncio
@pytest.mark.parametrize("kind", KINDS)
async def test_cloud_credit_exhaustion_falls_to_offline(kind):
    ctx = _ctx()
    cloud   = _FakeProvider("cloud",   "cloud",
                                              exc=RuntimeError("402 credits exhausted"))
    offline = _FakeProvider("offline", "offline",
                                              draft=_valid_draft(ctx, GenerationMode.LLM_OFFLINE))
    gw = NarrationGateway(
        providers={"cloud": cloud, "offline": offline,
                          "deterministic": DeterministicProvider()},
        order=("cloud", "offline", "deterministic"),
    )
    out = await gw.render(NarrationRequest(kind=kind, context=ctx))
    assert out.provider == "offline"
    assert out.generation_mode == GenerationMode.LLM_OFFLINE
    assert "cloud" in out.fallback_chain[0]


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", KINDS)
async def test_cloud_timeout_offline_unavailable_falls_to_deterministic(kind):
    ctx = _ctx()
    cloud   = _FakeProvider("cloud",   "cloud",
                                              exc=asyncio.TimeoutError("timeout"))
    offline = _FakeProvider("offline", "offline",
                                              exc=RuntimeError("ollama runtime absent"))
    gw = NarrationGateway(
        providers={"cloud": cloud, "offline": offline,
                          "deterministic": DeterministicProvider()},
        order=("cloud", "offline", "deterministic"),
    )
    out = await gw.render(NarrationRequest(kind=kind, context=ctx))
    assert out.provider == "deterministic"
    assert out.generation_mode == GenerationMode.DETERMINISTIC
    assert out.text.strip() != ""


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", KINDS)
async def test_cloud_malformed_response_falls_through(kind):
    """Malformed LLM output (e.g. non-dict paragraphs) must be
    caught by the grounding validator, not surfaced to the
    analyst."""
    ctx = _ctx()
    bad_draft = NarrationDraft(
        paragraphs=[NarrationParagraph(text="bogus",
                                                                evidence_ids=("EV-INVENTED",))],
        verdict=ctx.verdict, severity=ctx.severity,
        confidence=ctx.confidence, entities=tuple(ctx.entities),
        generation_mode=GenerationMode.LLM_CLOUD,
    )
    cloud = _FakeProvider("cloud", "cloud", draft=bad_draft)
    gw = NarrationGateway(
        providers={"cloud": cloud,
                          "deterministic": DeterministicProvider()},
        order=("cloud", "deterministic"),
    )
    out = await gw.render(NarrationRequest(kind=kind, context=ctx))
    assert out.provider == "deterministic"
    assert any("EV-INVENTED" in c or "not present" in c
                     for c in out.caveats)


# ---------- 2. Semantic invariance across providers -------------------
@pytest.mark.asyncio
@pytest.mark.parametrize("kind", KINDS)
async def test_same_governed_facts_across_providers(kind):
    ctx = _ctx()
    cloud   = _FakeProvider("cloud",   "cloud",
                                              draft=_valid_draft(ctx, GenerationMode.LLM_CLOUD))
    offline = _FakeProvider("offline", "offline",
                                              draft=_valid_draft(ctx, GenerationMode.LLM_OFFLINE))
    gw = NarrationGateway(
        providers={"cloud": cloud, "offline": offline,
                          "deterministic": DeterministicProvider()},
        order=("cloud", "offline", "deterministic"),
    )
    a = await gw.render(NarrationRequest(
        kind=kind, context=ctx, preferred_provider="cloud"))
    b = await gw.render(NarrationRequest(
        kind=kind, context=ctx, preferred_provider="offline"))
    c = await gw.render(NarrationRequest(
        kind=kind, context=ctx, preferred_provider="deterministic"))
    for out in (a, b, c):
        assert out.evidence_ids   == ctx.evidence_ids
        assert out.finding_ids    == ctx.finding_ids
        assert out.technique_ids  == ctx.technique_ids
        assert out.verdict        == ctx.verdict
        assert out.severity       == ctx.severity
        assert out.confidence     == ctx.confidence
        assert out.provenance     == ctx.provenance
    assert {a.provider, b.provider, c.provider} == {
        "cloud", "offline", "deterministic",
    }


# ---------- 3. Guaranteed baseline supports every migrated kind -------
@pytest.mark.asyncio
@pytest.mark.parametrize("kind", KINDS)
async def test_deterministic_baseline_supports_every_migrated_kind(kind):
    d = DeterministicProvider()
    assert kind in d.supports
    out = await d.draft(kind, _ctx(), None)
    assert out.paragraphs
    assert out.generation_mode == GenerationMode.DETERMINISTIC
    # Baseline text must reference governed truth honestly.
    joined = " ".join(p.text for p in out.paragraphs).upper()
    if kind is not NarrationKind.R48_REPORT_NARRATION:
        assert "MALICIOUS" in joined


# ---------- 4. Empty-context honesty across every kind ----------------
@pytest.mark.asyncio
@pytest.mark.parametrize("kind", KINDS)
async def test_deterministic_baseline_stays_honest_with_empty_context(kind):
    d = DeterministicProvider()
    empty = NarrationContext(incident_id="empty-inc")
    out = await d.draft(kind, empty, None)
    joined = " ".join(p.text for p in out.paragraphs).lower()
    if kind is NarrationKind.ATTACK_STORY:
        assert "no att&ck technique" in joined \
                    or "coverage gap" in joined
    if kind is NarrationKind.EXECUTIVE_SUMMARY:
        assert "insufficient evidence" in joined


# ---------- 5. Provider order override never demotes deterministic ----
@pytest.mark.asyncio
async def test_deterministic_always_appended_if_operator_forgets():
    """The gateway MUST always keep the deterministic baseline in
    the chain, even when the operator misconfigures the order."""
    from services.narration.gateway import _parse_order
    order = _parse_order("cloud,offline")           # no deterministic
    assert "deterministic" in order
    assert order[-1] == "deterministic"
