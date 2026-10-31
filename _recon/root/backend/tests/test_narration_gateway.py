"""
Narration Gateway regression suite — Phase 1.

Covers every scenario the directive explicitly requires:

  · Cloud LLM available            → cloud narration
  · Cloud LLM unavailable          → offline narration
  · Cloud + Offline unavailable    → deterministic narration
  · All three configured           → same governed facts across
                                       providers (only wording differs)
  · LLM invents an evidence id     → grounding validator rejects,
                                       gateway falls back
  · LLM inflates confidence /
    promotes verdict / invents
    an entity                       → grounding validator rejects
  · Deterministic narrator NEVER
    fails for supported kinds       → catastrophic-only path
"""
from __future__ import annotations

import pytest

from services.narration import (
    GenerationMode, NarrationContext, NarrationKind,
    NarrationRequest,
)
from services.narration.contracts import NarrationParagraph
from services.narration.gateway import NarrationGateway
from services.narration.providers import (
    DeterministicProvider, NarrationDraft,
)
from services.narration.grounding import (
    validate_machine_truth, validate_paragraphs,
)
from services.narration.contracts import GroundingError


# ---------- helpers ---------------------------------------------------
def _ctx(**overrides):
    base = dict(
        incident_id    = "inc-1",
        evidence_ids   = ("EV-1", "EV-2"),
        finding_ids    = ("FND-1",),
        technique_ids  = ("T1059.001", "T1105"),
        entities       = ("HOST-01", "user@example.com"),
        verdict        = "MALICIOUS",
        severity       = "P1",
        confidence     = 0.9,
        provenance     = ({"source": "workspace_cases"},),
        composer_input = {"incident_id": "inc-1"},
    )
    base.update(overrides)
    return NarrationContext(**base)


class _FakeProvider:
    kind = "cloud"
    supports = {NarrationKind.EXECUTIVE_SUMMARY}
    def __init__(self, name, draft=None, exc=None):
        self.name  = name
        self._draft = draft
        self._exc   = exc
        self.calls  = 0
    async def draft(self, kind, context, session_id):
        self.calls += 1
        if self._exc:
            raise self._exc
        return self._draft


def _valid_draft(ctx, mode=GenerationMode.LLM_CLOUD, name="cloud"):
    return NarrationDraft(
        paragraphs = [
            NarrationParagraph(
                text          = "MALICIOUS P1 — see evidence.",
                evidence_ids  = tuple(ctx.evidence_ids),
                finding_ids   = tuple(ctx.finding_ids),
                technique_ids = tuple(ctx.technique_ids),
            ),
            NarrationParagraph(
                text          = "Affected host: HOST-01.",
            ),
        ],
        verdict         = ctx.verdict,
        severity        = ctx.severity,
        confidence      = ctx.confidence,
        entities        = tuple(ctx.entities),
        generation_mode = mode,
    )


# ---------- 1. Cloud available ----------------------------------------
@pytest.mark.asyncio
async def test_cloud_llm_available_wins():
    ctx = _ctx()
    cloud = _FakeProvider("cloud-fake", draft=_valid_draft(ctx))
    gw = NarrationGateway(
        providers = {"cloud": cloud,
                              "offline": _FakeProvider("offline",
                                                                       exc=RuntimeError("boom")),
                              "deterministic": DeterministicProvider()},
        order = ("cloud", "offline", "deterministic"),
    )
    out = await gw.render(NarrationRequest(
        kind=NarrationKind.EXECUTIVE_SUMMARY, context=ctx))
    assert out.provider == "cloud-fake"
    assert out.generation_mode == GenerationMode.LLM_CLOUD
    assert out.verdict == "MALICIOUS"
    assert out.confidence == 0.9


# ---------- 2. Cloud fails → Offline wins -----------------------------
@pytest.mark.asyncio
async def test_offline_takes_over_when_cloud_errors():
    ctx = _ctx()
    cloud   = _FakeProvider("cloud-fake",   exc=RuntimeError("credits exhausted"))
    offline = _FakeProvider("offline-fake",
                                              draft=_valid_draft(ctx, GenerationMode.LLM_OFFLINE))
    offline.kind = "offline"
    gw = NarrationGateway(
        providers = {"cloud": cloud, "offline": offline,
                              "deterministic": DeterministicProvider()},
        order = ("cloud", "offline", "deterministic"),
    )
    out = await gw.render(NarrationRequest(
        kind=NarrationKind.EXECUTIVE_SUMMARY, context=ctx))
    assert out.provider == "offline-fake"
    assert out.generation_mode == GenerationMode.LLM_OFFLINE
    assert cloud.calls == 1
    assert offline.calls == 1


# ---------- 3. Cloud + Offline fail → Deterministic wins --------------
@pytest.mark.asyncio
async def test_deterministic_always_wins_when_all_llm_fail():
    ctx = _ctx()
    cloud   = _FakeProvider("cloud-fake",   exc=RuntimeError("credits exhausted"))
    offline = _FakeProvider("offline-fake", exc=RuntimeError("ollama offline"))
    offline.kind = "offline"
    gw = NarrationGateway(
        providers = {"cloud": cloud, "offline": offline,
                              "deterministic": DeterministicProvider()},
        order = ("cloud", "offline", "deterministic"),
    )
    out = await gw.render(NarrationRequest(
        kind=NarrationKind.EXECUTIVE_SUMMARY, context=ctx))
    assert out.provider == "deterministic"
    assert out.generation_mode == GenerationMode.DETERMINISTIC
    assert "MALICIOUS" in out.text
    assert out.text.strip() != ""
    # Deterministic narrator does not need an LLM.
    assert cloud.calls == 1 and offline.calls == 1


# ---------- 4. Same governed facts across providers -------------------
@pytest.mark.asyncio
async def test_same_governed_facts_regardless_of_provider():
    ctx = _ctx()
    cloud   = _FakeProvider("cloud",   draft=_valid_draft(ctx, GenerationMode.LLM_CLOUD))
    offline = _FakeProvider("offline", draft=_valid_draft(ctx, GenerationMode.LLM_OFFLINE))
    offline.kind = "offline"

    gw = NarrationGateway(
        providers = {"cloud": cloud, "offline": offline,
                              "deterministic": DeterministicProvider()},
        order = ("cloud", "offline", "deterministic"),
    )
    a = await gw.render(NarrationRequest(
        kind=NarrationKind.EXECUTIVE_SUMMARY, context=ctx,
        preferred_provider="cloud"))
    b = await gw.render(NarrationRequest(
        kind=NarrationKind.EXECUTIVE_SUMMARY, context=ctx,
        preferred_provider="offline"))
    c = await gw.render(NarrationRequest(
        kind=NarrationKind.EXECUTIVE_SUMMARY, context=ctx,
        preferred_provider="deterministic"))

    for out in (a, b, c):
        assert out.evidence_ids   == ctx.evidence_ids
        assert out.finding_ids    == ctx.finding_ids
        assert out.technique_ids  == ctx.technique_ids
        assert out.verdict        == ctx.verdict
        assert out.severity       == ctx.severity
        assert out.confidence     == ctx.confidence
    # Providers used are distinct.
    assert {a.provider, b.provider, c.provider} \
              == {"cloud", "offline", "deterministic"}


# ---------- 5. Grounding validator rejects hallucinated ids -----------
def test_validator_rejects_invented_evidence_id():
    ctx = _ctx()
    bad = [NarrationParagraph(text="x",
                                                    evidence_ids=("EV-99999",))]
    with pytest.raises(GroundingError):
        validate_paragraphs(bad, ctx)


def test_validator_rejects_invented_finding_id():
    ctx = _ctx()
    bad = [NarrationParagraph(text="x", finding_ids=("FND-99",))]
    with pytest.raises(GroundingError):
        validate_paragraphs(bad, ctx)


def test_validator_rejects_invented_technique_id():
    ctx = _ctx()
    bad = [NarrationParagraph(text="x", technique_ids=("T9999",))]
    with pytest.raises(GroundingError):
        validate_paragraphs(bad, ctx)


# ---------- 6. Machine-truth cannot be altered ------------------------
def test_validator_rejects_verdict_promotion():
    ctx = _ctx(verdict="SUSPICIOUS")
    with pytest.raises(GroundingError):
        validate_machine_truth("MALICIOUS", "P1", 0.9,
                                                    list(ctx.entities), ctx)


def test_validator_rejects_confidence_inflation():
    ctx = _ctx(confidence=0.7)
    with pytest.raises(GroundingError):
        validate_machine_truth("MALICIOUS", "P1", 0.95,
                                                    list(ctx.entities), ctx)


def test_validator_rejects_invented_entity():
    ctx = _ctx()
    with pytest.raises(GroundingError):
        validate_machine_truth(
            "MALICIOUS", "P1", 0.9,
            ["HOST-01", "attacker-invented.example.com"], ctx)


# ---------- 7. LLM output with invented id → fallback -----------------
@pytest.mark.asyncio
async def test_gateway_falls_back_when_cloud_hallucinates_id():
    ctx = _ctx()
    bad_draft = NarrationDraft(
        paragraphs = [NarrationParagraph(text="bogus",
                                                                  evidence_ids=("EV-INVENTED",))],
        verdict    = ctx.verdict,
        severity   = ctx.severity,
        confidence = ctx.confidence,
        entities   = tuple(ctx.entities),
        generation_mode = GenerationMode.LLM_CLOUD,
    )
    cloud = _FakeProvider("cloud", draft=bad_draft)
    gw = NarrationGateway(
        providers = {"cloud": cloud,
                              "deterministic": DeterministicProvider()},
        order = ("cloud", "deterministic"),
    )
    out = await gw.render(NarrationRequest(
        kind=NarrationKind.EXECUTIVE_SUMMARY, context=ctx))
    assert out.provider == "deterministic"
    assert any("EV-INVENTED" in c or "not present" in c
                     for c in out.caveats)


# ---------- 8. Deterministic path — never raises for supported kind ---
@pytest.mark.asyncio
async def test_deterministic_provider_never_raises_for_supported_kinds():
    d = DeterministicProvider()
    ctx = _ctx()
    out = await d.draft(NarrationKind.EXECUTIVE_SUMMARY, ctx, None)
    assert out.paragraphs
    assert out.generation_mode == GenerationMode.DETERMINISTIC


# ---------- 9. Empty-context honesty ----------------------------------
@pytest.mark.asyncio
async def test_deterministic_handles_empty_context_honestly():
    d = DeterministicProvider()
    ctx = NarrationContext(incident_id="inc-empty")
    out = await d.draft(NarrationKind.EXECUTIVE_SUMMARY, ctx, None)
    joined = " ".join(p.text for p in out.paragraphs).lower()
    assert "insufficient evidence" in joined
