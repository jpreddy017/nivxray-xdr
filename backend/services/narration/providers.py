"""
Narration provider protocol + concrete implementations.

Providers are intentionally minimal — they emit a
`NarrationDraft` (paragraphs + machine-truth echoes).  The
gateway is responsible for validation and turning a draft into a
`NarrationResult`.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Any, Protocol

from .contracts import (
    GenerationMode, GroundingError, NarrationContext, NarrationKind,
    NarrationParagraph,
)
from .grounding import coerce_paragraph_dicts

log = logging.getLogger("nivxray.narration")


@dataclass(frozen=True)
class NarrationDraft:
    """Provider output prior to gateway-level validation."""
    paragraphs:      list[NarrationParagraph]
    verdict:         str | None = None
    severity:        str | None = None
    confidence:      float | None = None
    entities:        tuple[str, ...] = ()
    generation_mode: GenerationMode = GenerationMode.DETERMINISTIC


class NarrationProvider(Protocol):
    name: str
    kind: str          # "cloud" | "offline" | "deterministic"
    supports: set[NarrationKind]

    async def draft(
        self,
        kind:        NarrationKind,
        context:     NarrationContext,
        session_id:  str | None,
    ) -> NarrationDraft: ...


# --------------------------------------------------------------------
# LLM prompt used by cloud/offline providers.  Structured JSON
# generation: the model must SELECT from the ids we hand it and
# never invent new ones.  The gateway validator enforces this.
# --------------------------------------------------------------------
_LLM_SYSTEM = """\
You are the NivXRay XDR narration engine.  You explain a security
incident in analyst-readable prose.  Absolute rules:

  · You MAY only reference evidence_ids, finding_ids and
    technique_ids that appear in the ALLOWED_IDS block below.
    Inventing IDs is forbidden.
  · You MAY only reference entities that appear in
    ALLOWED_ENTITIES.  Do NOT invent hostnames, usernames,
    processes, hashes, IPs, domains or files.
  · You MUST NOT change the verdict, severity, or confidence.
    Echo them verbatim from GOVERNED_TRUTH.  Never promote a
    verdict, never inflate confidence.
  · If a required fact is missing, say so honestly.  Never
    fabricate an ATT&CK technique, kill-chain stage, threat
    actor, malware family, campaign, or timeline detail.
  · You MUST return valid JSON that matches OUTPUT_SCHEMA
    exactly.

OUTPUT_SCHEMA:
{
  "paragraphs": [
    {
      "text":          "prose paragraph, no bullet points",
      "evidence_ids":  ["subset of ALLOWED_IDS.evidence"],
      "finding_ids":   ["subset of ALLOWED_IDS.findings"],
      "technique_ids": ["subset of ALLOWED_IDS.techniques"]
    }
  ],
  "verdict":     "<verbatim from GOVERNED_TRUTH.verdict>",
  "severity":    "<verbatim from GOVERNED_TRUTH.severity>",
  "confidence":  <number, <= GOVERNED_TRUTH.confidence>,
  "entities":    ["subset of ALLOWED_ENTITIES"]
}
"""


def _build_llm_user_prompt(kind: NarrationKind,
                                       ctx: NarrationContext) -> str:
    return json.dumps({
        "task": {
            "kind":        kind.value,
            "instruction": {
                NarrationKind.EXECUTIVE_SUMMARY.value:
                    "Write a conclusion-led executive summary in 2–4 short "
                    "paragraphs.  Lead with the verdict and severity; then "
                    "explain what was observed with evidence ids; then "
                    "list the affected entities.",
            }.get(kind.value, "Summarise faithfully."),
        },
        "GOVERNED_TRUTH": {
            "incident_id": ctx.incident_id,
            "verdict":     ctx.verdict,
            "severity":    ctx.severity,
            "confidence":  ctx.confidence,
        },
        "ALLOWED_IDS": {
            "evidence":   list(ctx.evidence_ids   or []),
            "findings":   list(ctx.finding_ids    or []),
            "techniques": list(ctx.technique_ids  or []),
        },
        "ALLOWED_ENTITIES": list(ctx.entities or []),
        "COMPOSER_INPUT":  ctx.composer_input,
    }, ensure_ascii=False)


# --------------------------------------------------------------------
# Cloud LLM provider.
# --------------------------------------------------------------------
class CloudLLMProvider:
    name = "cloud-llm"
    kind = "cloud"
    supports = {
        NarrationKind.EXECUTIVE_SUMMARY,
        NarrationKind.ATTACK_STORY,
        NarrationKind.R46_OVERLAY_SUMMARY,
        NarrationKind.R48_REPORT_NARRATION,
    }

    def __init__(self, backend_name: str = "emergent-claude"):
        self.name = f"cloud:{backend_name}"

    async def draft(self, kind, context, session_id):
        # Reuse existing provider registry.  We only invoke the
        # first ONLINE provider so we can distinguish cloud vs
        # offline failure clearly in the gateway logs.
        from llm_provider import _REGISTRY as _LLM_REG
        online = next((s["provider"] for s in _LLM_REG
                                 if getattr(s["provider"], "kind", "") == "online"),
                             None)
        if online is None:
            raise GroundingError("no cloud LLM provider registered")
        payload = await online.json(
            session_id or f"narr:{context.incident_id}",
            _LLM_SYSTEM,
            _build_llm_user_prompt(kind, context),
            retries=1,
        )
        return _coerce_llm_payload(payload, GenerationMode.LLM_CLOUD)


# --------------------------------------------------------------------
# Offline LLM provider (Ollama / Qwen / any local runtime).
# Falls back to a GroundingError if not configured — gateway
# then moves on to the deterministic narrator.
# --------------------------------------------------------------------
class OfflineLLMProvider:
    name = "offline-llm"
    kind = "offline"
    supports = {
        NarrationKind.EXECUTIVE_SUMMARY,
        NarrationKind.ATTACK_STORY,
        NarrationKind.R46_OVERLAY_SUMMARY,
        NarrationKind.R48_REPORT_NARRATION,
    }

    async def draft(self, kind, context, session_id):
        from llm_provider import _REGISTRY as _LLM_REG
        offline = next((s["provider"] for s in _LLM_REG
                                  if getattr(s["provider"], "kind", "") == "offline"),
                              None)
        if offline is None:
            raise GroundingError("no offline LLM provider registered")
        # The Ollama stub raises NotImplementedError when the
        # env vars are absent — surface it as a grounding-fallback.
        try:
            payload = await offline.json(
                session_id or f"narr:{context.incident_id}",
                _LLM_SYSTEM,
                _build_llm_user_prompt(kind, context),
                retries=0,
            )
        except NotImplementedError as e:
            raise GroundingError(f"offline llm not configured: {e}")
        return _coerce_llm_payload(payload, GenerationMode.LLM_OFFLINE)


def _coerce_llm_payload(payload: dict[str, Any],
                                    mode: GenerationMode) -> NarrationDraft:
    if not isinstance(payload, dict):
        raise GroundingError(
            f"llm returned non-dict payload: {type(payload).__name__}")
    paragraphs = coerce_paragraph_dicts(payload.get("paragraphs"))
    entities   = payload.get("entities") or []
    if not isinstance(entities, list):
        raise GroundingError("llm returned non-list entities")
    conf = payload.get("confidence")
    try:
        conf = float(conf) if conf is not None else None
    except (TypeError, ValueError):
        raise GroundingError("llm returned non-numeric confidence")
    return NarrationDraft(
        paragraphs      = paragraphs,
        verdict         = payload.get("verdict"),
        severity        = payload.get("severity"),
        confidence      = conf,
        entities        = tuple(str(e) for e in entities),
        generation_mode = mode,
    )


# --------------------------------------------------------------------
# Deterministic narrator — MANDATORY, NEVER FAILS.
#
# Wraps the existing `detection_content.xdr_executive_summary`
# composer (owner-locked, byte-identical output, no LLM).  Every
# other kind is declared but not yet wired; extending it is a
# subsequent-phase job, but callers can already rely on the
# executive-summary path today.
# --------------------------------------------------------------------
class DeterministicProvider:
    """Guaranteed-baseline narration capability.

    Terminology note (owner rule): the deterministic provider is
    **not** merely a fallback.  It is the guaranteed baseline —
    every kind it supports is always available, regardless of
    LLM credits, network, or legacy runtime state.  The Cloud
    and Offline providers are *priority* alternatives that may
    supply richer prose when available."""
    name = "deterministic"
    kind = "deterministic"
    supports = {
        NarrationKind.EXECUTIVE_SUMMARY,
        NarrationKind.ATTACK_STORY,
        NarrationKind.R46_OVERLAY_SUMMARY,
        NarrationKind.R48_REPORT_NARRATION,
    }

    async def draft(self, kind, context, session_id):
        if kind is NarrationKind.EXECUTIVE_SUMMARY:
            return _deterministic_executive_summary(context)
        if kind is NarrationKind.R46_OVERLAY_SUMMARY:
            # R46 analyst overlay base text = executive summary
            # produced deterministically.  The analyst overlay
            # layer edits *interpretation*, never machine truth.
            return _deterministic_executive_summary(context)
        if kind is NarrationKind.ATTACK_STORY:
            return _deterministic_attack_story(context)
        if kind is NarrationKind.R48_REPORT_NARRATION:
            return _deterministic_report_narration(context)
        raise GroundingError(
            f"deterministic narrator does not yet support {kind.value}")


def _deterministic_executive_summary(
    ctx: NarrationContext,
) -> NarrationDraft:
    """Compose an evidence-grounded executive summary from the
    governed context ALONE.  Same inputs → byte-identical output;
    no external calls; guaranteed available.
    """
    verdict  = (ctx.verdict or "UNKNOWN").upper()
    severity = (ctx.severity or "—").upper()
    conf     = ctx.confidence if ctx.confidence is not None else None
    ev_count = len(ctx.evidence_ids  or ())
    fn_count = len(ctx.finding_ids   or ())
    tc_count = len(ctx.technique_ids or ())
    ent      = list(ctx.entities or ())[:6]

    p1_text = (
        f"Verdict: {verdict}"
        + (f" · Severity: {severity}" if severity != "—" else "")
        + (f" · Confidence: {conf:.2f}" if conf is not None else "")
        + "."
    )
    p2_bits: list[str] = []
    p2_bits.append(
        f"NivXRay XDR has attributed {tc_count} ATT&CK "
        f"{'technique' if tc_count == 1 else 'techniques'} to this "
        f"incident, supported by {ev_count} canonical evidence "
        f"{'row' if ev_count == 1 else 'rows'}"
        + (f" and {fn_count} finding{'s' if fn_count != 1 else ''}."
              if fn_count else ".")
    )
    if not ev_count and not tc_count:
        p2_bits.append(
            "Insufficient evidence has been collected to substantiate "
            "an attack chain — this is a coverage gap, not an "
            "all-clear."
        )
    p2_text = " ".join(p2_bits)

    p3_text: str
    if ent:
        p3_text = "Affected entities in scope: " + ", ".join(ent) + "."
    else:
        p3_text = "No entities have been observed for this incident yet."

    paragraphs = [
        NarrationParagraph(
            text          = p1_text,
            evidence_ids  = (),
            finding_ids   = (),
            technique_ids = (),
        ),
        NarrationParagraph(
            text          = p2_text,
            evidence_ids  = tuple(ctx.evidence_ids  or ()),
            finding_ids   = tuple(ctx.finding_ids   or ()),
            technique_ids = tuple(ctx.technique_ids or ()),
        ),
        NarrationParagraph(
            text          = p3_text,
            evidence_ids  = (),
            finding_ids   = (),
            technique_ids = (),
        ),
    ]
    return NarrationDraft(
        paragraphs      = paragraphs,
        verdict         = ctx.verdict,
        severity        = ctx.severity,
        confidence      = ctx.confidence,
        entities        = tuple(ent),
        generation_mode = GenerationMode.DETERMINISTIC,
    )




def _deterministic_attack_story(ctx: NarrationContext) -> NarrationDraft:
    """Guaranteed-baseline Attack Story narration."""
    verdict  = (ctx.verdict or "UNKNOWN").upper()
    severity = (ctx.severity or "—").upper()
    tech     = list(ctx.technique_ids or ())

    paragraphs: list[NarrationParagraph] = [
        NarrationParagraph(
            text = (
                f"Attack Story · Verdict: {verdict}"
                + (f" · Severity: {severity}" if severity != "—" else "")
                + f" · Technique count: {len(tech)}."
            ),
        ),
    ]
    if not tech:
        paragraphs.append(NarrationParagraph(
            text = ("No ATT&CK technique has been substantiated for this "
                            "incident yet. Attack progression cannot be narrated "
                            "without evidence — this is a coverage gap, not an "
                            "all-clear."),
        ))
    else:
        for tid in tech:
            paragraphs.append(NarrationParagraph(
                text          = (
                    f"Stage: {tid} — attributed by NivXRay XDR's "
                    "AttackTechniqueEvidence SSOT to this incident."),
                technique_ids = (tid,),
                evidence_ids  = tuple(ctx.evidence_ids or ()),
            ))
    return NarrationDraft(
        paragraphs      = paragraphs,
        verdict         = ctx.verdict,
        severity        = ctx.severity,
        confidence      = ctx.confidence,
        entities        = tuple(list(ctx.entities or ())[:6]),
        generation_mode = GenerationMode.DETERMINISTIC,
    )


def _deterministic_report_narration(ctx: NarrationContext) -> NarrationDraft:
    """Guaranteed-baseline PDF-report narration.  Prose only —
    the report composer owns layout."""
    base = _deterministic_executive_summary(ctx)
    header = NarrationParagraph(
        text = (f"NivXRay XDR Investigation Report · Incident "
                     f"{ctx.incident_id}."),
    )
    return NarrationDraft(
        paragraphs      = [header, *base.paragraphs],
        verdict         = ctx.verdict,
        severity        = ctx.severity,
        confidence      = ctx.confidence,
        entities        = base.entities,
        generation_mode = GenerationMode.DETERMINISTIC,
    )
