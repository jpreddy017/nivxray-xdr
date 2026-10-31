"""
Grounding validator — enforces that LLM narration references only
objects that already exist in the supplied `NarrationContext`.

If an LLM tries to invent an evidence id, finding id, technique
id, entity, verdict, severity, or an inflated confidence, the
validator raises `GroundingError` and the gateway falls back to
the next provider — ultimately to the deterministic narrator.
"""
from __future__ import annotations

from typing import Any

from .contracts import (
    GroundingError, NarrationContext, NarrationParagraph,
)


def validate_paragraphs(
    paragraphs: list[NarrationParagraph],
    context:    NarrationContext,
) -> None:
    """Raise `GroundingError` on the first violation.  The
    validator is intentionally strict — a single hallucinated id
    is enough to reject the whole draft and fall back."""
    ev  = set(context.evidence_ids  or ())
    fn  = set(context.finding_ids   or ())
    tec = set(context.technique_ids or ())
    for i, p in enumerate(paragraphs):
        for eid in p.evidence_ids or ():
            if eid not in ev:
                raise GroundingError(
                    f"paragraph[{i}] references evidence_id "
                    f"{eid!r} not present in context")
        for fid in p.finding_ids or ():
            if fid not in fn:
                raise GroundingError(
                    f"paragraph[{i}] references finding_id "
                    f"{fid!r} not present in context")
        for tid in p.technique_ids or ():
            if tid not in tec:
                raise GroundingError(
                    f"paragraph[{i}] references technique_id "
                    f"{tid!r} not present in context")


def validate_machine_truth(
    verdict:      str | None,
    severity:     str | None,
    confidence:   float | None,
    entities:     list[str] | tuple[str, ...],
    context:      NarrationContext,
) -> None:
    """LLM providers may echo machine-truth fields but MUST NOT
    change them.  Verdict / severity cannot be promoted;
    confidence cannot be inflated; entities cannot be invented."""
    if verdict is not None and context.verdict is not None \
            and str(verdict).strip().upper() != str(context.verdict).strip().upper():
        raise GroundingError(
            f"LLM altered verdict: {verdict!r} != context "
            f"{context.verdict!r}")
    if severity is not None and context.severity is not None \
            and str(severity).strip().upper() != str(context.severity).strip().upper():
        raise GroundingError(
            f"LLM altered severity: {severity!r} != context "
            f"{context.severity!r}")
    if confidence is not None and context.confidence is not None:
        if float(confidence) > float(context.confidence) + 1e-6:
            raise GroundingError(
                f"LLM inflated confidence: {confidence!r} > "
                f"context {context.confidence!r}")
    if entities:
        allowed = set(context.entities or ())
        for e in entities:
            if e and e not in allowed:
                raise GroundingError(
                    f"LLM referenced entity {e!r} not present "
                    f"in context")


def coerce_paragraph_dicts(raw: Any) -> list[NarrationParagraph]:
    """Parse the JSON shape LLM providers must return.  Any
    malformed field (e.g. list of ints instead of strings)
    raises `GroundingError` so the caller can fall back."""
    if not isinstance(raw, list):
        raise GroundingError(
            f"paragraphs must be a list, got {type(raw).__name__}")
    out: list[NarrationParagraph] = []
    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            raise GroundingError(f"paragraph[{i}] not a dict")
        text = item.get("text")
        if not isinstance(text, str) or not text.strip():
            raise GroundingError(f"paragraph[{i}] missing/empty text")
        def _str_list(k):
            v = item.get(k) or []
            if not isinstance(v, list):
                raise GroundingError(
                    f"paragraph[{i}].{k} must be a list")
            return tuple(str(x) for x in v)
        out.append(NarrationParagraph(
            text          = text.strip(),
            evidence_ids  = _str_list("evidence_ids"),
            finding_ids   = _str_list("finding_ids"),
            technique_ids = _str_list("technique_ids"),
        ))
    return out
