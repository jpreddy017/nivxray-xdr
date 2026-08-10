"""Adapter · Intent (upstream, D1-D).

Wraps services/die/intent.classify_intent. Under D1-D, intent
classification moves upstream into the composer instead of being a
post-classification step. Phase 1 only stamps intent; the fuller
intent-from-analyze pipeline stays out of Phase 1 (that's Phase 3).
"""
from __future__ import annotations

from typing import List, Tuple

from services.die.intent import classify_intent

from ..models import IUEEvidence, Intent, Provenance, RawInput


PROV = Provenance(engine="canonical.iue.adapters.intent",
                  version="1.0.0",
                  at="phase1",
                  upstream_evidence_ids=[])


def intent_evidence(
    raw: RawInput,
    primary_type: str,
    classification_confidence: int,
) -> Tuple[Intent, List[IUEEvidence]]:
    """Return (Intent, evidence[])."""
    text = raw.as_text()
    try:
        result = classify_intent(text, primary_type, float(classification_confidence) / 100.0)
    except Exception as exc:
        intent = Intent(label="unknown", confidence=0, evidence_ids=[])
        return intent, [IUEEvidence(
            id="ev.intent.error",
            source="intent",
            observation="die.classify_intent raised",
            confidence=0,
            rationale=f"exception: {type(exc).__name__}: {exc}",
            meta={},
            provenance=PROV,
        )]

    label = str(result.get("label") or result.get("intent") or "unknown")
    conf = int(float(result.get("confidence", 0.0)) * 100) if isinstance(result.get("confidence"), float) else int(result.get("confidence", 0))
    reasoning = result.get("reasoning") or result.get("rationale") or []
    if isinstance(reasoning, str):
        reasoning = [reasoning]

    intent = Intent(label=label, confidence=conf, evidence_ids=[])
    ev: List[IUEEvidence] = [IUEEvidence(
        id="ev.intent.0001",
        source="intent",
        observation=f"intent classified as {label}",
        confidence=conf,
        rationale=(reasoning[0] if reasoning else "die.classify_intent"),
        meta={"label": label, "reasoning_count": len(reasoning)},
        provenance=PROV,
    )]
    intent.evidence_ids = [ev[0].id]
    return intent, ev
