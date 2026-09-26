"""Adapter · Language + Multi-Artefact (IUE-3).

Wraps v2/investigation/iu/engine.classify — detects per-language
artefacts and emits Capability dispatch hints + embedded types.
"""
from __future__ import annotations

from typing import List, Optional, Tuple

from v2.investigation.iu.engine import classify as v2iu_classify

from ..models import IUEEvidence, Provenance, RawInput


PROV = Provenance(engine="canonical.iue.adapters.language_multi_artefact",
                  version="1.0.0",
                  at="phase1",
                  upstream_evidence_ids=[])


def language_multi_artefact_evidence(
    raw: RawInput,
) -> Tuple[Optional[str], List[str], List[str], List[IUEEvidence]]:
    """Return (primary_type, embedded[], capability_hints[], evidence[])."""
    text = raw.as_text()
    try:
        cls = v2iu_classify(text)
    except Exception as exc:
        return None, [], [], [IUEEvidence(
            id="ev.lang_multi.error",
            source="language_multi_artefact",
            observation="v2 iu.engine.classify raised",
            confidence=0,
            rationale=f"exception: {type(exc).__name__}: {exc}",
            meta={},
            provenance=PROV,
        )]

    primary = cls.primary_type.value if cls.primary_type is not None else None
    embedded = [t.value for t in cls.embedded]
    dispatch = [c.value for c in cls.dispatch]

    ev: List[IUEEvidence] = []
    for i, e in enumerate(cls.evidence or []):
        ev.append(IUEEvidence(
            id=f"ev.lang_multi.{i:04d}",
            source=str(e.source),
            observation=str(e.observation)[:200],
            confidence=int(e.confidence),
            rationale=str(e.rationale)[:200],
            meta=dict(e.meta or {}),
            provenance=PROV,
        ))
    if not ev:
        ev.append(IUEEvidence(
            id="ev.lang_multi.empty",
            source="language_multi_artefact",
            observation=f"no per-language detector matched ({primary})",
            confidence=int(cls.confidence),
            rationale="v2 iu.engine emitted no evidence entries",
            meta={},
            provenance=PROV,
        ))
    return primary, embedded, dispatch, ev
