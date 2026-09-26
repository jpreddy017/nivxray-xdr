"""Adapter · Text-Structure (IUE-2).

Wraps services/die/input_understanding.understand — uses ONLY the
classification portion (no execution). Composer applies execute=False.
"""
from __future__ import annotations

from typing import List, Optional, Tuple

from services.die.input_understanding import understand as die_understand

from ..models import IUEEvidence, Provenance, RawInput


PROV = Provenance(engine="canonical.iue.adapters.text_structure",
                  version="1.0.0",
                  at="phase1",
                  upstream_evidence_ids=[])


def text_structure_evidence(raw: RawInput) -> Tuple[Optional[str], Optional[str], List[IUEEvidence]]:
    """Return (primary_type, next_engine_hint, evidence[])."""
    text = raw.as_text()
    try:
        # execute=False: classification + plan-emission only, no analyzer runs.
        u = die_understand(text, execute=False)
    except Exception as exc:
        return None, None, [IUEEvidence(
            id="ev.text_structure.error",
            source="text_structure",
            observation="text-structure classifier raised",
            confidence=0,
            rationale=f"exception: {type(exc).__name__}: {exc}",
            meta={},
            provenance=PROV,
        )]

    conf = int(round((u.confidence or 0.0) * 100))
    ev: List[IUEEvidence] = [IUEEvidence(
        id="ev.text_structure.0001",
        source="text_structure",
        observation=f"die.iue classified as {u.input_type} ({u.label})",
        confidence=conf,
        rationale=(u.reasoning[0] if u.reasoning else "die.iue classification"),
        meta={
            "input_type": u.input_type,
            "label": u.label,
            "decode_required": bool(u.decode_required),
            "reasoning_count": len(u.reasoning or []),
        },
        provenance=PROV,
    )]

    # Emit each additional reasoning line as its own evidence entry.
    for i, r in enumerate((u.reasoning or [])[1:], start=2):
        ev.append(IUEEvidence(
            id=f"ev.text_structure.{i:04d}",
            source="text_structure",
            observation=str(r)[:200],
            confidence=max(conf - 5, 0),
            rationale="secondary die.iue reasoning",
            meta={},
            provenance=PROV,
        ))
    return u.input_type, u.next_engine, ev
