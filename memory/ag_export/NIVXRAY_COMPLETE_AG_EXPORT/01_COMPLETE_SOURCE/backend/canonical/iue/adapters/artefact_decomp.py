"""Adapter · Artefact Decomposition (IUE-5).

Wraps services/ida/input_classifier.classify_artifact_input — shallow
artefact decomposition. Composer uses it to identify whether the input
contains typed sub-artefacts that Phase 3 Executor's ARTIFACT_SPLIT
capability will process.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from services.ida.input_classifier import classify_artifact_input

from ..models import IUEEvidence, Provenance, RawInput


PROV = Provenance(engine="canonical.iue.adapters.artefact_decomp",
                  version="1.0.0",
                  at="phase1",
                  upstream_evidence_ids=[])


def artefact_decomp_evidence(
    raw: RawInput,
) -> Tuple[Dict[str, Any], List[IUEEvidence]]:
    """Return (ida_result, evidence[])."""
    text = raw.as_text()
    try:
        result = classify_artifact_input(text)
    except Exception as exc:
        return {}, [IUEEvidence(
            id="ev.artefact_decomp.error",
            source="artefact_decomp",
            observation="ida.classify_artifact_input raised",
            confidence=0,
            rationale=f"exception: {type(exc).__name__}: {exc}",
            meta={},
            provenance=PROV,
        )]

    ida_class = result.get("ida_class")
    raw_conf = result.get("confidence", 0)
    # IDA emits float 0.0..1.0; normalise to int 0..100.
    if isinstance(raw_conf, float) and raw_conf <= 1.0:
        conf = int(round(raw_conf * 100))
    else:
        conf = int(raw_conf)
    reasoning = result.get("reasoning") or []
    summary = result.get("summary") or {}
    artifacts_hint = sum(int(v) for v in summary.values()) if isinstance(summary, dict) else 0

    ev: List[IUEEvidence] = [IUEEvidence(
        id="ev.artefact_decomp.0001",
        source="artefact_decomp",
        observation=f"IDA classified as {ida_class} (artefacts_hint={artifacts_hint})",
        confidence=conf,
        rationale=(reasoning[0] if reasoning else "ida.classify_artifact_input"),
        meta={
            "ida_class": ida_class,
            "artifact_count_hint": artifacts_hint,
            "reasoning_len": len(reasoning),
        },
        provenance=PROV,
    )]
    return result, ev
