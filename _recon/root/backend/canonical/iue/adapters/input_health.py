"""Adapter · Input Health (pre-IUE).

Wraps services/die/input_health.check_health.
"""
from __future__ import annotations

from dataclasses import asdict
from typing import List

from services.die.input_health import check_health

from ..models import InputHealthResult, IUEEvidence, Provenance, RawInput


PROV = Provenance(engine="canonical.iue.adapters.input_health",
                  version="1.0.0",
                  at="phase1",
                  upstream_evidence_ids=[])


def health_evidence(raw: RawInput) -> tuple[InputHealthResult, List[IUEEvidence]]:
    """Return (InputHealthResult, evidence[])."""
    text = raw.as_text()
    ih = check_health(text)
    d = asdict(ih)

    # Determine blocking: any structural corruption or oversized signal.
    blocking_kinds = {"structural_corruption", "oversized"}
    blocking = any(
        (issue.get("kind") in blocking_kinds) for issue in d.get("issues", [])
    )

    result = InputHealthResult(
        ok=not blocking,
        blocking=blocking,
        size_bytes=raw.size(),
        control_char_ratio=float(d.get("control_char_ratio", 0.0)),
        encoding=d.get("encoding", "utf-8"),
        issues=d.get("issues", []),
    )

    evidence: List[IUEEvidence] = []
    for i, issue in enumerate(d.get("issues", [])):
        evidence.append(IUEEvidence(
            id=f"ev.input_health.{i:04d}",
            source="input_health",
            observation=str(issue.get("kind", "issue")),
            confidence=int(issue.get("confidence", 60)),
            rationale=str(issue.get("detail") or issue.get("message") or "input-health finding"),
            meta={"issue": issue},
            provenance=PROV,
        ))
    if not evidence:
        evidence.append(IUEEvidence(
            id="ev.input_health.ok",
            source="input_health",
            observation="input passes structural health checks",
            confidence=100,
            rationale=f"size={raw.size()}B; control_char_ratio={result.control_char_ratio:.3f}",
            meta={"size_bytes": raw.size()},
            provenance=PROV,
        ))
    return result, evidence
