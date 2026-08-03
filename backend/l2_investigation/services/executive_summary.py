"""Executive Summary service · Blueprint §9 (Summary lens).

Answers the Tier-1 analyst question: "What is this, how bad, and what
do I do in the next 60 seconds?"

Scaffold: emits a well-formed but content-empty summary. PR-4 adds real
scoring, risk phrasing, and top-3 actions.
"""
from __future__ import annotations

from typing import Any

from ..schemas import EvidenceBundle, ServiceOutput
from .base import BaseService, register_service

_NAME = "executive_summary"
_VERSION = "0.1.0-scaffold"


def _top_iocs(bundle: EvidenceBundle, n: int = 3) -> list[dict[str, Any]]:
    """Deterministically pick the first `n` IOCs sorted by id."""
    ordered = sorted(bundle.iocs, key=lambda x: x.ioc_id)[:n]
    return [i.to_dict() for i in ordered]


def _verdict(bundle: EvidenceBundle) -> str:
    """Placeholder verdict — PR-4 will replace with a scored decision.

    Deterministic mapping so tests can pin the value:
      * has family + capabilities   → "malicious"
      * has any capabilities/iocs   → "suspicious"
      * otherwise                   → "unknown"
    """
    if bundle.sample.family and bundle.capabilities:
        return "malicious"
    if bundle.capabilities or bundle.iocs:
        return "suspicious"
    return "unknown"


def run(bundle: EvidenceBundle) -> ServiceOutput:
    body: dict[str, Any] = {
        "verdict": _verdict(bundle),
        "risk": "unscored",  # PR-4 will populate
        "family": bundle.sample.family,
        "technique": bundle.sample.technique,
        "canonical_state": bundle.certificate.get("canonical_state", False),
        "ready_for_behavioral_analysis": bundle.certificate.get(
            "ready_for_behavioral_analysis", False
        ),
        "top_iocs": _top_iocs(bundle, 3),
        "top_actions": [],   # PR-4 will populate
        "bullets": [],       # PR-4 will populate; each bullet must anchor to evidence
    }
    return ServiceOutput(
        service=_NAME,
        version=_VERSION,
        case_id=bundle.case_id,
        body=body,
    )


SERVICE = register_service(BaseService(name=_NAME, version=_VERSION, run=run))

__all__ = ["run", "SERVICE"]
