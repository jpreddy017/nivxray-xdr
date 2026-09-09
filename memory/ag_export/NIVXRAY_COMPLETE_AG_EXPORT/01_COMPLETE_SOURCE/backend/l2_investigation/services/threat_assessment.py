"""Threat Assessment service · Blueprint §9 (Summary lens · risk section).

Produces a deterministic risk breakdown from evidence signals. Scaffold
uses a simple bucketized aggregation; a real risk model lands in PR-4.
"""
from __future__ import annotations

from typing import Any

from ..schemas import EvidenceBundle, ServiceOutput
from .base import BaseService, register_service

_NAME = "threat_assessment"
_VERSION = "0.1.0-scaffold"


def _severity(bundle: EvidenceBundle) -> str:
    n_caps = len(bundle.capabilities)
    n_mitre = len(bundle.mitre)
    if n_caps >= 3 and n_mitre >= 3:
        return "critical"
    if n_caps >= 2 or n_mitre >= 2:
        return "high"
    if n_caps or n_mitre or bundle.iocs:
        return "medium"
    return "informational"


def run(bundle: EvidenceBundle) -> ServiceOutput:
    body: dict[str, Any] = {
        "severity": _severity(bundle),
        "signals": {
            "iocs": len(bundle.iocs),
            "capabilities": len(bundle.capabilities),
            "mitre": len(bundle.mitre),
            "transformations": len(bundle.transformations),
        },
        "family": bundle.sample.family,
        "canonical_state": bundle.certificate.get("canonical_state", False),
    }
    return ServiceOutput(
        service=_NAME,
        version=_VERSION,
        case_id=bundle.case_id,
        body=body,
    )


SERVICE = register_service(BaseService(name=_NAME, version=_VERSION, run=run))

__all__ = ["run", "SERVICE"]
