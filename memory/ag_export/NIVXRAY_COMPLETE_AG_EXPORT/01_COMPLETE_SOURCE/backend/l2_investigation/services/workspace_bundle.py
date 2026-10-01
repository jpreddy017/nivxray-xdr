"""Workspace Bundle service · Blueprint §10.

Aggregates outputs of every other L2 service into a single deterministic
bundle. This is what the L1 API endpoint
``GET /api/investigation/:case_id`` (planned PR-2) returns as the full
workspace payload. The Workspace shell (PR-3) hydrates lenses from this
one call to eliminate lens-switching latency (Blueprint §8.2 modes
switch with ``0 data refetches``).
"""
from __future__ import annotations

from typing import Any

from ..schemas import EvidenceBundle, ServiceOutput
from .attack_story import run as run_attack_story
from .base import BaseService, register_service
from .capability_explorer import run as run_capability_explorer
from .detection_rules import run as run_detection_rules
from .executive_summary import run as run_executive_summary
from .hunting_queries import run as run_hunting_queries
from .ioc_intelligence import run as run_ioc_intelligence
from .threat_assessment import run as run_threat_assessment

_NAME = "workspace_bundle"
_VERSION = "0.1.0-scaffold"


def run(bundle: EvidenceBundle) -> ServiceOutput:
    # Order is deterministic (alphabetical), producing a stable JSON.
    parts = {
        "attack_story": run_attack_story(bundle).to_dict(),
        "capability_explorer": run_capability_explorer(bundle).to_dict(),
        "detection_rules": run_detection_rules(bundle).to_dict(),
        "executive_summary": run_executive_summary(bundle).to_dict(),
        "hunting_queries": run_hunting_queries(bundle).to_dict(),
        "ioc_intelligence": run_ioc_intelligence(bundle).to_dict(),
        "threat_assessment": run_threat_assessment(bundle).to_dict(),
    }
    body: dict[str, Any] = {
        "evidence_fingerprint": bundle.fingerprint,
        "services": parts,
    }
    return ServiceOutput(
        service=_NAME,
        version=_VERSION,
        case_id=bundle.case_id,
        body=body,
    )


SERVICE = register_service(BaseService(name=_NAME, version=_VERSION, run=run))

__all__ = ["run", "SERVICE"]
