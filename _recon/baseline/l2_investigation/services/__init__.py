"""L2 Investigation Services — deterministic content producers.

Each service module exposes a single ``run(bundle)`` function returning
a ``ServiceOutput``. PR-1 provides skeletons: input contract enforced,
output schema defined, empty-but-well-formed bodies. Real content lands
per-service in PR-4 through PR-6.

Blueprint mapping (Validation Matrix §4):

    executive_summary   → Summary lens · Reports
    attack_story        → Story lens · Reports (P0 #4)
    ioc_intelligence    → Evidence · IOC panel
    capability_explorer → Evidence · Capability panel · MITRE cross-ref
    threat_assessment   → Summary lens · Reports
    detection_rules     → Analysis lens · Exports (P0 #3)
    hunting_queries     → Analysis lens · Exports
    workspace_bundle    → single bundle for Workspace shell (PR-3)
"""
from __future__ import annotations

from . import (
    attack_story,
    capability_explorer,
    detection_rules,
    executive_summary,
    hunting_queries,
    ioc_intelligence,
    threat_assessment,
    workspace_bundle,
)
from .base import BaseService, register_service, iter_services

__all__ = [
    "BaseService",
    "register_service",
    "iter_services",
    "attack_story",
    "capability_explorer",
    "detection_rules",
    "executive_summary",
    "hunting_queries",
    "ioc_intelligence",
    "threat_assessment",
    "workspace_bundle",
]
