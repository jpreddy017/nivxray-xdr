"""Hunting Queries service · Blueprint §9 (Analysis lens).

Emits pivot-friendly hunt queries per SIEM. Scaffold parallels
``detection_rules`` with empty query sets.
"""
from __future__ import annotations

from typing import Any

from ..schemas import EvidenceBundle, ServiceOutput
from .base import BaseService, register_service

_NAME = "hunting_queries"
_VERSION = "0.1.0-scaffold"

_TARGETS: tuple[str, ...] = ("splunk", "sentinel", "elastic", "crowdstrike")


def run(bundle: EvidenceBundle) -> ServiceOutput:
    body: dict[str, Any] = {
        "targets": list(_TARGETS),
        "queries": {t: [] for t in _TARGETS},
        "anchors": {"iocs": [], "mitre": [], "capabilities": []},
    }
    return ServiceOutput(
        service=_NAME,
        version=_VERSION,
        case_id=bundle.case_id,
        body=body,
    )


SERVICE = register_service(BaseService(name=_NAME, version=_VERSION, run=run))

__all__ = ["run", "SERVICE"]
