"""Detection Rules service · Blueprint §9 (Analysis lens) · P0 #3.

Generates Sigma / KQL / Splunk / YARA rules anchored to evidence.
Scaffold emits empty rule sets in each format so PR-6 can plug in
generators without changing the wire schema.
"""
from __future__ import annotations

from typing import Any

from ..schemas import EvidenceBundle, ServiceOutput
from .base import BaseService, register_service

_NAME = "detection_rules"
_VERSION = "0.1.0-scaffold"

_FORMATS: tuple[str, ...] = ("sigma", "kql", "splunk", "yara")


def run(bundle: EvidenceBundle) -> ServiceOutput:
    body: dict[str, Any] = {
        "formats": list(_FORMATS),
        "rules": {fmt: [] for fmt in _FORMATS},
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
