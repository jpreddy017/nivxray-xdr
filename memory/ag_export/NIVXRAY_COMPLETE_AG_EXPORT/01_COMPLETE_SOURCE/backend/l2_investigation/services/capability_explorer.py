"""Capability Explorer service · Blueprint §9 (Evidence lens · Capability panel).

Cross-references detected capabilities with MITRE techniques (via the
``via_capability`` mapping already present in ``MitreEvidence``).
"""
from __future__ import annotations

from typing import Any

from ..schemas import EvidenceBundle, ServiceOutput
from .base import BaseService, register_service

_NAME = "capability_explorer"
_VERSION = "0.1.0-scaffold"


def run(bundle: EvidenceBundle) -> ServiceOutput:
    # Deterministic ordering: capabilities alphabetical by id.
    caps = sorted(bundle.capabilities, key=lambda c: c.capability_id)
    # Group MITRE per capability.
    mitre_by_cap: dict[str, list[dict[str, Any]]] = {}
    for m in sorted(bundle.mitre, key=lambda x: x.technique_id):
        mitre_by_cap.setdefault(m.via_capability, []).append(m.to_dict())

    items: list[dict[str, Any]] = []
    for c in caps:
        items.append(
            {
                **c.to_dict(),
                "mitre": mitre_by_cap.get(c.capability_id, []),
            }
        )

    body: dict[str, Any] = {
        "total": len(caps),
        "items": items,
    }
    return ServiceOutput(
        service=_NAME,
        version=_VERSION,
        case_id=bundle.case_id,
        body=body,
    )


SERVICE = register_service(BaseService(name=_NAME, version=_VERSION, run=run))

__all__ = ["run", "SERVICE"]
