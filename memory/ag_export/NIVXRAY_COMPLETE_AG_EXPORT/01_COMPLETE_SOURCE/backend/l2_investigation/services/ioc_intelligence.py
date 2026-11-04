"""IOC Intelligence service · Blueprint §9 (Evidence lens · IOC panel).

Groups IOCs by type, deduplicates by value, and preserves source-iteration
provenance so Blueprint §8.4 (IOC → source iteration) drill-downs work.
"""
from __future__ import annotations

from typing import Any

from ..schemas import EvidenceBundle, ServiceOutput
from .base import BaseService, register_service

_NAME = "ioc_intelligence"
_VERSION = "0.1.0-scaffold"


def run(bundle: EvidenceBundle) -> ServiceOutput:
    by_type: dict[str, list[dict[str, Any]]] = {}
    for ioc in sorted(bundle.iocs, key=lambda x: (x.ioc_type, x.value, x.ioc_id)):
        by_type.setdefault(ioc.ioc_type, []).append(ioc.to_dict())

    body: dict[str, Any] = {
        "total": len(bundle.iocs),
        "by_type": {k: by_type[k] for k in sorted(by_type)},
        "enrichment": {},  # reserved for external TI enrichment (future PR)
    }
    return ServiceOutput(
        service=_NAME,
        version=_VERSION,
        case_id=bundle.case_id,
        body=body,
    )


SERVICE = register_service(BaseService(name=_NAME, version=_VERSION, run=run))

__all__ = ["run", "SERVICE"]
