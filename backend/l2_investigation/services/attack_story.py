"""Attack Story service · Blueprint §9 (Story lens) · P0 #4.

Produces an ordered, evidence-anchored narrative of the attack. Each
story event must link back to an iteration in the Convergence
Certificate (Blueprint §8.4 Evidence Navigation Contract).

Scaffold: derives one event per changed transformation, in iteration
order. PR-4 replaces with human-readable narrative sentences.
"""
from __future__ import annotations

from typing import Any

from ..schemas import EvidenceBundle, ServiceOutput
from .base import BaseService, register_service

_NAME = "attack_story"
_VERSION = "0.1.0-scaffold"


def _events(bundle: EvidenceBundle) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    # Iterate transformations in the exact order they appear (already
    # deterministic per the Convergence engine iteration record).
    for idx, t in enumerate(bundle.transformations):
        if not t.changed:
            continue
        events.append(
            {
                "event_id": f"evt-{idx:04d}",
                "iteration": t.iteration,
                "pass_name": t.pass_name,
                "transformation": t.transformation,
                "text": f"{t.pass_name} pass applied {t.transformation}",
                "anchor": {
                    "kind": "transformation",
                    "iteration": t.iteration,
                    "transformation": t.transformation,
                },
            }
        )
    return events


def run(bundle: EvidenceBundle) -> ServiceOutput:
    body: dict[str, Any] = {
        "events": _events(bundle),
        "narrative": "",  # PR-4 replaces with human-readable prose
    }
    return ServiceOutput(
        service=_NAME,
        version=_VERSION,
        case_id=bundle.case_id,
        body=body,
    )


SERVICE = register_service(BaseService(name=_NAME, version=_VERSION, run=run))

__all__ = ["run", "SERVICE"]
