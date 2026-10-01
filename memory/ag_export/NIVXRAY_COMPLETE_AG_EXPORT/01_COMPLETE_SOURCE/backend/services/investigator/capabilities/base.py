"""Round 32 · Capability base contract + registry.

Contract enhancements over Round 31:
  * ``category`` — declared capability category (process / network / ...)
  * ``evidence_requirements`` — declared inputs; the selector uses them
    to honestly skip when required inputs are absent.
  * ``evidence_sufficiency`` — result state per execution:
    SUFFICIENT · PARTIAL · INSUFFICIENT · NOT_APPLICABLE.
  * ``investigation_question`` — one-line "what does this engine answer?"
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Literal, Tuple

from services.investigator.models import Finding, PivotAction, CapabilityAvailability


EvidenceSufficiency = Literal[
    "SUFFICIENT", "PARTIAL", "INSUFFICIENT", "NOT_APPLICABLE",
]


def fid(payload: str) -> str:
    return "fnd_" + hashlib.sha256(payload.encode()).hexdigest()[:20]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Capability:
    """Investigation capability contract.

    Subclasses override ``id``, ``engine``, ``category``,
    ``investigation_question``, ``evidence_requirements``,
    ``availability`` and implement ``check_evidence`` +
    ``execute``.
    """
    id: str = "capability::base"
    name: str = "base"
    version: str = "1.0.0"
    engine: str = "nivxray::investigator::capability::base"
    category: str = "generic"
    investigation_question: str = ""
    evidence_requirements: Tuple[str, ...] = ()
    availability: CapabilityAvailability = "cap-unavailable"
    unavailable_reason: str = "Not registered."
    gaps_closed_hint: Tuple[str, ...] = ()

    # ── Evidence-sufficiency check ───────────────────────────────
    def check_evidence(self, incident: Dict[str, Any],
                          canonical: Optional[Dict[str, Any]],
                         ) -> Tuple[EvidenceSufficiency, str]:
        """Return (sufficiency, reason).

        Default implementation: SUFFICIENT when a canonical event
        exists.  Subclasses override for stricter checks.
        """
        if canonical:
            return "SUFFICIENT", "canonical evidence available"
        return "INSUFFICIENT", "no canonical evidence linked to incident"

    async def execute(self, db, pivot: PivotAction,
                        incident: Dict[str, Any],
                        canonical: Optional[Dict[str, Any]],
                       ) -> Tuple[List[Finding], List[str]]:
        raise NotImplementedError

    # ── Descriptor for the read API + selector introspection ────
    def descriptor(self) -> Dict[str, Any]:
        return {
            "id":                     self.id,
            "name":                   self.name,
            "version":                self.version,
            "engine":                 self.engine,
            "category":               self.category,
            "investigation_question": self.investigation_question,
            "evidence_requirements":  list(self.evidence_requirements),
            "availability":           self.availability,
            "unavailable_reason":     self.unavailable_reason
                                             if self.availability != "cap-full"
                                             else None,
            "gaps_closed_hint":       list(self.gaps_closed_hint),
        }


# ── Registry ────────────────────────────────────────────────────────

_REGISTRY: Dict[str, Capability] = {}


def register_capability(cap: Capability) -> None:
    _REGISTRY[cap.id] = cap


def get_capability(capability_id: str) -> Optional[Capability]:
    return _REGISTRY.get(capability_id)


def all_capabilities() -> Dict[str, Capability]:
    return dict(_REGISTRY)
