"""EDR Activity/Evidence canonical model.

Owner rule #19 (2026-08-26):
    One canonical Activity/Evidence object drives:
        Left inventory → Trajectory canvas → Right details → Evidence
                → Verdict Explainability
    Do NOT maintain separate mock data models for each panel.

Every UI panel of the EDR Device Trajectory experience projects
from this SINGLE object graph.  Each ``ActivityEntity`` is an
observed subject (a process, file, host, IP, domain, user, registry
key) that the analyst can pivot on.  Each ``ActivityEvent`` is a
timestamped fact carrying provenance back to raw evidence.

Rule #10: process events carry deterministic parent/child/timestamp/
pid/executable/hash/user/command_line/provenance — never invented.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


# ── Entity kinds (rule #8 left rail) ─────────────────────────────
KIND_PROCESS   = "process"
KIND_FILE      = "file"
KIND_NETWORK   = "network"
KIND_REGISTRY  = "registry"
KIND_IDENTITY  = "identity"
KIND_SYSTEM    = "system"

ENTITY_KINDS = (KIND_PROCESS, KIND_FILE, KIND_NETWORK,
                 KIND_REGISTRY, KIND_IDENTITY, KIND_SYSTEM)


# ── File actions (rule #14) ──────────────────────────────────────
FILE_ACTIONS = ("created", "written", "modified", "executed",
                 "moved", "deleted", "quarantined",
                 "quarantine_failed", "detected")


@dataclass(frozen=True)
class ActivityEntity:
    """A pivotable subject in the EDR trajectory.

    - Left rail groups entities by ``kind``.
    - Right panel shows detailed fields when an entity is selected.
    - Trajectory canvas positions events belonging to this entity.
    """
    entity_id: str                   # deterministic id
    kind: str                        # one of ENTITY_KINDS
    display_name: str
    # Optional attributes surfaced in the right-panel details.
    # Only populated when supported by evidence (owner rule #13).
    attributes: Dict[str, Any] = field(default_factory=dict)
    event_ids: List[str] = field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    # Ancestry for process entities.
    parent_entity_id: Optional[str] = None
    child_entity_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ActivityEvent:
    """A timestamped observation.  Same event_id as the source
    TimelineEvent so pivots between panels resolve identically."""
    event_id: str
    kind: str                        # entity kind this event belongs to
    entity_id: str                   # deterministic ancestor entity
    timestamp: Optional[str]         # None → surfaces in "untimed" bucket
    action: Optional[str]            # e.g. "execute", "created", "connect"
    lane: str                        # "log" | "url" | "file" | "narrative"
    display_summary: str             # one-line for the trajectory node
    canonical_fields: Dict[str, Any] = field(default_factory=dict)
    provenance_chain: List[str] = field(default_factory=list)
    detection: Optional[Dict[str, Any]] = None   # rule id / engine / severity
    mitre: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ActivityInventory:
    """Complete inventory driving all four panels."""
    case_id: Optional[str]
    tenant_id: Optional[str]
    entities: Dict[str, List[ActivityEntity]]     # kind → entities
    events: List[ActivityEvent]                   # chronologically ordered
    untimed_events: List[ActivityEvent]
    generated_at: str
    span_start: Optional[str] = None
    span_end: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id":        self.case_id,
            "tenant_id":      self.tenant_id,
            "entities": {k: [e.to_dict() for e in v]
                          for k, v in self.entities.items()},
            "events":         [e.to_dict() for e in self.events],
            "untimed_events": [e.to_dict() for e in self.untimed_events],
            "generated_at":   self.generated_at,
            "span_start":     self.span_start,
            "span_end":       self.span_end,
            "counts": {k: len(v) for k, v in self.entities.items()},
        }


__all__ = [
    "KIND_PROCESS", "KIND_FILE", "KIND_NETWORK", "KIND_REGISTRY",
    "KIND_IDENTITY", "KIND_SYSTEM", "ENTITY_KINDS", "FILE_ACTIONS",
    "ActivityEntity", "ActivityEvent", "ActivityInventory",
]
