"""Contracts: closed vocabularies + invariant-checked records. UNKNOWN is first-class."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

MACHINE_ASSESSMENTS = ("MALICIOUS", "SUSPICIOUS", "BENIGN", "UNKNOWN", "NOT_ASSESSED", "INSUFFICIENT_EVIDENCE")
ANALYST_DISPOSITIONS = ("TRUE_POSITIVE", "FALSE_POSITIVE", "EXPECTED_ACTIVITY", "AUTHORIZED_TEST",
                        "NEEDS_INVESTIGATION")
RELATIONSHIP_STATES = ("PROVEN_CAUSAL", "SUPPORTED_RELATIONSHIP", "CORRELATED", "UNKNOWN")
CAUSAL_LINKAGES = ("SOURCE_PROCESS_GUID", "PROCESS_IID")  # the only linkages allowed to be PROVEN_CAUSAL
TI_STATES = ("MALICIOUS", "SUSPICIOUS", "BENIGN", "UNKNOWN", "NO_DATA", "UNAVAILABLE", "RATE_LIMITED", "ERROR")
RESPONSE_STATES = ("REQUESTED", "AUTHORIZED", "ACCEPTED", "DISPATCHED", "EXECUTED", "VERIFIED", "FAILED",
                   "VERIFICATION_FAILED", "CAPABILITY_UNAVAILABLE", "REFUSED", "UNKNOWN_STATE")
RETRO_TRIGGERS = ("INITIAL", "RULE_CHANGE", "INTEL_CHANGE", "MODEL_CHANGE", "REPUTATION_CHANGE", "ANALYST_CHANGE",
                  "NEW_EVIDENCE")
# AVAILABLE: data present. EMPTY: the source ran and claimed nothing (never "clean").
# UNKNOWN: cannot be determined. UNAVAILABLE: source failed / absent. NOT_WIRED: no backend source yet.
SECTION_STATES = ("AVAILABLE", "EMPTY", "UNKNOWN", "UNAVAILABLE", "NOT_WIRED")
SECTION_KEYS = ("observation", "causal_context", "detection_attribution", "behavioral", "threat_intel", "ml",
                "supporting_evidence", "contradicting_evidence", "missing_evidence", "mitre", "retrospection",
                "response", "verification", "provenance", "pivots")
FORBIDDEN_WORDS = ("clean", "contained", "safe")  # never emitted as a state by this view model


def _req(cond: bool, msg: str) -> None:
    if not cond:
        raise ValueError(msg)


@dataclass(frozen=True)
class Relationship:
    type: str
    source: str
    target: Optional[str]
    state: str
    evidence_refs: Tuple[str, ...] = ()
    linkage: Optional[str] = None
    reason: str = ""

    def __post_init__(self) -> None:
        _req(self.state in RELATIONSHIP_STATES, f"bad relationship state {self.state!r}")
        if self.state != "UNKNOWN":
            _req(bool(self.evidence_refs) and bool(self.target), "non-UNKNOWN relationship needs target + evidence")
        if self.state == "PROVEN_CAUSAL":
            _req(self.linkage in CAUSAL_LINKAGES, "PROVEN_CAUSAL requires a deterministic identity linkage")


@dataclass(frozen=True)
class TIResult:
    indicator: str
    indicator_type: str
    state: str
    provider: Optional[str]
    provenance: Dict[str, Any] = field(default_factory=dict, compare=False)

    def __post_init__(self) -> None:
        _req(self.state in TI_STATES, f"bad TI state {self.state!r}")
        if self.state in ("MALICIOUS", "SUSPICIOUS", "BENIGN"):
            _req(bool(self.provider), "a TI reputation claim requires provider provenance")


@dataclass(frozen=True)
class AnalystDisposition:
    value: str
    actor: str
    at: str
    note: str = ""

    def __post_init__(self) -> None:
        _req(self.value in ANALYST_DISPOSITIONS, f"bad analyst disposition {self.value!r}")
        _req(bool(self.actor) and bool(self.at), "analyst disposition requires actor and time (auditable)")


@dataclass(frozen=True)
class RetroEntry:
    version: int
    at: str
    trigger: str
    assessment: str
    evidence_refs: Tuple[str, ...]
    engine_versions: Dict[str, str] = field(default_factory=dict, compare=False)
    supersedes: Optional[int] = None

    def __post_init__(self) -> None:
        _req(self.trigger in RETRO_TRIGGERS, f"bad retro trigger {self.trigger!r}")
        _req(self.assessment in MACHINE_ASSESSMENTS, f"bad assessment {self.assessment!r}")
        _req(self.version >= 1, "versions start at 1")
        _req(self.supersedes == (None if self.version == 1 else self.version - 1),
             "each version supersedes exactly the previous one")


def validate_history(entries: List[RetroEntry]) -> Tuple[RetroEntry, ...]:
    """Append-only: versions 1..n contiguous; history is never rewritten or reordered."""
    _req([e.version for e in entries] == list(range(1, len(entries) + 1)), "assessment history is not append-only")
    return tuple(entries)


@dataclass(frozen=True)
class Section:
    key: str
    state: str
    items: Tuple[Dict[str, Any], ...] = ()
    statements: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _req(self.key in SECTION_KEYS, f"unknown section {self.key!r}")
        _req(self.state in SECTION_STATES, f"bad section state {self.state!r}")
        _req((self.state == "AVAILABLE") == bool(self.items) or self.key == "observation",
             f"{self.key}: AVAILABLE iff items present")

    def to_dict(self) -> Dict[str, Any]:
        return {"key": self.key, "state": self.state, "items": [dict(i) for i in self.items],
                "statements": list(self.statements)}


@dataclass(frozen=True)
class ActivityDetail:
    view_version: str
    tenant_id: str
    endpoint_id: Optional[str]
    subject: str
    machine_assessment: str
    analyst_disposition: Optional[AnalystDisposition]
    sections: Tuple[Section, ...]

    def __post_init__(self) -> None:
        _req(bool(self.tenant_id), "tenant_id is mandatory (no default tenant)")
        _req(self.machine_assessment in MACHINE_ASSESSMENTS, "bad machine assessment")
        _req(tuple(s.key for s in self.sections) == SECTION_KEYS, "sections must follow the §15 order")

    def section(self, key: str) -> Section:
        return self.sections[SECTION_KEYS.index(key)]

    def to_dict(self) -> Dict[str, Any]:
        d = self.analyst_disposition
        return {"view_version": self.view_version, "tenant_id": self.tenant_id, "endpoint_id": self.endpoint_id,
                "subject": self.subject, "machine_assessment": self.machine_assessment,
                "analyst_disposition": None if d is None else
                {"value": d.value, "actor": d.actor, "at": d.at, "note": d.note},
                "sections": [s.to_dict() for s in self.sections]}
