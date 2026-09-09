"""Canonical Investigation Object (CIO) — NORTH_STAR §3.

The CIO is the append-only shape every future NivXForge engine will
read and write. Phase 0 defines the shape and the append-only
invariant. It does NOT populate any field.

Rules (enforced by tests):
  - Append-only. Existing entries are never overwritten or removed.
  - Every appended entry carries provenance (which engine, when).
  - No analytical logic lives in this file.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Provenance(BaseModel):
    """Mandatory attribution for every CIO append."""
    engine: str = Field(..., min_length=1, description="Name of the engine that produced this entry.")
    at: datetime = Field(default_factory=_utcnow)


class CIOEntry(BaseModel):
    """A single append into a CIO field. Immutable once created."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    provenance: Provenance
    payload: Dict[str, Any]

    model_config = {"frozen": True}


class Metadata(BaseModel):
    investigation_id: str = Field(default_factory=lambda: str(uuid4()))
    created_at: datetime = Field(default_factory=_utcnow)


# Every append-only collection is a list of CIOEntry so that the
# provenance and immutability rules apply uniformly across the whole
# investigation. The 15 semantic buckets are declared here for shape
# discoverability. NO engine reads or writes them in Phase 0.
class CIO(BaseModel):
    """Canonical Investigation Object — the platform's single source of truth."""

    metadata: Metadata = Field(default_factory=Metadata)
    input: List[CIOEntry] = Field(default_factory=list)
    artifacts: List[CIOEntry] = Field(default_factory=list)
    decode_layers: List[CIOEntry] = Field(default_factory=list)
    evidence: List[CIOEntry] = Field(default_factory=list)
    iocs: List[CIOEntry] = Field(default_factory=list)
    behavior: List[CIOEntry] = Field(default_factory=list)
    mitre: List[CIOEntry] = Field(default_factory=list)
    malware: List[CIOEntry] = Field(default_factory=list)
    campaign: List[CIOEntry] = Field(default_factory=list)
    threat_intel: List[CIOEntry] = Field(default_factory=list)
    knowledge_graph: List[CIOEntry] = Field(default_factory=list)
    recommendations: List[CIOEntry] = Field(default_factory=list)
    confidence: List[CIOEntry] = Field(default_factory=list)
    telemetry: List[CIOEntry] = Field(default_factory=list)
    report: List[CIOEntry] = Field(default_factory=list)

    _APPENDABLE = (
        "input", "artifacts", "decode_layers", "evidence", "iocs",
        "behavior", "mitre", "malware", "campaign", "threat_intel",
        "knowledge_graph", "recommendations", "confidence", "telemetry",
        "report",
    )

    def append(self, field: str, *, engine: str, payload: Dict[str, Any]) -> CIOEntry:
        """Append a new entry to `field`. Never mutates or removes prior entries.

        Raises ValueError if `field` is not one of the 15 semantic buckets.
        `engine` and `payload` are required — this is where the North Star
        provenance rule is enforced.
        """
        if field not in self._APPENDABLE:
            raise ValueError(
                f"CIO field {field!r} is not appendable. "
                f"Allowed: {sorted(self._APPENDABLE)}"
            )
        entry = CIOEntry(
            provenance=Provenance(engine=engine),
            payload=payload,
        )
        getattr(self, field).append(entry)
        return entry
