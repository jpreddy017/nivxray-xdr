"""Evidence Ledger primitives — NORTH_STAR §4, CHARTER Rule 3.

Every conclusion is a four-tuple:
    Finding · Evidence · Engine · Confidence

Enforced invariant: a Finding with zero Evidence entries is refused.
This is the "no unsupported conclusions" rule as data, not as prose.
Phase 0 defines the shape only — no engine emits Findings yet.
"""

from __future__ import annotations

from typing import List, Optional
from datetime import datetime, timezone
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Evidence(BaseModel):
    """A single observation that supports a Finding.

    `source` names the input stream / artifact the observation was
    drawn from (e.g. `"input"`, `"decode_layer[2]"`, `"strings"`).
    `detail` is a short human-readable description.
    """
    id: str = Field(default_factory=lambda: str(uuid4()))
    source: str = Field(..., min_length=1)
    detail: str = Field(..., min_length=1)
    observed_at: datetime = Field(default_factory=_utcnow)

    model_config = {"frozen": True}


class Finding(BaseModel):
    """A conclusion emitted by an engine.

    Must carry ≥1 Evidence entries. Confidence is bounded 0.0–1.0.
    Engine is the name of the emitting engine (matches the CIO
    provenance rule).
    """
    id: str = Field(default_factory=lambda: str(uuid4()))
    finding: str = Field(..., min_length=1)
    evidence: List[Evidence]
    engine: str = Field(..., min_length=1)
    confidence: float = Field(..., ge=0.0, le=1.0)
    at: datetime = Field(default_factory=_utcnow)

    @field_validator("evidence")
    @classmethod
    def _no_unsupported_conclusions(cls, v: List[Evidence]) -> List[Evidence]:
        if not v:
            raise ValueError(
                "Finding rejected — no Evidence attached. "
                "Charter Rule 3: every conclusion must cite evidence."
            )
        return v

    model_config = {"frozen": True}
