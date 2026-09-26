"""Artifact + Shape Classifier — artifact-agnostic.

Supports arbitrary artifact families (PowerShell, CMD, JavaScript,
HTA, VBA, Batch, MSI, Shellcode, Office macros, ELF, Mach-O, and any
future family). The classifier is a stable interface; concrete
family detectors are ADDED via `register_family_detector`, one per
future ADR. No concrete detector is shipped in ADR-0001.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional


@dataclass(frozen=True)
class Artifact:
    """A raw input plus optional metadata. Immutable."""
    payload: str
    kind_hint: Optional[str] = None
    tags: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class Shape:
    """Classifier output — an opaque family token + confidence + reasons."""
    family: str
    confidence: float
    reasons: List[str] = field(default_factory=list)


# Registered family detectors. Each is a callable
# `Artifact -> Optional[Shape]` returning None if the family does not match.
_DETECTORS: Dict[str, Callable[[Artifact], Optional[Shape]]] = {}


def register_family_detector(family: str, detector: Callable[[Artifact], Optional[Shape]]) -> None:
    """Register a detector for a new artifact family.

    Called ONLY from an ADR-authorised registration site. The framework
    itself does not know any families.
    """
    if not family:
        raise ValueError("family must be non-empty")
    _DETECTORS[family] = detector


def registered_families() -> List[str]:
    return sorted(_DETECTORS.keys())


def classify(artifact: Artifact) -> Shape:
    """Return the highest-confidence family match, or an `unknown` shape."""
    best: Optional[Shape] = None
    for _fam, det in _DETECTORS.items():
        try:
            candidate = det(artifact)
        except Exception:
            candidate = None
        if candidate is None:
            continue
        if best is None or candidate.confidence > best.confidence:
            best = candidate
    if best is not None:
        return best
    return Shape(family="unknown", confidence=0.0, reasons=["no registered detector matched"])
