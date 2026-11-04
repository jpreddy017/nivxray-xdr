"""Artifact Intelligence Layer — deterministic dispatcher for
specialized analyzers.

Phase 3 · Cycle A · owner-approved 2026-02.

Philosophy (mirrors Technique Detector registry · Rule 26):

    IEDDE
       ↓
    Canonical Artifact
       ↓
    Artifact Intelligence Layer  (this module)
       │
       ├── classify by magic + heuristics
       ├── dispatch to registered analyzer
       ├── expose capability_available per analyzer
       └── gracefully degrade when a library is missing

Analyzer contract:
    class Analyzer:
        artifact_type: str          # canonical id (pe, pdf, elf, ...)
        display_name: str           # human-facing label
        magic_matcher: (bytes) -> confidence 0-100 | None
        is_available(): bool        # capability check (lib installed?)
        analyze(bytes): dict        # deterministic structured report

Each analyzer registers itself once via `register()`. Adding a new
type (e.g. APK) requires only:

    class ApkAnalyzer(Analyzer): ...
    register(ApkAnalyzer())

The router never grows conditional branches per type — new analyzers
plug in cleanly, exactly like the Technique Detector plugins.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Protocol, runtime_checkable


# ─── Analyzer contract ─────────────────────────────────────────────────
@runtime_checkable
class Analyzer(Protocol):
    """Protocol every artifact analyzer implements."""
    artifact_type: str
    display_name: str

    def magic_matcher(self, data: bytes) -> Optional[int]:
        """Return a 0-100 confidence score if `data` looks like this
        artifact type, or None if not applicable. Must be cheap — invoked
        for every dispatch call."""

    def is_available(self) -> bool:
        """True iff the underlying parser library is importable in this
        deployment. Used for graceful degradation."""

    def analyze(self, data: bytes) -> Dict[str, Any]:
        """Deterministic structured analysis report. Must return a dict
        with at least `available: bool` — never raise."""


# ─── Analysis result contract ─────────────────────────────────────────
@dataclass
class AnalysisResult:
    """Return of `dispatch(bytes)`.

    Contract for consumers (Workspace panel, downstream analyzers):
        • `artifact_type` is either a registered analyzer id or `unknown`
        • `analysis` is always a dict with `available: bool`; when the
          library is missing or the payload does not parse, the dict
          carries a reasoned `error` / `reason` and `message` field.
        • `hashes` is computed centrally for every artifact.
    """
    artifact_type: str
    display_name: str
    confidence: int                         # 0-100
    size: int
    hashes: Dict[str, str]
    analysis: Dict[str, Any]
    capability_available: bool
    detected_by: str                        # magic-byte | zip-content | heuristic
    fallback_reason: Optional[str] = None   # populated when unknown/degraded

    def to_dict(self) -> Dict[str, Any]:
        return {
            "artifact_type":        self.artifact_type,
            "display_name":         self.display_name,
            "confidence":           self.confidence,
            "size":                 self.size,
            "hashes":               dict(self.hashes),
            "analysis":             dict(self.analysis),
            "capability_available": self.capability_available,
            "detected_by":          self.detected_by,
            "fallback_reason":      self.fallback_reason,
        }


# ─── Registry ─────────────────────────────────────────────────────────
_REGISTRY: List[Analyzer] = []


def register(analyzer: Analyzer) -> None:
    """Register a new artifact analyzer. Idempotent by artifact_type."""
    for i, existing in enumerate(_REGISTRY):
        if existing.artifact_type == analyzer.artifact_type:
            _REGISTRY[i] = analyzer
            return
    _REGISTRY.append(analyzer)


def registered_types() -> List[Dict[str, Any]]:
    """Public introspection — used by `/api/artifacts/capabilities`."""
    return [
        {
            "artifact_type": a.artifact_type,
            "display_name":  a.display_name,
            "available":     a.is_available(),
        }
        for a in _REGISTRY
    ]


def _hash(data: bytes) -> Dict[str, str]:
    return {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


# ─── Dispatcher ───────────────────────────────────────────────────────
def dispatch(data: bytes) -> AnalysisResult:
    """Route `data` to the best-matching registered analyzer.

    Deterministic — never raises. Returns an `AnalysisResult` with
    `artifact_type='unknown'` when no analyzer claims the payload.
    """
    if not isinstance(data, (bytes, bytearray)):
        return _unknown(b"", "input_not_bytes")
    data = bytes(data)
    if len(data) < 4:
        return _unknown(data, "input_too_small")

    # Score every analyzer and take the highest-confidence hit.
    best: Optional[Analyzer] = None
    best_score = 0
    for a in _REGISTRY:
        try:
            score = a.magic_matcher(data)
        except Exception:
            score = None
        if score is not None and score > best_score:
            best, best_score = a, score

    if best is None:
        return _unknown(data, "no_analyzer_claimed_the_payload")

    capability = False
    try:
        capability = bool(best.is_available())
    except Exception:
        capability = False

    if not capability:
        # Analyzer claims the artifact type but the parser lib is missing.
        # Return a graceful "capability unavailable" analysis dict — the
        # frontend renders the reasoned unavailable card.
        analysis = {
            "available": False,
            "reason":   "capability_unavailable",
            "message":  (
                f"{best.display_name} analysis capability unavailable — the "
                "underlying parser library is not installed in this deployment."
            ),
        }
        return AnalysisResult(
            artifact_type=best.artifact_type,
            display_name=best.display_name,
            confidence=int(best_score),
            size=len(data),
            hashes=_hash(data),
            analysis=analysis,
            capability_available=False,
            detected_by="magic",
            fallback_reason="parser_library_missing",
        )

    try:
        analysis = best.analyze(data)
    except Exception as e:
        analysis = {
            "available": True,
            "error":     "analyzer_exception",
            "message":   f"{type(e).__name__}: {e}",
        }

    return AnalysisResult(
        artifact_type=best.artifact_type,
        display_name=best.display_name,
        confidence=int(best_score),
        size=len(data),
        hashes=_hash(data),
        analysis=analysis,
        capability_available=True,
        detected_by="magic",
    )


def _unknown(data: bytes, reason: str) -> AnalysisResult:
    return AnalysisResult(
        artifact_type="unknown",
        display_name="Unknown artifact",
        confidence=0,
        size=len(data),
        hashes=_hash(data) if data else {"md5": "", "sha1": "", "sha256": ""},
        analysis={
            "available": True,
            "error":     "unknown_artifact_type",
            "message":   (
                "No specialized analyzer claimed the payload. The IEDDE "
                "canonical output is still available in the Decode panel."
            ),
        },
        capability_available=False,
        detected_by="none",
        fallback_reason=reason,
    )


__all__ = ["Analyzer", "AnalysisResult", "register", "registered_types", "dispatch"]

# Import analyzers so they self-register. Placed at the END so `register`
# and `dispatch` are already defined at import time.
from . import analyzers  # noqa: E402,F401
