"""UAIE Contract #3 · Capability + Registry (Rule R25)

Capability answers: "given this artifact type, what can I do?"
It performs a bounded analysis and emits (evidence, child_artifacts).
Capabilities NEVER call each other — declared dependencies only.

Capability Registry maps artifact_type → List[Capability].  Recognizers
do NOT know which capabilities exist; the registry is the source of
truth.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing      import Any, Dict, List, Optional, Protocol, runtime_checkable

from .artifact import Artifact


@dataclass(frozen=True)
class CapabilityResult:
    """A Capability's structured output."""
    evidence:        List["Evidence"]                = field(default_factory=list)  # forward-ref, resolved at import time
    child_artifacts: List[Artifact]                  = field(default_factory=list)
    notes:           Dict[str, Any]                  = field(default_factory=dict)
    elapsed_ms:      float                           = 0.0
    failed:          bool                            = False
    error:           Optional[str]                   = None


@runtime_checkable
class Capability(Protocol):
    """Every Capability declares its dependencies and executes on a
    single Artifact.  Pure function — same input → same output."""

    name:                    str
    requires_artifact_type:  List[str]     # e.g. ["gzip"] · empty list = universal
    requires_evidence:       List[str]     # optional prerequisites · e.g. ["shellcode_strings"]

    def execute(self, artifact: Artifact) -> CapabilityResult: ...


# ══════════════════════════════════════════════════════════════════
# Registry — flat, discovery-friendly, no core changes to add plugins
# ══════════════════════════════════════════════════════════════════
_REGISTRY: Dict[str, List[Capability]] = {}


def register(capability: Capability) -> None:
    for t in (capability.requires_artifact_type or ["*"]):
        _REGISTRY.setdefault(t, []).append(capability)


def for_type(artifact_type: str) -> List[Capability]:
    return list(_REGISTRY.get(artifact_type, [])) + list(_REGISTRY.get("*", []))


def all_registered() -> Dict[str, List[str]]:
    return {t: [c.name for c in caps] for t, caps in _REGISTRY.items()}


def clear() -> None:
    """Test helper — never call in production code path."""
    _REGISTRY.clear()


# Resolve the forward reference at import time.
from .evidence import Evidence  # noqa: E402,F401  — needed by CapabilityResult
