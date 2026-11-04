"""GATE 3 · the analyzer registry — a CONTRACT, not documentation.

Same style as `services.edr.endpoint_query.ENDPOINT_KEYED_STORES`: the
structural test reads this registry, so an analyzer cannot be wired into
the fabric without declaring its class, version, inference location and
its own capability limits.

Execution order is deliberately NOT expressed here. Findings are
additive and the verdict composes them deterministically, which is what
lets an endpoint-side analyzer (Gate 4, offline protection) contribute
findings the backend joins rather than recomputes.
"""
from __future__ import annotations

from typing import Dict, List, Protocol, runtime_checkable

from edr_plane.fabric.contracts import (AnalyzerClass, AnalyzerResult,
                                        Capability, EvidenceUnit,
                                        InferenceLocation)


@runtime_checkable
class Analyzer(Protocol):
    id: str
    analyzer_class: AnalyzerClass
    version: str
    inference_location: InferenceLocation

    def capability(self) -> Capability: ...

    def evaluate(self, unit: EvidenceUnit) -> AnalyzerResult: ...


_REGISTRY: Dict[str, Analyzer] = {}


def register(analyzer: Analyzer) -> Analyzer:
    for attr in ("id", "analyzer_class", "version", "inference_location"):
        if not getattr(analyzer, attr, None):
            raise ValueError(f"an analyzer must declare {attr} before it can "
                             f"be registered in the detection fabric")
    if analyzer.id in _REGISTRY:
        raise ValueError(f"analyzer id already registered: {analyzer.id}")
    _REGISTRY[analyzer.id] = analyzer
    return analyzer


def analyzers() -> List[Analyzer]:
    return list(_REGISTRY.values())


def get(analyzer_id: str) -> Analyzer:
    return _REGISTRY[analyzer_id]


def declared_capabilities() -> List[Dict[str, object]]:
    """What the fabric can and cannot evaluate today, for the console.

    This is the honest answer to "is this endpoint protected?" — it
    reports the engines that exist, with their own stated blind spots,
    instead of a green tick.
    """
    out = []
    for a in analyzers():
        cap = a.capability()
        out.append({"analyzer_id": a.id,
                    "analyzer_class": a.analyzer_class.value
                    if hasattr(a.analyzer_class, "value")
                    else a.analyzer_class,
                    "version": a.version,
                    "inference_location": a.inference_location.value
                    if hasattr(a.inference_location, "value")
                    else a.inference_location,
                    "evaluates": cap.evaluates,
                    "cannot": cap.cannot,
                    "requires": cap.requires})
    return out
