"""Adapter protocol + registry + input router."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Protocol, Tuple

from ..artifact import Artifact, make_artifact


@dataclass(frozen=True)
class AdapterResult:
    """Adapter output — a small bundle of artifacts + diagnostics.

    All fields default to empty so an adapter can emit any subset.
    ``artifacts`` MUST contain at least one artifact — the invariant
    guarantees the orchestrator always has something to plan on.
    """
    artifacts:   List[Artifact]          = field(default_factory=list)
    diagnostics: List[Dict[str, Any]]    = field(default_factory=list)
    meta:        Dict[str, Any]          = field(default_factory=dict)


class Adapter(Protocol):
    """Convert one unstructured input blob into typed artifacts.

    Adapters are DETERMINISTIC and format-only.  They never make
    security decisions, never recurse on their own outputs, never
    invoke other adapters.  The UAIE orchestrator does all recursion.
    """
    name:     str
    priority: int   # higher wins on ties

    def sniff(self, payload: bytes,
                *, filename: Optional[str] = None,
                declared_mime: Optional[str] = None) -> int:
        """Return a 0..100 confidence that this adapter should handle
        the input.  0 = don't touch it.  100 = only-me.  Selection
        is (priority, confidence)-ordered."""
        ...

    def extract(self, payload: bytes,
                  *, filename: Optional[str] = None) -> AdapterResult:
        """Emit at least one artifact.  Never raise on well-formed
        input.  If the input is malformed, emit a diagnostic-tagged
        ``raw_bytes`` artifact and record the failure in
        ``diagnostics``."""
        ...


# ── Registry ─────────────────────────────────────────────────────
adapter_registry: List[Adapter] = []


def register_adapter(adapter: Adapter) -> None:
    """Register an adapter.  Idempotent — same-named adapter is
    replaced so re-imports in pytest don't duplicate."""
    global adapter_registry
    adapter_registry[:] = [a for a in adapter_registry
                              if a.name != adapter.name]
    adapter_registry.append(adapter)


# ── Router ───────────────────────────────────────────────────────
def route_input(payload: bytes,
                  *, filename: Optional[str] = None,
                  declared_mime: Optional[str] = None) -> AdapterResult:
    """Pick the best adapter and run it.

    Ranking is (adapter.sniff(...), adapter.priority) — tie-break by
    declaration order so results are deterministic.

    If NO adapter claims the input, we still emit a single
    ``raw_bytes`` artifact carrying the original payload so the
    orchestrator has something to run recognizers on.  This keeps
    the pipeline artifact-first even for unrecognised binaries.
    """
    if not payload:
        # Explicit empty-input handling — emit a stub so downstream
        # never encounters ``None`` artifacts.
        art = make_artifact(
            b"", "empty_input",
            discovered_by="adapter.router",
            meta={"reason": "empty_payload"},
        )
        return AdapterResult(
            artifacts=[art],
            diagnostics=[{"code": "DX_EMPTY_INPUT",
                             "severity": "info",
                             "reason": "empty payload"}],
        )
    ranked: List[Tuple[int, int, Adapter]] = []
    for a in adapter_registry:
        try:
            conf = int(a.sniff(payload, filename=filename,
                                declared_mime=declared_mime))
        except Exception:
            conf = 0
        if conf > 0:
            ranked.append((conf, a.priority, a))
    if not ranked:
        # Fallback — emit raw bytes so UAIE can still run
        # magic-byte recognizers and generic string extractors.
        art = make_artifact(
            payload, "raw_bytes",
            discovered_by="adapter.router",
            meta={"reason": "no_adapter_claimed",
                    "filename": filename},
        )
        return AdapterResult(
            artifacts=[art],
            diagnostics=[{"code": "DX_NO_ADAPTER",
                             "severity": "info",
                             "reason": "no adapter claimed the input"}],
            meta={"selected_adapter": None},
        )
    ranked.sort(key=lambda t: (t[0], t[1]), reverse=True)
    _, _, chosen = ranked[0]
    result = chosen.extract(payload, filename=filename)
    # Enrich meta so downstream can trace the routing decision.
    meta = dict(result.meta or {})
    meta["selected_adapter"] = chosen.name
    meta["candidate_ranking"] = [
        {"adapter": a.name, "sniff": c, "priority": p}
        for c, p, a in ranked[:5]
    ]
    return AdapterResult(
        artifacts=list(result.artifacts),
        diagnostics=list(result.diagnostics or []),
        meta=meta,
    )
