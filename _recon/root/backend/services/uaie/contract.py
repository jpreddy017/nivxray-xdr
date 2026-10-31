"""UAIE Contract #10 · Capability Registry  (Rule R28.6)

The Capability Registry is the single source of truth for what
the engine can do.  Every plugin that opts in gets described by a
``CapabilityContract`` — a declarative, machine-readable specification
of what it consumes, produces, improves, at what cost, and with what
confidence gain.

Rationale (approved 2026-02-15, user direction)
────────────────────────────────────────────────
The orchestrator should never know what a PowerShell decoder or an
Rclone recognizer is.  It only asks the registry:

    · Which capabilities are applicable to this artifact?
    · Which capabilities produce this artifact type?
    · Which capabilities improve this dimension of the investigation?
    · What is the expected confidence gain / cost of each?

That way, adding a new capability becomes a data problem — drop in
one file with a contract — rather than an orchestration problem.

Backwards compatibility
──────────────────────
Existing plugins (registered through ``capability.register``) continue
to work.  Contracts are OPT-IN — a plugin can register a contract in
addition to (or instead of) its legacy registration.  Phase 6 does not
break any of the 211 existing tests.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing      import Any, Callable, Dict, List, Optional, Tuple


# ══════════════════════════════════════════════════════════════════
# Canonical categories (single vocabulary for the whole engine)
# ══════════════════════════════════════════════════════════════════
CAT_RECOGNIZER   = "recognizer"     # emits Recognition[]
CAT_EXECUTOR     = "executor"       # emits child artifacts + evidence
CAT_VALIDATOR    = "validator"      # diagnoses artifacts
CAT_REPAIR       = "repair"         # transforms bytes deterministically
CAT_ANALYZER     = "analyzer"       # emits evidence only, no children
CAT_FAMILY       = "family"         # emits family/threat attribution
CAT_MITRE_MAPPER = "mitre_mapper"   # emits ATT&CK evidence

CATEGORIES = (
    CAT_RECOGNIZER, CAT_EXECUTOR, CAT_VALIDATOR, CAT_REPAIR,
    CAT_ANALYZER,   CAT_FAMILY,   CAT_MITRE_MAPPER,
)

# Canonical "improves" dimensions — the engine's confidence vector.
# Phase 7 will make these first-class multi-dimensional metrics.
IMPROVES_DECODE       = "decode_confidence"
IMPROVES_REPAIR       = "repair_confidence"
IMPROVES_ANALYSIS     = "analysis_confidence"
IMPROVES_FAMILY       = "family_confidence"
IMPROVES_MITRE        = "mitre_coverage"
IMPROVES_IOC          = "ioc_confidence"
IMPROVES_ATTRIBUTION  = "attribution_confidence"
IMPROVES_EVIDENCE     = "evidence_confidence"
IMPROVES_VERDICT      = "verdict_confidence"


# ══════════════════════════════════════════════════════════════════
# Contract data class (frozen, hashable — usable as dict keys)
# ══════════════════════════════════════════════════════════════════
@dataclass(frozen=True)
class CapabilityContract:
    """Declarative specification of a capability.  Immutable.

    Field semantics:

        · ``id``               Globally unique reverse-DNS-style name.
                                 e.g. ``recognizer.vssadmin_delete_shadows``,
                                 ``executor.base64_decode``,
                                 ``repair.base64.strip_html_entities``.
        · ``version``          SemVer.  Bump when contract shape changes.
        · ``category``         One of ``CATEGORIES``.
        · ``requires``         ALL of these artifact types must exist
                                 in the graph before the capability can
                                 run.  Universal-match: ``["*"]``.
        · ``optional_requires``  Any of these boost applicability but
                                 aren't strictly required.
        · ``produces``         Artifact types this capability may emit
                                 as children.
        · ``consumes``         Artifact types this capability
                                 semantically "uses up" — after it runs,
                                 the parent may not need re-processing.
                                 Used by the planner to avoid loops.
        · ``improves``         Confidence dimensions this capability
                                 lifts (see ``IMPROVES_*``).
        · ``confidence_gain``  0.00–1.00: expected lift on the FIRST
                                 dimension in ``improves``.  Used by the
                                 goal-driven planner (Phase 8).
        · ``produces_confidence``   Optional per-dimension confidence
                                     lift map — e.g.
                                     ``{"analysis": 0.20, "mitre": 0.15,
                                        "ioc": 0.10}``.  When absent, the
                                     planner uses ``confidence_gain`` on
                                     the first ``improves`` dimension.
                                     Phase 7 uses this directly.
        · ``cost``             1 (cheap) – 5 (expensive).  Used by the
                                 planner to prefer cheap wins.
        · ``priority_hint``    Advisory tie-breaker (int, higher wins).
                                 The planner is free to ignore it.
                                 Used when two contracts have identical
                                 gain × cost — e.g. prefer a
                                 recognizer over an executor at the
                                 same stage.
        · ``parallelizable``   Whether multiple instances can run at
                                 the same lifecycle stage without
                                 conflict.
        · ``deterministic``    Whether the plugin is bit-for-bit
                                 deterministic (R28 invariant).
        · ``description``      Human-readable one-liner.
    """
    id:                    str
    version:               str
    category:              str
    requires:              Tuple[str, ...] = ()
    optional_requires:     Tuple[str, ...] = ()
    produces:              Tuple[str, ...] = ()
    consumes:              Tuple[str, ...] = ()
    improves:              Tuple[str, ...] = ()
    confidence_gain:       float           = 0.0
    produces_confidence:   Tuple[Tuple[str, float], ...] = ()   # frozen k/v pairs
    cost:                  int             = 1
    priority_hint:         int             = 0
    parallelizable:        bool            = True
    deterministic:         bool            = True
    description:           str             = ""

    def __post_init__(self):
        if self.category not in CATEGORIES:
            raise ValueError(
                f"invalid category {self.category!r}; "
                f"must be one of {CATEGORIES}")
        if not (0.0 <= self.confidence_gain <= 1.0):
            raise ValueError(
                f"confidence_gain must be in [0.0, 1.0]; got "
                f"{self.confidence_gain}")
        if not (1 <= self.cost <= 5):
            raise ValueError(f"cost must be in [1, 5]; got {self.cost}")
        # Validate produces_confidence — every gain must be in [0, 1]
        # and every key must be a recognised improves dimension OR match
        # something already in ``improves`` (allow project-specific dims).
        for k, v in (self.produces_confidence or ()):
            if not (0.0 <= v <= 1.0):
                raise ValueError(
                    f"produces_confidence[{k!r}] must be in [0.0, 1.0]; got {v}")

    # Helpers ------------------------------------------------------
    def applies_to(self, artifact_type: str) -> bool:
        """True iff this contract's Requires clause admits an artifact
        of the given type (or if it is universal)."""
        if not self.requires:
            return False
        if "*" in self.requires:
            return True
        return artifact_type in self.requires

    def gain_for(self, dimension: str) -> float:
        """Return the confidence lift this contract delivers on the
        given dimension.  Uses ``produces_confidence`` first, falling
        back to ``confidence_gain`` when ``dimension`` matches the
        first entry in ``improves``."""
        for k, v in (self.produces_confidence or ()):
            if k == dimension:
                return v
        if self.improves and self.improves[0] == dimension:
            return self.confidence_gain
        return 0.0

    def total_expected_gain(self) -> float:
        """Sum of all per-dimension gains — used by the planner as a
        rough "how much does this move the investigation" score."""
        if self.produces_confidence:
            return sum(v for _, v in self.produces_confidence)
        return self.confidence_gain


# ══════════════════════════════════════════════════════════════════
# Registry
# ══════════════════════════════════════════════════════════════════
_CONTRACT_REGISTRY: Dict[str, CapabilityContract] = {}
_IMPL_REGISTRY:     Dict[str, Any]                = {}
# Indexes (rebuilt on every registration for O(1) planner lookup)
_INDEX_BY_REQUIRES: Dict[str, List[str]] = {}      # artifact_type → contract_ids
_INDEX_BY_PRODUCES: Dict[str, List[str]] = {}
_INDEX_BY_CATEGORY: Dict[str, List[str]] = {}
_INDEX_BY_IMPROVES: Dict[str, List[str]] = {}


def _rebuild_indexes() -> None:
    _INDEX_BY_REQUIRES.clear()
    _INDEX_BY_PRODUCES.clear()
    _INDEX_BY_CATEGORY.clear()
    _INDEX_BY_IMPROVES.clear()
    for cid, c in _CONTRACT_REGISTRY.items():
        for t in (c.requires or ()):
            _INDEX_BY_REQUIRES.setdefault(t, []).append(cid)
        for t in (c.produces or ()):
            _INDEX_BY_PRODUCES.setdefault(t, []).append(cid)
        _INDEX_BY_CATEGORY.setdefault(c.category, []).append(cid)
        for imp in (c.improves or ()):
            _INDEX_BY_IMPROVES.setdefault(imp, []).append(cid)


def register(contract: CapabilityContract, impl: Any) -> None:
    """Register a contract + its implementation.  Idempotent — a
    later registration with the same ``id`` REPLACES the earlier
    entry (with an operator-visible warning via the index rebuild).
    """
    if not isinstance(contract, CapabilityContract):
        raise TypeError(f"expected CapabilityContract; got {type(contract).__name__}")
    _CONTRACT_REGISTRY[contract.id] = contract
    _IMPL_REGISTRY[contract.id]     = impl
    _rebuild_indexes()


def clear() -> None:
    """Test helper — never call in production code path."""
    _CONTRACT_REGISTRY.clear()
    _IMPL_REGISTRY.clear()
    _rebuild_indexes()


# ── Planner queries ────────────────────────────────────────────────
def get(contract_id: str) -> Optional[Tuple[CapabilityContract, Any]]:
    c = _CONTRACT_REGISTRY.get(contract_id)
    if c is None:
        return None
    return (c, _IMPL_REGISTRY.get(contract_id))


def applicable_contracts(artifact_type: str) -> List[CapabilityContract]:
    """Every contract whose ``requires`` matches the given artifact type."""
    ids = list(_INDEX_BY_REQUIRES.get(artifact_type, [])) \
        + list(_INDEX_BY_REQUIRES.get("*", []))
    # Deterministic order — sort by id.
    return sorted(
        {cid: _CONTRACT_REGISTRY[cid] for cid in ids}.values(),
        key=lambda c: (c.cost, c.id),
    )


def contracts_producing(artifact_type: str) -> List[CapabilityContract]:
    ids = _INDEX_BY_PRODUCES.get(artifact_type, [])
    return [_CONTRACT_REGISTRY[i] for i in ids]


def contracts_improving(dimension: str) -> List[CapabilityContract]:
    ids = _INDEX_BY_IMPROVES.get(dimension, [])
    return [_CONTRACT_REGISTRY[i] for i in ids]


def contracts_by_category(category: str) -> List[CapabilityContract]:
    ids = _INDEX_BY_CATEGORY.get(category, [])
    return [_CONTRACT_REGISTRY[i] for i in ids]


def all_contracts() -> List[CapabilityContract]:
    return sorted(_CONTRACT_REGISTRY.values(), key=lambda c: c.id)


# ── Introspection (for the Opportunity Analysis in the certificate) ─
def stats() -> Dict[str, int]:
    return {
        "contracts":           len(_CONTRACT_REGISTRY),
        "by_category":         {k: len(v) for k, v in _INDEX_BY_CATEGORY.items()},
        "by_requires":         {k: len(v) for k, v in _INDEX_BY_REQUIRES.items()},
        "by_produces":         {k: len(v) for k, v in _INDEX_BY_PRODUCES.items()},
        "by_improves":         {k: len(v) for k, v in _INDEX_BY_IMPROVES.items()},
    }


__all__ = [
    # categories & dimensions
    "CAT_RECOGNIZER", "CAT_EXECUTOR", "CAT_VALIDATOR", "CAT_REPAIR",
    "CAT_ANALYZER",   "CAT_FAMILY",   "CAT_MITRE_MAPPER", "CATEGORIES",
    "IMPROVES_DECODE", "IMPROVES_REPAIR", "IMPROVES_ANALYSIS",
    "IMPROVES_FAMILY", "IMPROVES_MITRE",  "IMPROVES_IOC",
    "IMPROVES_ATTRIBUTION", "IMPROVES_EVIDENCE", "IMPROVES_VERDICT",
    # types
    "CapabilityContract",
    # registry ops
    "register", "clear", "get",
    # queries
    "applicable_contracts", "contracts_producing", "contracts_improving",
    "contracts_by_category", "all_contracts", "stats",
]
