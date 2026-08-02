"""Stage 3 · Semantic Field Mapping.

Concept resolution — never parsing, never decoding, never investigation.

Contract (see NIVXRAY_ARCHITECTURE_VISION.md §Semantic Field Mapping):

  · Consumes ``SchemaFingerprint`` + ``ParsedInput`` (values only,
    never re-parsed) + ``semantic_alias_registry_v1``.
  · Produces ``SemanticMappingResult`` with:
        mappings · unmapped_fields · ambiguous_fields ·
        semantic_confidence · evidence · diagnostics · registry_version
  · **Every mapping is explainable.** ``FieldMapping.confidence_provenance``
    itemises every signal contribution as ``SignalContribution``
    records that sum to the final confidence.
  · Ambiguity band: two concepts within ``SEMANTIC_AMBIGUITY_THRESHOLD``
    (default 0.15, configurable) → surfaced in ``ambiguous_fields``,
    never silently resolved.
  · Never depends on vendor identity. Never performs decoding, timeline,
    ATT&CK reasoning, or IOC enrichment.
  · Never raises. Unknown / ambiguous / low-confidence are supported
    success states.

Removal test: if this subsystem is removed, the CEM cannot be built
from unseen telemetry, and Timeline / Attack Chain / Correlation /
Reasoning / Narrative all lose their canonical entities. **On the
critical path.**
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .parser import ParsedInput
from .schema_understanding import SchemaFingerprint
from .semantic_alias_registry import (
    SEMANTIC_ALIAS_REGISTRY_VERSION,
    AliasMatch,
    concepts as _all_concepts,
    lookup as _registry_lookup,
)
from .value_shape import (
    ShapeMatch,
    concept_boosts_for,
    detect_shapes,
)


# ── Tunables (single constants for future adjustment) ─────────────

SEMANTIC_AMBIGUITY_THRESHOLD: float = 0.15
"""Delta between top-two candidate confidences below which a field is
classified as ambiguous rather than mapped."""

SEMANTIC_MAPPING_MIN_CONFIDENCE: float = 0.30
"""Below this final confidence a field falls to ``unmapped_fields``."""

_MAX_SAMPLE_VALUES_PER_FIELD: int = 20
"""How many values per candidate field to sample for shape detection."""

_MAX_RECORDS_SCANNED: int = 200
"""Cap records scanned to keep Stage 3 O(N) small on huge payloads."""

_MAX_EVIDENCE_PER_MAPPING: int = 3
"""How many record-level evidence rows to preserve per mapping."""

_VALUE_PREVIEW_LIMIT: int = 96
"""Truncation length for value previews in evidence."""


# ── Data model ────────────────────────────────────────────────────

@dataclass(frozen=True)
class SignalContribution:
    """One line in the confidence provenance ledger.

    Deltas SUM to the final confidence (clamped to [0.0, 1.0]).
    """
    signal: str      # stable label, e.g. "registry_alias_match:hostname"
    delta: float     # signed contribution
    detail: str = ""


@dataclass(frozen=True)
class RejectedAlternative:
    """A competing concept that lost to the winner."""
    concept: str
    confidence: float
    reason: str


@dataclass(frozen=True)
class MappingEvidence:
    """Per-record evidence that a surface field carried the mapping."""
    field_path: str
    record_index: int
    value_preview: Optional[str]


@dataclass(frozen=True)
class FieldMapping:
    """A confidence-scored, explainable field → concept resolution."""
    surface_field: str
    normalized_surface: str
    concept: str
    confidence: float
    base_confidence: float
    matched_aliases: Tuple[str, ...]
    supporting_signals: Tuple[str, ...]
    rejected_alternatives: Tuple[RejectedAlternative, ...]
    evidence_refs: Tuple[MappingEvidence, ...]
    confidence_provenance: Tuple[SignalContribution, ...]


@dataclass(frozen=True)
class AmbiguousField:
    """Field with ≥2 concept candidates inside the ambiguity band."""
    surface_field: str
    candidates: Tuple[Tuple[str, float], ...]   # (concept, confidence)
    delta: float
    provenance: Tuple[SignalContribution, ...]


@dataclass(frozen=True)
class SemanticMappingResult:
    """Stage 3 output — always populated, never raises."""
    mappings: Tuple[FieldMapping, ...]
    unmapped_fields: Tuple[str, ...]
    ambiguous_fields: Tuple[AmbiguousField, ...]
    semantic_confidence: float
    evidence: Tuple[MappingEvidence, ...]
    diagnostics: Tuple[str, ...]
    registry_version: str


# ── Public entry point ────────────────────────────────────────────

def map_semantic_fields(fingerprint: SchemaFingerprint,
                        parsed: ParsedInput,
                        *,
                        ambiguity_threshold: float = SEMANTIC_AMBIGUITY_THRESHOLD,
                        ) -> SemanticMappingResult:
    """Resolve candidate fields to canonical concepts.

    Deterministic. Never raises. Empty candidate_fields returns a
    well-formed empty result (a supported success state).
    """
    diagnostics: List[str] = []
    records = list(parsed.records or ())[:_MAX_RECORDS_SCANNED]

    mappings: List[FieldMapping] = []
    unmapped: List[str] = []
    ambiguous: List[AmbiguousField] = []
    all_evidence: List[MappingEvidence] = []

    # 1. Precompute per-field values (bounded).
    field_values: Dict[str, List[Tuple[int, Any]]] = {
        f: _collect_values(records, f) for f in fingerprint.candidate_fields
    }

    # 2. First pass — registry + shape signals only (per field).
    per_field_candidates: Dict[str, List[_Candidate]] = {}
    for field in fingerprint.candidate_fields:
        per_field_candidates[field] = _score_field(
            field=field,
            values=field_values.get(field, []),
        )

    # 3. Sibling co-occurrence pass — bump concepts whose siblings
    #    also mapped high. Deterministic, one iteration only.
    _apply_sibling_boosts(per_field_candidates)

    # 4. Namespace-context pass — for dotted candidate fields,
    #    align with dotted parent siblings (e.g. `source.ip` +
    #    `source.port` supporting the "source" namespace family).
    _apply_namespace_boosts(per_field_candidates)

    # 5. Resolve each field to Mapped / Ambiguous / Unmapped.
    for field, cands in per_field_candidates.items():
        cands_sorted = sorted(cands, key=lambda c: -c.confidence)
        cands_sorted = [c for c in cands_sorted if c.confidence > 0.0]

        if not cands_sorted:
            unmapped.append(field)
            continue

        top = cands_sorted[0]
        if top.confidence < SEMANTIC_MAPPING_MIN_CONFIDENCE:
            unmapped.append(field)
            continue

        if len(cands_sorted) >= 2:
            delta = top.confidence - cands_sorted[1].confidence
            if delta <= ambiguity_threshold:
                ambiguous.append(AmbiguousField(
                    surface_field=field,
                    candidates=tuple(
                        (c.concept, round(c.confidence, 4))
                        for c in cands_sorted[:5]
                    ),
                    delta=round(delta, 4),
                    provenance=tuple(top.provenance),
                ))
                continue

        # Winner — assemble the FieldMapping.
        rejected = tuple(
            RejectedAlternative(
                concept=c.concept,
                confidence=round(c.confidence, 4),
                reason=(f"lost to {top.concept} by "
                        f"{round(top.confidence - c.confidence, 4)}"),
            )
            for c in cands_sorted[1:5]
        )
        evidence_refs = _build_evidence(field, field_values.get(field, []))
        all_evidence.extend(evidence_refs)

        mappings.append(FieldMapping(
            surface_field=field,
            normalized_surface=_normalize_surface(field),
            concept=top.concept,
            confidence=round(top.confidence, 4),
            base_confidence=round(top.base_confidence, 4),
            matched_aliases=tuple(top.matched_aliases),
            supporting_signals=tuple(top.supporting_signals),
            rejected_alternatives=rejected,
            evidence_refs=evidence_refs,
            confidence_provenance=tuple(top.provenance),
        ))

    # 6. Aggregate semantic_confidence = mean of accepted mappings.
    if mappings:
        agg = sum(m.confidence for m in mappings) / len(mappings)
    else:
        agg = 0.0

    if not fingerprint.candidate_fields:
        diagnostics.append(
            "schema fingerprint carried no candidate fields — "
            "supported success state"
        )

    return SemanticMappingResult(
        mappings=tuple(mappings),
        unmapped_fields=tuple(unmapped),
        ambiguous_fields=tuple(ambiguous),
        semantic_confidence=round(agg, 4),
        evidence=tuple(all_evidence),
        diagnostics=tuple(diagnostics),
        registry_version=SEMANTIC_ALIAS_REGISTRY_VERSION,
    )


# ── Internal candidate model ──────────────────────────────────────

@dataclass
class _Candidate:
    concept: str
    confidence: float
    base_confidence: float
    matched_aliases: List[str]
    supporting_signals: List[str]
    provenance: List[SignalContribution]


# ── Scoring ───────────────────────────────────────────────────────

def _score_field(field: str,
                 values: List[Tuple[int, Any]]) -> List[_Candidate]:
    """Score a single field against every concept it could match.

    Combines: registry alias match + value-shape boosts.
    Sibling / namespace boosts happen in later passes.
    """
    by_concept: Dict[str, _Candidate] = {}

    # 1. Registry alias match(es) — try both the full surface AND
    #    the leaf field name (when dotted). Nested telemetry commonly
    #    exposes surfaces like ``file.file_name`` where the semantic
    #    concept lives in the leaf token.
    surfaces_to_try: List[Tuple[str, str]] = [(field, "surface")]
    if "." in field:
        leaf = field.rsplit(".", 1)[1]
        if leaf and leaf != field:
            surfaces_to_try.append((leaf, "leaf"))

    for probe, origin in surfaces_to_try:
        for match in _registry_lookup(probe):
            cand = by_concept.setdefault(match.concept, _Candidate(
                concept=match.concept,
                confidence=0.0,
                base_confidence=0.0,
                matched_aliases=[],
                supporting_signals=[],
                provenance=[],
            ))
            signal = (f"registry_alias_match:{match.surface_normalized}"
                      + (":leaf" if origin == "leaf" else ""))
            if signal in {p.signal for p in cand.provenance}:
                continue
            # Leaf matches carry a small confidence tax to keep the
            # full-surface match preferred when both hit the same
            # concept.
            confidence = (match.confidence
                          if origin == "surface"
                          else round(match.confidence * 0.9, 4))
            cand.provenance.append(SignalContribution(
                signal=signal,
                delta=confidence,
                detail=(f"{origin} '{match.surface_normalized}' is a "
                        f"declared v1 alias for {match.concept} "
                        f"(base confidence {confidence:.2f})"),
            ))
            cand.matched_aliases.append(match.surface_normalized)
            cand.supporting_signals.append(signal)
            cand.base_confidence = max(cand.base_confidence, confidence)

    # 2. Value-shape signals — sample the field's values.
    shape_totals: Dict[Tuple[str, str], float] = {}
    shape_details: Dict[Tuple[str, str], List[ShapeMatch]] = {}
    shape_hit_counts: Dict[str, int] = {}

    for _idx, val in values[:_MAX_SAMPLE_VALUES_PER_FIELD]:
        shapes = detect_shapes(val)
        for m in shapes:
            shape_hit_counts[m.shape] = shape_hit_counts.get(m.shape, 0) + 1
        for concept, signal, delta in concept_boosts_for(shapes):
            key = (concept, signal)
            shape_totals[key] = shape_totals.get(key, 0.0) + delta
            shape_details.setdefault(key, []).extend(shapes)

    # Convert per-shape totals into per-concept contributions with a
    # cap per (concept, shape) tuple so a runaway sample doesn't
    # dominate the ledger.
    for (concept, signal), total in shape_totals.items():
        shape_name = signal.split(":", 1)[1]
        occurrences = shape_hit_counts.get(shape_name, 1)
        # cap: original per-value delta from affinity table
        cap_delta = total / occurrences if occurrences else total
        # Coverage bonus: 100% of sampled values matched → x1.0,
        # 50% → x0.75, 25% → x0.5, singleton in a large sample → x0.25.
        sampled = min(len(values), _MAX_SAMPLE_VALUES_PER_FIELD)
        coverage = occurrences / sampled if sampled else 0.0
        coverage_multiplier = max(0.25, min(1.0, 0.5 + coverage / 2))
        applied = round(cap_delta * coverage_multiplier, 4)
        if applied <= 0.0:
            continue

        cand = by_concept.setdefault(concept, _Candidate(
            concept=concept,
            confidence=0.0,
            base_confidence=0.0,
            matched_aliases=[],
            supporting_signals=[],
            provenance=[],
        ))
        cand.provenance.append(SignalContribution(
            signal=signal,
            delta=applied,
            detail=(f"{occurrences}/{sampled} sampled values matched "
                    f"shape {shape_name!r} (coverage x{coverage_multiplier:.2f})"),
        ))
        cand.supporting_signals.append(signal)

    # 3. Compute confidences (sum of provenance deltas, clamped).
    for cand in by_concept.values():
        cand.confidence = _sum_and_clamp(cand.provenance)

    return list(by_concept.values())


def _sum_and_clamp(provenance: List[SignalContribution]) -> float:
    total = sum(p.delta for p in provenance)
    if total > 1.0:
        overshoot = total - 1.0
        provenance.append(SignalContribution(
            signal="clamp_at_1.0",
            delta=-overshoot,
            detail="confidence capped at 1.0",
        ))
        total = 1.0
    if total < 0.0:
        total = 0.0
    return total


# ── Sibling co-occurrence boost ──────────────────────────────────

# Concepts that tend to appear together in the same record.
# Small, curated. Additive boost when both siblings are strong.
_SIBLING_FAMILIES: Dict[str, Tuple[str, ...]] = {
    "IP":   ("Port", "Domain", "Host"),
    "Port": ("IP", "Protocol"),
    "Host": ("User", "IP", "Domain"),
    "User": ("Host", "Process"),
    "Process": ("Command", "Host", "User", "File"),
    "Command": ("Process",),
    "File": ("Hash", "Directory", "Process"),
    "Hash": ("File",),
    "Domain": ("IP", "URL"),
    "URL": ("Domain", "IP"),
    "Registry": ("Process", "User"),
}


def _apply_sibling_boosts(per_field: Dict[str, List[_Candidate]]) -> None:
    # Which concepts already have a strong candidate?
    strong_concepts: set = set()
    for cands in per_field.values():
        for c in cands:
            if c.confidence >= 0.60:
                strong_concepts.add(c.concept)

    if not strong_concepts:
        return

    for field, cands in per_field.items():
        for cand in cands:
            allies = set(_SIBLING_FAMILIES.get(cand.concept, ()))
            hits = allies & strong_concepts
            if not hits:
                continue
            delta = min(0.10, 0.03 * len(hits))
            signal = f"sibling_concept:{','.join(sorted(hits))}"
            if signal in {p.signal for p in cand.provenance}:
                continue
            cand.provenance.append(SignalContribution(
                signal=signal,
                delta=delta,
                detail=(f"sibling concept(s) present with strong "
                        f"mapping in the same telemetry: "
                        f"{', '.join(sorted(hits))}"),
            ))
            cand.supporting_signals.append(signal)
            cand.confidence = _sum_and_clamp(cand.provenance)


# ── Namespace context boost ──────────────────────────────────────

# Dotted namespaces that thematically group concepts.
_NAMESPACE_FAMILIES: Dict[str, Tuple[str, ...]] = {
    "source":      ("IP", "Port", "Host", "User"),
    "destination": ("IP", "Port", "Host"),
    "client":      ("IP", "Port", "Host", "User"),
    "server":      ("IP", "Port", "Host"),
    "host":        ("Host", "IP"),
    "user":        ("User",),
    "process":     ("Process", "Command"),
    "parent":      ("Process", "Command"),
    "file":        ("File", "Hash", "Directory"),
    "network":     ("IP", "Port", "Protocol", "Domain"),
    "url":         ("URL", "Domain"),
    "dns":         ("Domain", "IP", "Protocol"),
    "registry":    ("Registry",),
}


def _apply_namespace_boosts(per_field: Dict[str, List[_Candidate]]) -> None:
    for field, cands in per_field.items():
        if "." not in field:
            continue
        head = field.split(".", 1)[0].lower()
        family = set(_NAMESPACE_FAMILIES.get(head, ()))
        if not family:
            continue
        for cand in cands:
            if cand.concept not in family:
                continue
            signal = f"namespace_context:{head}"
            if signal in {p.signal for p in cand.provenance}:
                continue
            cand.provenance.append(SignalContribution(
                signal=signal,
                delta=0.05,
                detail=(f"dotted parent namespace '{head}' groups "
                        f"the concept family "
                        f"{sorted(family)}"),
            ))
            cand.supporting_signals.append(signal)
            cand.confidence = _sum_and_clamp(cand.provenance)


# ── Utilities ────────────────────────────────────────────────────

def _normalize_surface(field: str) -> str:
    """Same normalization as semantic_alias_registry, private copy
    to avoid coupling to a private symbol."""
    out = []
    for ch in field.lower():
        if ch in ("_", "-", ".", " ", "\t"):
            continue
        out.append(ch)
    return "".join(out)


def _collect_values(records: List[Dict[str, Any]],
                    field_path: str) -> List[Tuple[int, Any]]:
    """Return up to _MAX_SAMPLE_VALUES_PER_FIELD (record_idx, value)
    pairs for a field path. Handles dotted paths against nested
    objects."""
    out: List[Tuple[int, Any]] = []
    parts = field_path.split(".") if "." in field_path else [field_path]

    for idx, rec in enumerate(records):
        if not isinstance(rec, dict):
            continue
        val: Any = rec
        for part in parts:
            if isinstance(val, dict) and part in val:
                val = val[part]
            else:
                val = None
                break
        if val is None:
            # Also accept dotted keys as literal keys (already flattened
            # by Schema Understanding on some inputs).
            if field_path in rec:
                val = rec[field_path]
        if val is None:
            continue
        out.append((idx, val))
        if len(out) >= _MAX_SAMPLE_VALUES_PER_FIELD:
            break
    return out


def _build_evidence(field: str,
                    values: List[Tuple[int, Any]]
                    ) -> Tuple[MappingEvidence, ...]:
    out: List[MappingEvidence] = []
    for record_idx, val in values[:_MAX_EVIDENCE_PER_MAPPING]:
        preview = _value_preview(val)
        out.append(MappingEvidence(
            field_path=field,
            record_index=record_idx,
            value_preview=preview,
        ))
    return tuple(out)


def _value_preview(val: Any) -> Optional[str]:
    if val is None:
        return None
    s = str(val)
    if len(s) > _VALUE_PREVIEW_LIMIT:
        s = s[:_VALUE_PREVIEW_LIMIT - 1] + "…"
    return s


__all__ = [
    "SEMANTIC_AMBIGUITY_THRESHOLD",
    "SEMANTIC_MAPPING_MIN_CONFIDENCE",
    "SignalContribution",
    "RejectedAlternative",
    "MappingEvidence",
    "FieldMapping",
    "AmbiguousField",
    "SemanticMappingResult",
    "map_semantic_fields",
]
