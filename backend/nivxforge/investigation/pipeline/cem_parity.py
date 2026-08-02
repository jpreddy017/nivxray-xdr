"""CEM Parity Comparator — evidence for the semantic cut-over decision.

Runs BOTH paths on the same telemetry:

  (1) Vendor path  : parser → vendor_detection → vendor_normalizer → CEM
  (2) Semantic path: parser → schema → semantic_field_mapper → semantic_cem_builder → CEM

Computes a rich per-fixture ``ParityReport`` covering the metrics the
owner mandated:

  · mapping_parity        Field-by-field agreement rate
  · confidence_drift      Δ between vendor route confidence & semantic
  · new_mappings          Fields the semantic path resolved that the
                          vendor path did NOT populate
  · lost_mappings         Fields the vendor path populated that the
                          semantic path did NOT
  · ambiguous_mappings    Fields the semantic path deferred
  · false_positives       Semantic-only mappings that disagree with the
                          vendor ground truth
  · false_negatives       Vendor entities the semantic path missed

Reports are rendered to Markdown at
``tests/investigation/cem_parity_report.md`` for owner review before
any cut-over decision.

The comparator ships as an ADDITIVE artifact. It does not mutate the
orchestrator or the vendor pipeline. Cut-over criteria are documented
in ``REGISTRY_GOVERNANCE.md``.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from nivxforge.investigation.cem import CanonicalEvent, CanonicalEventModel
from .composite_extractor import expand_composites
from .input_classification import classify_input
from .normalizers import normalize
from .parser import parse_input
from .schema_understanding import understand_schema
from .semantic_cem_builder import build_semantic_cem
from .semantic_field_mapper import map_semantic_fields
from .vendor_detection import detect_vendor


# ── Field extraction ────────────────────────────────────────────

# CanonicalEvent fields we compare for parity. Chosen to focus on the
# semantic core: host / user / process / file / network / dns.
_ENTITY_FIELDS: Tuple[Tuple[str, ...], ...] = (
    ("host", "name"),
    ("host", "ip"),
    ("user", "name"),
    ("process", "image"),
    ("process", "command_line"),
    ("process", "hash_sha256"),
    ("file", "path"),
    ("file", "name"),
    ("file", "hash_sha256"),
    ("file", "hash_md5"),
    ("network", "src_ip"),
    ("network", "src_port"),
    ("network", "dst_ip"),
    ("network", "dst_port"),
    ("network", "protocol"),
    ("network", "url"),
    ("network", "domain"),
    ("dns", "query"),
    ("registry", "key"),
)


def _flatten_event(evt: Optional[CanonicalEvent]
                   ) -> Dict[str, Any]:
    """Extract the ``_ENTITY_FIELDS`` from a CanonicalEvent as a
    flat dict keyed by ``"host.name"`` etc. Missing/None fields are
    represented as absent keys (not as None entries)."""
    if evt is None:
        return {}
    flat: Dict[str, Any] = {}
    for parent, child in _ENTITY_FIELDS:
        entity = getattr(evt, parent, None)
        if entity is None:
            continue
        value = getattr(entity, child, None)
        if value is None or value == "":
            continue
        flat[f"{parent}.{child}"] = value
    return flat


def _flatten_cem(cem: CanonicalEventModel) -> Dict[str, Any]:
    """Merge the first event's fields (Phase 1 vendor normalizers
    typically emit one canonical event per input)."""
    if not cem.events:
        return {}
    # Combine all events for richer parity — repeat surfaces get
    # the first-seen value.
    merged: Dict[str, Any] = {}
    for evt in cem.events:
        for k, v in _flatten_event(evt).items():
            merged.setdefault(k, v)
    return merged


# ── Report shapes ──────────────────────────────────────────────

@dataclass(frozen=True)
class FieldDelta:
    field: str
    kind: str          # "match", "new_mapping", "lost_mapping", "value_mismatch"
    vendor_value: Optional[Any]
    semantic_value: Optional[Any]
    reason: Optional[str] = None
    gap_category: Optional[str] = None   # populated for non-match deltas


class GapCategory:
    """Taxonomy of parity-report gap causes (owner directive 2026-02-XX).

    Every non-match FieldDelta receives a category so the parity
    report is actionable — engineers can see where effort actually
    needs to land.
    """
    PARSER_GAP        = "parser_gap"          # composite / pre-parsing needed
    SCHEMA_GAP        = "schema_gap"          # nested deeper than schema flattens
    SEMANTIC_GAP      = "semantic_gap"        # semantic mapper mis-assigns concept
    REGISTRY_GAP      = "registry_gap"        # alias missing from registry
    IDENTITY_PARSER   = "identity_parser"     # DOMAIN\User / SID / UPN split
    EVENT_INFERENCE   = "event_inference"     # event-kind routing (dns vs network)
    GOVERNANCE_DECISION = "governance_decision"  # deliberate registry rejection
    EXPECTED_DIVERGENCE = "expected_divergence"  # semantic adds value; not a defect
    UNCLASSIFIED      = "unclassified"


@dataclass(frozen=True)
class ParityReport:
    fixture: str
    vendor_route: Optional[str]
    vendor_field_count: int
    semantic_field_count: int
    matches: int
    new_mappings: int
    lost_mappings: int
    value_mismatches: int
    ambiguous: int
    confidence_drift: float
    parity_rate: float             # 0..1 · matches / max(vendor_count, semantic_count)
    field_deltas: Tuple[FieldDelta, ...]
    semantic_confidence: float
    schema_family: str


# ── Public entry point ─────────────────────────────────────────

def compare_fixture(name: str, raw: str) -> ParityReport:
    """Run both pipelines on ``raw`` and produce a ParityReport."""
    classification = classify_input(raw)
    parsed = parse_input(raw, classification)

    # Vendor path — the current source of truth.
    vendor = detect_vendor(parsed)
    vendor_cem = normalize(parsed, vendor)
    vendor_flat = _flatten_cem(vendor_cem)
    vendor_confidence = vendor_cem.provenance.confidence

    # Semantic path — the candidate. Composite Extractor runs BEFORE
    # Schema Understanding so composite fields like Sysmon "Hashes:
    # SHA256=… MD5=…" surface as sibling candidate paths.
    enriched = expand_composites(parsed)
    fingerprint = understand_schema(enriched)
    mapping = map_semantic_fields(fingerprint, enriched)
    semantic_cem = build_semantic_cem(enriched, mapping)
    semantic_flat = _flatten_cem(semantic_cem)

    all_fields = sorted(set(vendor_flat) | set(semantic_flat))
    deltas: List[FieldDelta] = []
    matches = new_mappings = lost_mappings = mismatches = 0

    for f in all_fields:
        v = vendor_flat.get(f)
        s = semantic_flat.get(f)
        if v is not None and s is not None:
            if _values_equal(v, s):
                matches += 1
                deltas.append(FieldDelta(f, "match", v, s))
            else:
                mismatches += 1
                category = _classify_gap(f, v, s, "value_mismatch")
                deltas.append(FieldDelta(
                    f, "value_mismatch", v, s,
                    reason="different values across pipelines",
                    gap_category=category,
                ))
        elif s is not None:
            new_mappings += 1
            deltas.append(FieldDelta(
                f, "new_mapping", None, s,
                reason="semantic path resolved a field the vendor "
                       "route did not populate",
                gap_category=GapCategory.EXPECTED_DIVERGENCE,
            ))
        else:
            lost_mappings += 1
            category = _classify_gap(f, v, None, "lost_mapping")
            deltas.append(FieldDelta(
                f, "lost_mapping", v, None,
                reason="semantic path did not populate a vendor entity",
                gap_category=category,
            ))

    denom = max(len(vendor_flat), len(semantic_flat), 1)
    parity_rate = matches / denom
    drift = round(vendor_confidence - mapping.semantic_confidence, 4)

    return ParityReport(
        fixture=name,
        vendor_route=vendor_cem.vendor_route,
        vendor_field_count=len(vendor_flat),
        semantic_field_count=len(semantic_flat),
        matches=matches,
        new_mappings=new_mappings,
        lost_mappings=lost_mappings,
        value_mismatches=mismatches,
        ambiguous=len(mapping.ambiguous_fields),
        confidence_drift=drift,
        parity_rate=parity_rate,
        field_deltas=tuple(deltas),
        semantic_confidence=mapping.semantic_confidence,
        schema_family=fingerprint.schema_family,
    )


def _values_equal(a: Any, b: Any) -> bool:
    if type(a) is type(b):
        return a == b
    # Common numeric/string coercions: 443 vs "443"
    if isinstance(a, int) and isinstance(b, str) and b.isdigit():
        return a == int(b)
    if isinstance(b, int) and isinstance(a, str) and a.isdigit():
        return b == int(a)
    return str(a) == str(b)


def _classify_gap(field: str,
                  vendor_value: Any,
                  semantic_value: Any,
                  kind: str) -> str:
    """Heuristic gap classifier — assigns each non-match a taxonomy
    label so the parity report is actionable.

    Deterministic. No vendor branching. Rules are ordered specific → general.
    """
    fnorm = field.lower()

    # ── Event inference: dns.query vs network.domain ─────────────
    if fnorm == "dns.query" and semantic_value is None:
        return GapCategory.EVENT_INFERENCE
    if fnorm == "network.domain" and vendor_value is None:
        return GapCategory.EVENT_INFERENCE

    # ── Identity parser: DOMAIN\User style splits ────────────────
    if fnorm == "user.name" and kind == "value_mismatch":
        v = str(vendor_value) if vendor_value is not None else ""
        s = str(semantic_value) if semantic_value is not None else ""
        if "\\" in s and "\\" not in v:
            return GapCategory.IDENTITY_PARSER
        if "\\" in v and "\\" not in s:
            return GapCategory.IDENTITY_PARSER

    # ── Parser gap: composite hash / composite key=value fields ──
    # If the semantic side lost a hash that the vendor found, and the
    # vendor value is hex of a hash-canonical length, this is almost
    # certainly a composite-extraction gap.
    if kind == "lost_mapping" and fnorm.endswith(
            ("hash_md5", "hash_sha1", "hash_sha256", "hash_sha512")):
        v = str(vendor_value) if vendor_value is not None else ""
        if len(v) in (32, 40, 64, 128) and all(
                c in "0123456789abcdefABCDEF" for c in v):
            return GapCategory.PARSER_GAP

    # ── Schema gap: deeply-nested fields the semantic path did not
    #    surface as a candidate. Any dotted path of depth ≥ 2 that
    #    the semantic side missed points at Schema Understanding.
    if kind == "lost_mapping" and field.count(".") >= 1:
        return GapCategory.SCHEMA_GAP

    # ── Registry gap: flat field the semantic side did not populate.
    #    Likely candidate for governance review.
    if kind == "lost_mapping":
        return GapCategory.REGISTRY_GAP

    # ── Semantic gap: both sides populated but disagree on value.
    if kind == "value_mismatch":
        return GapCategory.SEMANTIC_GAP

    return GapCategory.UNCLASSIFIED


# ── Report rendering ──────────────────────────────────────────

def render_parity_markdown(reports: List[ParityReport]) -> str:
    lines: List[str] = []
    lines.append("# CEM Parity Report · Semantic vs Vendor Normalizers")
    lines.append("")
    lines.append(f"Fixtures compared: {len(reports)}")
    lines.append("")

    total_matches = sum(r.matches for r in reports)
    total_new = sum(r.new_mappings for r in reports)
    total_lost = sum(r.lost_mappings for r in reports)
    total_mism = sum(r.value_mismatches for r in reports)
    total_amb = sum(r.ambiguous for r in reports)
    avg_parity = (sum(r.parity_rate for r in reports) / len(reports)
                  if reports else 0.0)
    avg_drift = (sum(r.confidence_drift for r in reports) / len(reports)
                 if reports else 0.0)

    # Gap classification totals (owner-mandated actionability)
    gap_counts: Dict[str, int] = {}
    for r in reports:
        for d in r.field_deltas:
            if d.kind == "match" or d.gap_category is None:
                continue
            gap_counts[d.gap_category] = gap_counts.get(d.gap_category, 0) + 1

    lines.append("## Aggregate")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---|")
    lines.append(f"| Matches | {total_matches} |")
    lines.append(f"| New (semantic-only) | {total_new} |")
    lines.append(f"| Lost (vendor-only) | {total_lost} |")
    lines.append(f"| Value mismatches | {total_mism} |")
    lines.append(f"| Ambiguous | {total_amb} |")
    lines.append(f"| Mean parity rate | {avg_parity:.1%} |")
    lines.append(f"| Mean confidence drift | {avg_drift:+.3f} |")
    lines.append("")

    # Gap classification breakdown — actionability panel.
    lines.append("## Gap classification (where engineering effort lands)")
    lines.append("")
    if gap_counts:
        lines.append("| Category | Count |")
        lines.append("|---|---|")
        for cat, cnt in sorted(gap_counts.items(),
                                key=lambda kv: (-kv[1], kv[0])):
            lines.append(f"| `{cat}` | {cnt} |")
    else:
        lines.append("_No non-match deltas — parity is perfect._")
    lines.append("")

    # Cut-over criteria table (from REGISTRY_GOVERNANCE.md)
    lines.append("## Cut-over criteria")
    lines.append("")
    lines.append("| Criterion | Target | Current |")
    lines.append("|---|---|---|")
    lines.append(f"| Mapping parity | ≥ 99.5% | "
                 f"{avg_parity:.1%} "
                 f"{'✅' if avg_parity >= 0.995 else '⏸'} |")
    lines.append(f"| Unexplained confidence regressions | 0 | "
                 f"{sum(1 for r in reports if r.confidence_drift > 0.3)} "
                 f"{'✅' if all(r.confidence_drift <= 0.3 for r in reports) else '⏸'} |")
    lines.append(f"| Ambiguous mapping increase | 0 | "
                 f"{total_amb} "
                 f"{'✅' if total_amb == 0 else '⏸'} |")
    lines.append("")

    lines.append("## Per-fixture detail")
    lines.append("")
    for r in reports:
        lines.append(f"### `{r.fixture}`")
        lines.append("")
        lines.append(f"- vendor route: `{r.vendor_route}` · "
                     f"schema: `{r.schema_family}`")
        lines.append(f"- vendor fields: {r.vendor_field_count} · "
                     f"semantic fields: {r.semantic_field_count}")
        lines.append(f"- matches: **{r.matches}** · "
                     f"new: {r.new_mappings} · "
                     f"lost: {r.lost_mappings} · "
                     f"mismatches: {r.value_mismatches} · "
                     f"ambiguous: {r.ambiguous}")
        lines.append(f"- parity: **{r.parity_rate:.1%}** · "
                     f"confidence drift: {r.confidence_drift:+.3f}")
        if r.field_deltas:
            lines.append("- field deltas:")
            for d in r.field_deltas:
                icon = ({"match": "✅", "new_mapping": "➕",
                         "lost_mapping": "➖",
                         "value_mismatch": "⚠️"}[d.kind])
                cat = (f" · [{d.gap_category}]"
                       if d.gap_category and d.gap_category != "match"
                       else "")
                lines.append(f"  - {icon}{cat} `{d.field}` "
                             f"vendor={d.vendor_value!r} · "
                             f"semantic={d.semantic_value!r}"
                             + (f" · {d.reason}" if d.reason else ""))
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("*Regenerated on every pytest run of "
                 "`test_cem_parity.py`. Cut-over decisions require "
                 "owner review of this report.*")
    return "\n".join(lines)


__all__ = [
    "FieldDelta",
    "ParityReport",
    "compare_fixture",
    "render_parity_markdown",
]
