"""M0c · Canonical Evidence Provenance schema (ADR-0014).

Additive, nullable, opt-in provenance block for canonical evidence records.

RULES (owner directive · M0c):
  • This module defines a SCHEMA only.  Nothing in production populates it yet.
  • Evidence records with `provenance` absent OR `provenance = None` are
    valid and must deserialise identically to today's records.
  • Two records with the same `observed_value` but different
    `provenance.extraction_method` are LEGITIMATELY distinct (dual-witness).
    Dedup/merge across witnesses is NOT implemented here — only representable.
  • No adapter, analyzer, correlator, MITRE resolver, verdict engine, or
    Workspace consumer is modified by M0c.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Optional


ALLOWED_EXTRACTION_METHODS = frozenset({
    # per ADR-0014 §8.1 + §18.5 — extraction methods a producer may claim
    "html_body",
    "image_ocr",
    "archive_member",
    "decoder_layer",
    "telemetry_field",
    "ast_match",
    "regex_match",
    "recursion",
    "legacy_unknown",    # migration-safe default for records without producer changes
})


class ProvenanceError(ValueError):
    """Raised only on validation of an EXPLICITLY provided provenance block.

    Absent / None provenance is legal — no error.
    """


@dataclass(frozen=True)
class Provenance:
    """Immutable provenance record.  All fields nullable except extraction_method."""
    extraction_method:      str                                    # required when present
    step_id:                Optional[str] = None
    adapter_id:             Optional[str] = None                   # registry id (M0b)
    analyzer_id:            Optional[str] = None                   # registry id (M0b)
    parent_ref:             Optional[str] = None                   # parent evidence_ref
    location:               Optional[str] = None                   # e.g. "url#img[2]"
    source_confidence:      Optional[float] = None                 # 0.0–1.0
    extraction_confidence:  Optional[float] = None                 # 0.0–1.0

    def to_dict(self) -> Dict[str, Any]:
        """Deterministic serialisation — omits Python-None fields for stable hashing."""
        d = asdict(self)
        return {k: v for k, v in d.items() if v is not None}


def validate(provenance: Any) -> Optional[Provenance]:
    """Validate an inbound provenance block.

    Contract:
      • None  → returns None                (legacy / absent — allowed)
      • dict  → returns Provenance instance (raises ProvenanceError on bad shape)
      • Provenance → returns as-is
    """
    if provenance is None:
        return None
    if isinstance(provenance, Provenance):
        return provenance
    if not isinstance(provenance, dict):
        raise ProvenanceError(f"provenance must be dict or None, got {type(provenance).__name__}")

    method = provenance.get("extraction_method")
    if not method or not isinstance(method, str):
        raise ProvenanceError("provenance.extraction_method is required and must be a string")
    if method not in ALLOWED_EXTRACTION_METHODS:
        raise ProvenanceError(
            f"unknown extraction_method {method!r}; "
            f"allowed: {sorted(ALLOWED_EXTRACTION_METHODS)}")

    for conf_field in ("source_confidence", "extraction_confidence"):
        v = provenance.get(conf_field)
        if v is not None:
            if not isinstance(v, (int, float)) or not (0.0 <= float(v) <= 1.0):
                raise ProvenanceError(
                    f"provenance.{conf_field} must be a number in [0.0, 1.0] or None; got {v!r}")

    allowed = {"extraction_method", "step_id", "adapter_id", "analyzer_id",
                "parent_ref", "location", "source_confidence", "extraction_confidence"}
    unknown = set(provenance.keys()) - allowed
    if unknown:
        raise ProvenanceError(f"unknown provenance fields: {sorted(unknown)}")

    return Provenance(
        extraction_method     = method,
        step_id               = provenance.get("step_id"),
        adapter_id            = provenance.get("adapter_id"),
        analyzer_id           = provenance.get("analyzer_id"),
        parent_ref            = provenance.get("parent_ref"),
        location              = provenance.get("location"),
        source_confidence     = provenance.get("source_confidence"),
        extraction_confidence = provenance.get("extraction_confidence"),
    )


def attach_to_record(record: Dict[str, Any],
                      provenance: Optional[Any]) -> Dict[str, Any]:
    """Return a shallow copy of `record` with a validated `provenance` block.

    If `provenance` is None the returned record has NO `provenance` key.  This
    means an existing record round-trips through this helper unchanged when
    the caller opts out — the essence of the additive-nullable contract.
    """
    out = dict(record)
    p = validate(provenance)
    if p is not None:
        out["provenance"] = p.to_dict()
    else:
        out.pop("provenance", None)
    return out


__all__ = ["ALLOWED_EXTRACTION_METHODS", "Provenance", "ProvenanceError",
            "validate", "attach_to_record"]
