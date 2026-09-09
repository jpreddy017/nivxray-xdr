"""Canonical Verdict Wrapper — ADR-004 Step 1 Phase 3.

Consumes `CanonicalVerdictInput` (derived from InvestigationModel),
scores each event via `v2.verdict.engine.score(event, ctx)`, and
aggregates to a case-level verdict.

**No scoring weight changes.** Per-event scoring is byte-identical to
`v2/verdict/engine.py::score` — this wrapper is aggregation only.

**Preserved semantics** (per owner directive 2026-08-10):
1. `Suspicious-as-floor` — When any event fires a HIGH-band signal
   but no CRITICAL-band evidence corroborates it, the case-level
   label caps at `Suspicious`. This mirrors engine A's current
   floor behaviour. Any change requires a separate Verdict Policy ADR.
2. `Runtime Dependent` — When the strongest event's band is
   `low` and the raw score is exactly in the runtime-dependent
   range (v2 band = 'low'), the aggregate label is
   `Runtime Dependent` — not elevated to `Suspicious` or `Malicious`.

Output shape mimics `nivxforge.investigation.verdict_engine.VerdictNode`
(label / confidence / confidence_pct / contributors / reason) for
migration compatibility, but the wrapper itself has NO dependency on
`nivxforge`.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

from v2.verdict.engine import score as _v2_score
from v2.verdict.canonical_input import CanonicalVerdictInput, CanonicalEvent


# ══════════════════════════════════════════════════════════════════
# Vocabulary — 5-label analyst-facing set (unchanged from engine A)
# ══════════════════════════════════════════════════════════════════
_LABELS = ("Undetermined", "Informational", "Runtime Dependent",
                "Suspicious", "Malicious")

_LABEL_RANK = {lbl: i for i, lbl in enumerate(_LABELS)}


def _v2_band_to_label(band: str) -> str:
    """Map v2 6-tier bands to 5-tier analyst labels.
    NOT a policy change — this is the same mapping the diff report uses."""
    return {
        "critical":      "Malicious",
        "malicious":     "Malicious",
        "suspicious":    "Suspicious",
        "low":           "Runtime Dependent",
        "informational": "Informational",
        "benign":        "Undetermined",
    }.get(band, "Undetermined")


# ══════════════════════════════════════════════════════════════════
# Case-level verdict output
# ══════════════════════════════════════════════════════════════════
@dataclass
class CanonicalContribution:
    event_id:      str
    signal:        str
    band:          str
    score:         int
    lane:          str
    reason:        str = ""


@dataclass
class CanonicalVerdict:
    label:          str
    confidence:     float
    confidence_pct: int
    reason:         str = ""
    top_score:      int = 0
    n_events:       int = 0
    n_signals:      int = 0
    contributors:   list[CanonicalContribution] = field(default_factory=list)
    engine:         str = "canonical-v2-verdict-1.0"

    # Explainability envelope so downstream surfaces (Verdict Card,
    # Investigation Ledger) get the same shape as engine A produced.
    escalation_rule: str | None = None
    floor_applied:   str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["contributors"] = [asdict(c) for c in self.contributors]
        return d


# ══════════════════════════════════════════════════════════════════
# The wrapper — aggregate per-event scores into a case verdict
# ══════════════════════════════════════════════════════════════════
def score(inp: CanonicalVerdictInput) -> CanonicalVerdict:
    """Score a CanonicalVerdictInput.

    Deterministic. Zero I/O. Same input → same output.

    Aggregation policy (preserved from engine A · Phase 3):
      * Per-event scores come from `v2.verdict.engine.score` verbatim.
      * Case-level `label` is determined by:
          - the STRONGEST band across all events, mapped to a label
          - then the Suspicious-as-floor policy is applied.
      * Case-level `confidence` is a Noisy-OR of per-event
        confidences (each per-event confidence = event_score / 100).
        Monotonic — adding contributors can only raise it.
    """
    contribs: list[CanonicalContribution] = []
    per_event_bands: list[str] = []
    per_event_scores: list[int] = []
    fired_signals: set[str] = set()

    for ev in inp.events:
        v2_event = ev.to_v2_event()
        ctx = {"n_ti_hits": inp.n_ti_hits,
                   "detection_sources": list(inp.detection_sources)}
        verdict = _v2_score(v2_event, ctx)
        per_event_bands.append(verdict.band)
        per_event_scores.append(int(verdict.score))
        for b in verdict.breakdown:
            sig = str(b.get("signal") or "")
            if sig:
                fired_signals.add(sig)
                contribs.append(CanonicalContribution(
                    event_id=ev.event_id,
                    signal=sig,
                    band=verdict.band,
                    score=int(b.get("effective_weight") or 0),
                    lane=ev.lane,
                    reason=str(b.get("reason") or "")[:180],
                ))

    if not contribs:
        return CanonicalVerdict(
            label="Undetermined",
            confidence=0.0,
            confidence_pct=0,
            reason="No verdict-relevant signals fired on the input.",
            top_score=0,
            n_events=len(inp.events),
            n_signals=0,
            contributors=[],
        )

    top_score = max(per_event_scores) if per_event_scores else 0
    # Strongest band wins (ties go to the higher analyst label).
    band_rank = {"benign": 0, "informational": 1, "low": 2,
                     "suspicious": 3, "malicious": 4, "critical": 5}
    top_band = max(per_event_bands, key=lambda b: band_rank.get(b, -1))
    baseline_label = _v2_band_to_label(top_band)

    # ── Preserved policy 1 · Suspicious-as-floor ──────────────────
    #
    # When ANY event fires a high-band signal but no CRITICAL evidence
    # corroborates it, we cap the case-level label at `Suspicious`.
    # This mirrors engine A's floor behaviour on 10/14 fixtures in the
    # Phase 2 diff report.
    #
    # Rule (verbatim inherited):
    #   IF baseline_label >= Malicious
    #   AND no event reached the `critical` v2 band
    #   AND no event fired a CORROBORATION-required signal alongside
    #       a corroborating family
    #   THEN cap label at Suspicious.
    floor_applied: str | None = None
    if _LABEL_RANK[baseline_label] >= _LABEL_RANK["Malicious"] \
              and "critical" not in per_event_bands:
        # Look for cross-family corroboration in the fired-signals set.
        from v2.verdict.weights import FAMILY_OF, CORROBORATION_REQUIRED
        fired_families = {FAMILY_OF.get(s) for s in fired_signals if s}
        core_families = {FAMILY_OF.get(s) for s in fired_signals
                              if s in CORROBORATION_REQUIRED}
        corroborated  = (fired_families - {None}) - core_families
        if core_families and not corroborated:
            baseline_label = "Suspicious"
            floor_applied  = "suspicious_as_floor · single-family HIGH corroboration missing"

    # ── Preserved policy 2 · Runtime Dependent ────────────────────
    #
    # If the strongest band is exactly `low`, the aggregate is
    # `Runtime Dependent` — we do NOT elevate to `Suspicious` or
    # `Malicious`, even if the raw top_score is in a higher band's
    # numeric range, because the underlying detectors intentionally
    # emitted `low` to communicate scope-uncertainty (e.g. download
    # observed, execution outcome unconfirmed).
    if top_band == "low":
        baseline_label = "Runtime Dependent"

    # ── Confidence — Noisy-OR of per-event confidences ────────────
    # p(mal) = 1 - Π_i (1 - c_i) where c_i = event_score/100.
    prod = 1.0
    for s in per_event_scores:
        c = max(0.0, min(1.0, s / 100.0))
        prod *= (1.0 - c)
    confidence = 1.0 - prod

    # Cap confidence: `Runtime Dependent` should not carry >0.60,
    # `Undetermined` / `Informational` should not exceed 0.30. This
    # mirrors engine A's confidence caps for label consistency.
    if baseline_label in ("Undetermined", "Informational"):
        confidence = min(confidence, 0.30)
    elif baseline_label == "Runtime Dependent":
        confidence = min(confidence, 0.60)

    # ── Reason ────────────────────────────────────────────────────
    top_signal_names = sorted({c.signal for c in contribs},
                                    key=lambda s: s)[:3]
    if floor_applied:
        reason = (
            f"{baseline_label} (floor applied: {floor_applied}). "
            f"Top signals: {', '.join(top_signal_names)}. "
            f"{len(contribs)} contributor(s), {len(inp.events)} event(s)."
        )
    else:
        reason = (
            f"{baseline_label}. Top signals: {', '.join(top_signal_names)}. "
            f"{len(contribs)} contributor(s) across {len(inp.events)} event(s)."
        )

    return CanonicalVerdict(
        label=baseline_label,
        confidence=round(confidence, 4),
        confidence_pct=int(round(confidence * 100)),
        reason=reason,
        top_score=top_score,
        n_events=len(inp.events),
        n_signals=len(fired_signals),
        contributors=contribs[:32],   # bound the payload
        floor_applied=floor_applied,
    )


__all__ = ["CanonicalVerdict", "CanonicalContribution", "score"]
