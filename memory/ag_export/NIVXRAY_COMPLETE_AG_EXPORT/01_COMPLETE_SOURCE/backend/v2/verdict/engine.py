"""v2/verdict/engine.py · Deterministic scoring core.

    score(event, ctx) → Verdict(score, band, breakdown, explanation)

Zero I/O. Zero LLM. Same input → same output. Add signals in `signals.py`.
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Any
from .signals import ALL_DETECTORS, ALL_DECAY
from .weights import (
    WEIGHTS, DECAY_WEIGHTS, FAMILY_OF, FAMILY_CAPS,
    CORROBORATION_REQUIRED, CORROBORATION_CAP, band_of,
)


@dataclass
class SignalHit:
    signal: str
    weight: int
    family: str
    reason: str


@dataclass
class Verdict:
    score: int
    band: str
    breakdown: list[dict] = field(default_factory=list)
    explanation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "band":  self.band,
            "explanation": self.explanation,
            "breakdown":  self.breakdown,
        }


def _dedupe(hits: list[dict]) -> list[dict]:
    """Same signal on the same event only counts once — first-fire wins."""
    seen = set()
    out = []
    for h in hits:
        k = h["signal"]
        if k in seen:
            continue
        seen.add(k)
        out.append(h)
    return out


def score(event: dict, ctx: dict | None = None) -> Verdict:
    ctx = ctx or {}
    raw_hits: list[dict] = []
    for det in ALL_DETECTORS:
        raw_hits.extend(det(event, ctx))
    hits = _dedupe(raw_hits)

    decay_hits: list[dict] = []
    for det in ALL_DECAY:
        decay_hits.extend(det(event, ctx))
    decay_hits = _dedupe(decay_hits)

    # Apply per-family caps.
    per_family: dict[str, list[SignalHit]] = {}
    for h in hits:
        w = WEIGHTS.get(h["signal"], 0)
        fam = FAMILY_OF.get(h["signal"], "execution")
        per_family.setdefault(fam, []).append(
            SignalHit(signal=h["signal"], weight=w, family=fam, reason=h["reason"]),
        )
    positive = 0
    breakdown: list[dict] = []
    families_fired: set[str] = set()
    for fam, hs in per_family.items():
        s = sum(h.weight for h in hs)
        cap = FAMILY_CAPS.get(fam, 40)
        capped = min(s, cap)
        # Distribute the cap proportionally so `breakdown` remains explainable.
        if s > 0:
            factor = capped / s
        else:
            factor = 1.0
        for h in hs:
            eff = int(round(h.weight * factor))
            positive += eff
            breakdown.append({
                "signal": h.signal, "family": h.family,
                "weight": h.weight, "effective_weight": eff,
                "reason": h.reason,
            })
            families_fired.add(fam)
    # Decay.
    negative = 0
    for h in decay_hits:
        w = DECAY_WEIGHTS.get(h["signal"], 0)
        negative += w  # already negative
        breakdown.append({
            "signal": h["signal"], "family": "decay",
            "weight": w, "effective_weight": w,
            "reason": h["reason"],
        })

    raw_score = positive + negative
    # Corroboration cap: if the ONLY high-value signal(s) fired come from a
    # single family AND belong to CORROBORATION_REQUIRED, ceiling at
    # CORROBORATION_CAP.
    high_value_families = {
        FAMILY_OF.get(k) for k in CORROBORATION_REQUIRED
        if k in {h["signal"] for h in hits}
    }
    corroborated = (families_fired - {None}) - high_value_families
    corroboration_applied = False
    if high_value_families and not corroborated and raw_score > CORROBORATION_CAP:
        raw_score = CORROBORATION_CAP
        corroboration_applied = True

    final = max(0, min(100, raw_score))
    band = band_of(final)

    top = sorted(breakdown, key=lambda b: b["effective_weight"], reverse=True)[:3]
    explanation = "; ".join(
        f'{b["signal"]}(+{b["effective_weight"]})' if b["effective_weight"] >= 0
        else f'{b["signal"]}({b["effective_weight"]})'
        for b in top
    ) or "no signals fired"
    if corroboration_applied:
        explanation += " · corroboration-capped"

    return Verdict(score=final, band=band, breakdown=breakdown, explanation=explanation)
