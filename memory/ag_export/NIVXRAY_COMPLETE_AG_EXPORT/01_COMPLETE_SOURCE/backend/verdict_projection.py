"""Canonical verdict projections (ARB Governance Rules 12, 14, 15).

``verdict_card`` is the sole verdict object. Legacy consumers reading
``risk`` still work, but only via ``derive_risk_projection(vc)`` — a
pure derivation with **zero independent decision logic**.

Guidance: NEVER hand-build a ``risk`` dict. Always call
``derive_risk_projection`` so the projection stays in lockstep with the
canonical verdict.
"""
from __future__ import annotations

from typing import Any, Optional


_LEVEL_BY_VERDICT: dict[str, str] = {
    # verdict.lower() → level bucket (used by legacy badge colors)
    "malicious":        "high",
    "high":             "high",
    "critical":         "high",
    "suspicious":       "medium",
    "medium":           "medium",
    "needs_review":     "low",
    "needs review":     "low",
    "runtime dependent":"low",
    "runtime_dependent":"low",
    "partial":          "low",
    "partial decode":   "low",
    "informational":    "safe",
    "info":             "safe",
    "low":              "safe",
    "safe":             "safe",
    "benign":           "safe",
    "undetermined":     "unknown",
    "unknown":          "unknown",
}


def _level_from_verdict(verdict: Optional[str]) -> str:
    if not verdict:
        return "unknown"
    return _LEVEL_BY_VERDICT.get(str(verdict).lower(), "unknown")


def derive_risk_projection(verdict_card: Optional[dict]) -> Optional[dict]:
    """Return a ``risk`` dict derived from ``verdict_card``.

    Contract:
      * If ``verdict_card`` is missing or empty → ``None``.
      * Otherwise returns ``{"verdict": ..., "level": ..., "score": ...}``.
      * The returned dict is a *projection* — no independent scoring
        happens here. Bumping / capping / thresholding must be done in
        the Verdict Engine, not in this projection.

    This is the ONLY approved way to build a ``risk`` dict for a
    response payload (Rule 12).
    """
    if not verdict_card:
        return None
    vc = verdict_card
    verdict = vc.get("verdict") or vc.get("label")
    if not verdict:
        return None
    score = vc.get("risk_score")
    if score is None:
        score = vc.get("score")
    if score is None:
        conf = vc.get("confidence")
        if isinstance(conf, (int, float)):
            score = int(round(conf * 100)) if conf <= 1 else int(conf)
    return {
        "verdict": verdict,
        "level":   _level_from_verdict(verdict),
        "score":   int(score) if isinstance(score, (int, float)) else score,
    }


def ensure_canonical_response(result: dict) -> dict:
    """Rule 15 · rewrites ``risk`` to a projection of ``verdict_card``
    on any result dict. Idempotent · zero-side-effect on responses that
    already agree.

    Should be called just before returning a decode / analyze payload
    to a client. Legacy consumers see a ``risk`` value that is now
    guaranteed to agree with ``verdict_card``.
    """
    vc = result.get("verdict_card")
    if not vc:
        return result
    projected = derive_risk_projection(vc)
    if projected is not None:
        # Overwrite any legacy independent ``risk`` object — a projection
        # ALWAYS wins per Rule 12.
        result["risk"] = projected
    return result


# ---------------------------------------------------------------------------
# semantic.verdict disambiguation (Rule 12 amendment)
# ---------------------------------------------------------------------------
#
# ``semantic.verdict`` was ambiguous — a semantic classifier signal, not
# a product verdict. We add ``semantic.review_signal`` as the new name
# and keep the legacy key populated for one release cycle so external
# consumers (if any) can migrate.
#
# Consumers MUST NOT read ``semantic.verdict`` as a decision source —
# it is a supporting signal only (Rule 15).


def promote_semantic_review_signal(result: dict) -> dict:
    """Add ``semantic.review_signal`` alongside legacy ``semantic.verdict``.

    Pure copy — the value is unchanged, only the field name is
    disambiguated. Reading code should migrate to ``review_signal`` and
    treat it as a signal, not a verdict.
    """
    sem = result.get("semantic")
    if not isinstance(sem, dict):
        return result
    legacy = sem.get("verdict")
    if legacy is not None and sem.get("review_signal") is None:
        sem["review_signal"] = legacy
    return result


__all__ = [
    "derive_risk_projection",
    "ensure_canonical_response",
    "promote_semantic_review_signal",
]
