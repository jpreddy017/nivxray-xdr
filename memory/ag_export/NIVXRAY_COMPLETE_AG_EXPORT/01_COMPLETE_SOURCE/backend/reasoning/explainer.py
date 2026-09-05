"""NivXRay Explainer (Feb-2026 roadmap).

Compiles the reasoning-engine trace into human-readable "why chose X, why
rejected Y" narratives that surface in the analyst's Verdict Card.

The explainer is a PURE FUNCTION over the ReasoningResult — no side
effects, no I/O. It's called by analysis_core after the reasoning loop
completes.

Output shape:
    {
        "headline": "Selected ROT13 (Δ+0.72 linguistic score, PowerShell tokens detected)",
        "selected": [
            {"step": 1, "op": "rot13", "delta": 0.72, "why": "..."},
            ...
        ],
        "rejected": [
            {"op": "xor(k=0x4e)", "delta": 0.09, "why": "below tie threshold"},
            ...
        ],
        "stop_reason": "converged",
        "tiebreakers": [...],
        "confidence": 0.82,
    }
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional


def _fmt_op(step: Dict[str, Any]) -> str:
    """Compact op representation. rot13 → rot13. xor {key:0x4e} → xor(k=0x4e)."""
    op = step.get("op") or "?"
    args = step.get("args") or {}
    if not args:
        return op
    if "key" in args:
        return f"{op}(k={args['key']})"
    if "shift" in args:
        return f"{op}(n={args['shift']})"
    return op


def _why_selected(step_dict: Dict[str, Any]) -> str:
    """Human-readable justification for a chosen candidate."""
    chosen = step_dict.get("chosen") or {}
    reasons = chosen.get("reasons") or []
    breakdown = chosen.get("breakdown") or {}
    delta = chosen.get("delta")
    hits = (breakdown.get("hits") or {})

    parts: List[str] = []
    if delta is not None:
        parts.append(f"Δ+{delta:.3f} linguistic score")
    if hits.get("analyst"):
        parts.append(f"{hits['analyst']} analyst-keyword hit(s)")
    if hits.get("english"):
        parts.append(f"{hits['english']} English word(s)")
    if "url" in (breakdown.get("reasons") or []):
        parts.append("URL detected")
    if not parts:
        parts.append("no other candidate improved the score")
    return ", ".join(parts)


def _why_rejected(cand: Dict[str, Any], winner_delta: float,
                  tie_threshold: float = 0.05) -> str:
    """Human-readable rejection reason for a considered-but-not-picked candidate."""
    delta = cand.get("delta", 0.0)
    if delta <= 0:
        return "no linguistic improvement over input"
    gap = winner_delta - delta
    if gap <= tie_threshold:
        return f"tied with winner (gap={gap:.3f} ≤ {tie_threshold})"
    return f"lower delta (Δ+{delta:.3f} vs winner Δ+{winner_delta:.3f})"


def explain_reasoning(
    reasoning_result: Dict[str, Any],
    confidence: Optional[float] = None,
) -> Dict[str, Any]:
    """Compile a reasoning-engine trace into a human-readable narrative.

    Args:
        reasoning_result: `ReasoningResult.as_dict()` output.
        confidence: Optional final confidence from the confidence engine.

    Returns:
        dict with `headline`, `selected`, `rejected`, `stop_reason`,
        `tiebreakers`, and `confidence` fields.
    """
    if not reasoning_result:
        return {
            "headline": "No reasoning trace",
            "selected": [], "rejected": [], "stop_reason": "unknown",
            "tiebreakers": [], "confidence": confidence,
        }

    trace = reasoning_result.get("trace") or []
    chain = reasoning_result.get("chain") or []
    stopped_at = reasoning_result.get("stopped_at") or "unknown"

    selected_narrative: List[Dict[str, Any]] = []
    rejected_narrative: List[Dict[str, Any]] = []
    tiebreakers: List[Dict[str, Any]] = []

    for i, step in enumerate(trace, start=1):
        chosen = step.get("chosen") or {}
        if chosen:
            selected_narrative.append({
                "step": i,
                "op": _fmt_op(chosen),
                "delta": chosen.get("delta"),
                "output_preview": (chosen.get("output") or "")[:120],
                "why": _why_selected(step),
            })
        winner_delta = chosen.get("delta", 0.0) if chosen else 0.0
        for cand in (step.get("considered") or []):
            # Skip the winner itself in rejection list
            if chosen and cand.get("op") == chosen.get("op") and cand.get("args") == chosen.get("args"):
                continue
            rejected_narrative.append({
                "step": i,
                "op": _fmt_op(cand),
                "delta": cand.get("delta"),
                "why": _why_rejected(cand, winner_delta),
            })
        if step.get("tiebreaker"):
            tiebreakers.append({
                "step": i,
                "note": step["tiebreaker"],
            })

    # Compose the headline
    if not chain:
        headline = f"No transformation applied — {stopped_at}."
    else:
        winning_ops = ", ".join(_fmt_op(s) for s in chain)
        final_delta = sum(
            (s.get("chosen") or {}).get("delta") or 0.0 for s in trace
        )
        headline = (
            f"Selected {winning_ops} (Δ+{final_delta:.3f} linguistic score, "
            f"stopped: {stopped_at})"
        )

    return {
        "headline": headline,
        "selected": selected_narrative,
        "rejected": rejected_narrative,
        "stop_reason": stopped_at,
        "tiebreakers": tiebreakers,
        "confidence": round(confidence, 4) if confidence is not None else None,
    }


def explain_chain(
    input_text: str,
    output_text: str,
    chain: List[Dict[str, Any]],
    confidence: Optional[float] = None,
    linguistic_delta: Optional[float] = None,
) -> str:
    """One-liner explanation of a decode chain — used by analysis_core.

    Kept separate from `explain_reasoning` so callers that don't have a
    full reasoning trace (fast mode, magic-only decoded chains) can still
    produce a coherent narrative.
    """
    if not chain:
        return "No decoding applied — input already at final state."
    ops = " → ".join((s.get("op") or "?") for s in chain)
    parts = [f"Applied {len(chain)}-step chain: {ops}."]
    if linguistic_delta is not None:
        parts.append(f"Linguistic score changed by {linguistic_delta:+.3f}.")
    if confidence is not None:
        band = "HIGH" if confidence >= 0.75 else "MEDIUM" if confidence >= 0.50 else "LOW"
        parts.append(f"Confidence: {band} ({confidence:.2f}).")
    return " ".join(parts)
