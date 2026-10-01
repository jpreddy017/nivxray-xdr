"""NivXRay reasoning — Phase 3/4 orchestrator.

Implements the recursive 4-phase algorithm on top of the text_candidates
generator:

    Phase 1 — Characterize input.
    Phase 2 — Generate candidates (structural + linguistic).
    Phase 3 — Apply top candidate, verify improvement.
    Phase 4 — Stop when:
        (a) no candidate exceeds MIN_DELTA
        (b) linguistic score converges (Δ within CONVERGENCE_EPS across 2 steps)
        (c) MAX_DEPTH reached (safety)

Modes (per user spec):
    fast        Deterministic core only — DO NOT invoke this engine.
                Provided as a public constant so callers can dispatch.
    balanced    Deterministic + linguistic tiebreak. LLM only on ties.
    deep        Deterministic + linguistic + LLM arbitration on every ambiguity.

The reasoning engine's job is NOT to replace the existing magic_decoder.
It is invoked BY analysis_core to arbitrate ambiguous outputs, or DIRECTLY
by /decode/smart when the input characterizes as ``text_like``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .characterize import characterize, InputProfile
from .scorer import linguistic_score, score_breakdown
from .text_candidates import text_candidates, Candidate, TIE_THRESHOLD

MODE_FAST = "fast"
MODE_BALANCED = "balanced"
MODE_DEEP = "deep"

MAX_DEPTH = 4
MIN_DELTA = 0.05
CONVERGENCE_EPS = 0.01


@dataclass
class ReasoningStep:
    depth: int
    profile: Dict[str, Any]
    chosen: Optional[Dict[str, Any]]
    considered: List[Dict[str, Any]] = field(default_factory=list)
    stop_reason: Optional[str] = None
    tiebreaker: Optional[str] = None


@dataclass
class ReasoningResult:
    final_output: str
    final_score: float
    chain: List[Dict[str, Any]]
    trace: List[ReasoningStep]
    mode: str
    stopped_at: str
    iterations: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "final_output": self.final_output,
            "final_score": round(self.final_score, 4),
            "chain": self.chain,
            "trace": [
                {
                    "depth": s.depth,
                    "profile": s.profile,
                    "chosen": s.chosen,
                    "considered": s.considered,
                    "stop_reason": s.stop_reason,
                    "tiebreaker": s.tiebreaker,
                }
                for s in self.trace
            ],
            "mode": self.mode,
            "stopped_at": self.stopped_at,
            "iterations": self.iterations,
        }


def _pick_with_tiebreak(
    cands: List[Candidate], mode: str, input_text: str = "",
) -> tuple:
    """Return (winner, tiebreaker_note, llm_verdict).

    ``tiebreaker_note`` is set when the top two candidates are within
    TIE_THRESHOLD of each other.

    When ``mode == "deep"`` AND a tie is detected AND an LLM key is
    configured, Claude Sonnet 4.5 is invoked to arbitrate. The LLM
    can only pick from the candidates we hand it — never invent new ops.
    If the LLM fails or is unavailable, we fall back to the top
    deterministic candidate and record the reason.
    """
    if not cands:
        return None, None, None
    if len(cands) == 1:
        return cands[0], None, None
    top, second = cands[0], cands[1]
    if (top.delta - second.delta) > TIE_THRESHOLD:
        return top, None, None

    note = (f"tie: {top.op}(Δ{top.delta:.3f}) vs "
            f"{second.op}(Δ{second.delta:.3f})")

    # Deep-mode LLM arbitration — only when explicitly requested.
    if mode == MODE_DEEP:
        try:
            from .llm_tiebreaker import arbitrate, tiebreak_available
            if tiebreak_available():
                cand_dicts = [c.as_dict() for c in cands[:5]]
                verdict = arbitrate(input_text, cand_dicts).as_dict()
                winner_op = verdict.get("winner_op")
                chosen = next(
                    (c for c in cands if c.op == winner_op), top,
                )
                return chosen, note, verdict
        except Exception as e:
            return top, note, {"used_llm": False, "error": str(e),
                               "provider": "fallback-deterministic"}
    return top, note, None


def reason(
    text: str,
    mode: str = MODE_BALANCED,
    max_depth: int = MAX_DEPTH,
    min_delta: float = MIN_DELTA,
) -> ReasoningResult:
    """Run the 4-phase recursive reasoning loop on ``text``.

    Returns a ReasoningResult describing the full decision trail. If no
    transformation improves the linguistic score, the input is returned
    unchanged with ``stopped_at == "no-improvement"``.
    """
    if mode not in (MODE_FAST, MODE_BALANCED, MODE_DEEP):
        raise ValueError(f"invalid mode: {mode!r}")

    trace: List[ReasoningStep] = []
    chain: List[Dict[str, Any]] = []
    current = text
    current_score = linguistic_score(current)
    stopped_at = "max-depth"
    last_score = current_score

    for depth in range(max_depth):
        # ── Phase 1: Characterize ─────────────────────────────────
        profile = characterize(current)

        # ── Phase 2: Generate candidates ───────────────────────────
        # Reasoning engine is TEXT-mode focused; structural containers
        # are best handled by magic_decoder. Delegate cleanly.
        if profile.kind not in ("text_like", "mixed"):
            trace.append(ReasoningStep(
                depth=depth,
                profile=profile.as_dict(),
                chosen=None,
                stop_reason=f"delegate-to-magic ({profile.kind})",
            ))
            stopped_at = f"delegate-{profile.kind}"
            break

        cands = text_candidates(current, min_delta=min_delta, top_n=5,
                                include_xor=(mode != MODE_FAST))

        # ── Phase 3: Apply top candidate (with tiebreak awareness) ─
        winner, tiebreak_note, llm_verdict = _pick_with_tiebreak(
            cands, mode, input_text=current,
        )

        step = ReasoningStep(
            depth=depth,
            profile=profile.as_dict(),
            chosen=winner.as_dict() if winner else None,
            considered=[c.as_dict() for c in cands[:5]],
            tiebreaker=tiebreak_note,
        )
        if llm_verdict is not None:
            step.profile.setdefault("_llm_arbitration", llm_verdict)

        if winner is None:
            step.stop_reason = "no-improving-candidate"
            trace.append(step)
            stopped_at = "no-improvement"
            break

        # ── Phase 4: Recursive stop condition ──────────────────────
        # Advance if the delta is meaningful; converge otherwise.
        if abs(winner.output_score - last_score) < CONVERGENCE_EPS:
            step.stop_reason = "converged"
            trace.append(step)
            stopped_at = "converged"
            break

        chain.append({
            "op": winner.op, "args": winner.args,
            "reason": f"{winner.op}: Δ+{winner.delta:.3f} linguistic score",
        })
        current = winner.output
        last_score = winner.output_score
        current_score = winner.output_score
        trace.append(step)

    return ReasoningResult(
        final_output=current,
        final_score=current_score,
        chain=chain,
        trace=trace,
        mode=mode,
        stopped_at=stopped_at,
        iterations=len(trace),
    )
