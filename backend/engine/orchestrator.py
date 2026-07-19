"""Orchestrator — recursive plugin-driven decode loop.

Algorithm (Phase A, deterministic-only)
---------------------------------------
1. Compute L0 fingerprint of current payload.
2. Ask DecoderRegistry for candidate decoders (ranked by confidence, cost).
3. Try each candidate up to `budget.max_branches` times per layer.
4. Score the output — if it improves on the current best (english/printable/
   terminal detection), accept it and recurse.
5. Terminate on any of:
      - shellcode prologue detected (delegated to L2 heuristic decoder later)
      - english_density >= 0.7 (very likely plaintext)
      - budget exhausted (depth or wall-time)
      - no candidate improves the score

The orchestrator ONLY routes. All capability lives in decoder plugins.
"""
from __future__ import annotations

import logging
import time
from typing import List, Optional

from .fingerprint_util import compute as fingerprint_compute
from .models import (
    AnalysisContext,
    DecodeOutcome,
    Fingerprint,
    TraceStep,
)
from .registry import DecoderRegistry

log = logging.getLogger("nivx.engine.orchestrator")

# Score constants — kept explicit and tunable in one place.
_TERMINAL_ENGLISH = 0.7
_IMPROVEMENT_EPS = 0.02


def _score(fp: Fingerprint) -> float:
    """Simple composite score used to decide whether an output improves things."""
    # weight english heavily (real plaintext), then printable, then low entropy
    return (fp.english_density * 0.6
            + fp.printable_ratio * 0.3
            + max(0.0, (5.0 - fp.entropy)) * 0.02)


class Orchestrator:
    """Run the deterministic recursive decode pipeline."""

    def __init__(self, ctx: Optional[AnalysisContext] = None):
        self.ctx = ctx or AnalysisContext()

    def run(self, payload: str) -> DecodeOutcome:
        ctx = self.ctx
        started = time.monotonic_ns()

        current = payload or ""
        current_fp = fingerprint_compute(current)
        ctx.trace.add_fingerprint(current_fp)
        best_score = _score(current_fp)
        depth = 0
        terminal = "no-op"
        stopped_reason = ""

        while True:
            # 1. Budget check
            reason = ctx.budget.exhausted(depth)
            if reason:
                terminal = "budget"
                stopped_reason = f"Budget exhausted ({reason})"
                break

            # 2. Terminal: already plausibly English
            if current_fp.english_density >= _TERMINAL_ENGLISH:
                terminal = "english"
                stopped_reason = f"english_density={current_fp.english_density:.2f} ≥ {_TERMINAL_ENGLISH}"
                break

            # 3. Candidate discovery
            cands = DecoderRegistry.candidates(
                current, current_fp, ctx, top_n=ctx.budget.max_branches
            )
            if not cands:
                terminal = "no-candidate"
                tried = [d.id for d in DecoderRegistry.all()]
                stopped_reason = (
                    f"No decoder claimed confidence ≥ 0.05 on this layer. "
                    f"Tried {len(tried)} plugins: {', '.join(tried) or '(none)'}"
                )
                break

            # 4. Try candidates until one improves things
            accepted = None
            for dec, det in cands:
                step_start = time.monotonic_ns()
                try:
                    res = dec.decode(current, det.args, ctx)
                except Exception as exc:                       # pragma: no cover
                    log.warning("decode() raised in %s: %s", dec.id, exc)
                    continue
                exec_ms = (time.monotonic_ns() - step_start) // 1_000_000
                cand_fp = fingerprint_compute(res.output)
                cand_score = _score(cand_fp)

                # Improvement check — favour longer english/printable output
                if cand_score >= best_score + _IMPROVEMENT_EPS or (
                    res.output != current and cand_score >= best_score * 0.75
                ):
                    step = TraceStep(
                        layer=depth,
                        decoder=dec.id,
                        schema_version=dec.schema_version,
                        confidence=det.confidence,
                        why=det.why,
                        in_len=len(current),
                        out_len=len(res.output),
                        exec_ms=int(exec_ms),
                        preview=res.output[:200],
                        args=det.args,
                        sub_iocs=res.sub_iocs,
                    )
                    ctx.trace.add_step(step)
                    current = res.output
                    current_fp = cand_fp
                    ctx.trace.add_fingerprint(current_fp)
                    best_score = cand_score
                    accepted = dec.id
                    break

            if not accepted:
                if depth == 0:
                    terminal = "no-candidate"
                    tried_names = ", ".join(f"{d.id}({dr.confidence:.2f})" for d, dr in cands)
                    stopped_reason = (
                        f"No decoder produced a useful transform on the raw input. "
                        f"Considered: {tried_names}."
                    )
                else:
                    terminal = "complete"
                    tried_names = ", ".join(f"{d.id}({dr.confidence:.2f})" for d, dr in cands)
                    stopped_reason = (
                        f"Decoded {depth} layer(s); no further transform improved the score. "
                        f"Considered at final layer: {tried_names}. "
                        f"Final english_density={current_fp.english_density:.2f}, "
                        f"printable={current_fp.printable_ratio:.2f}."
                    )
                break

            depth += 1

        elapsed_ms = (time.monotonic_ns() - started) // 1_000_000
        return DecodeOutcome(
            output=current,
            trace=list(ctx.trace.steps),
            fingerprint_history=list(ctx.trace.fingerprints),
            terminal=terminal,
            stopped_reason=stopped_reason,
            elapsed_ms=int(elapsed_ms),
            engine="orchestrator-v1",
        )
