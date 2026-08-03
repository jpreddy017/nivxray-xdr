"""
Canonical Candidate Selector · M6.

This module is the sole gateway through which callers wire the
Convergence Engine into any application-level decode pipeline
(``analysis_core.deterministic_best_decode``, ``/api/decode/smart``,
batch runners, corpus certification tools, ...). It replaces the
legacy "highest score wins" winner-picker with a *certificate-driven*
canonical selector:

    Legacy   :  candidates → score → pick highest
    M6       :  artifact → converge → certificate → canonical selection

If the Convergence Engine reaches ``canonical_state=YES`` AND the
final artifact is materially different from the input, the selector
returns a decode-shaped response envelope. Otherwise it returns
``None`` and the caller falls back to whatever pipeline it had
before (that fallback is *deliberately preserved* — every case the
Convergence Engine has not yet modelled must still work).

The returned envelope is compatible with the shape produced by
``analysis_core.deterministic_best_decode`` so callers can adopt
the M6 result without changing anything downstream. In particular:

  * ``output``  — the final canonical artifact content
  * ``steps``   — a flat list of ``{op, args, layer, iteration}``
                  transformation records, one entry per fired
                  transformation across every iteration
  * ``engine``  — literal ``"convergence"``
  * ``convergence_certificate`` — the full machine-readable certificate
  * ``certificate_fingerprint``  — SHA-256 of the canonical JSON
                                   (fingerprint stability guarantees
                                   deterministic selection across runs)
  * ``layer_trace`` — three-row ladder matching the legacy
                       archetype-match trace: L0 convergence matched,
                       L1 smart skipped, L2 magic skipped.
"""
from __future__ import annotations

from typing import Any, Optional

from . import Artifact, converge
from .engine import ConvergenceResult


def _steps_from_iterations(result: ConvergenceResult) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    for it in result.iterations:
        for pass_record in it.passes:
            if not pass_record.changed:
                continue
            for entry in pass_record.transformations:
                # Each entry looks like `content-env-var-substitute x2`.
                name, _, count_str = entry.partition(" x")
                try:
                    count = int(count_str) if count_str else 1
                except ValueError:
                    count = 1
                steps.append(
                    {
                        "op": name,
                        "args": {"count": count},
                        "layer": pass_record.name,
                        "iteration": it.iteration,
                    }
                )
    return steps


def _build_response(
    original: str,
    result: ConvergenceResult,
) -> dict[str, Any]:
    steps = _steps_from_iterations(result)
    return {
        "steps": steps,
        "output": result.final_artifact.content,
        "engine": "convergence",
        "reached_shellcode": False,
        "convergence_certificate": result.certificate.to_dict(),
        "certificate_fingerprint": result.certificate.fingerprint,
        "layer_trace": [
            {
                "layer": "L0",
                "engine": "convergence",
                "chain_len": len(steps),
                "score": 1.0,
                "verdict": "canonical",
            },
            {"layer": "L1", "engine": "smart", "chain_len": 0,
             "score": 0.0, "verdict": "skipped"},
            {"layer": "L2", "engine": "magic", "chain_len": 0,
             "score": 0.0, "verdict": "skipped"},
        ],
        "notes": [
            f"Canonical Convergence Engine · {result.certificate.iterations_executed} iteration(s)",
            f"Certificate fingerprint: {result.certificate.fingerprint[:16]}...",
        ],
    }


def convergence_decode(payload: str) -> Optional[dict[str, Any]]:
    """Run the Convergence Engine on ``payload`` and, if canonical
    convergence completes with a materially changed output, return a
    decode-shaped response envelope.

    Returns ``None`` when:
      * the engine could not reach ``canonical_state=YES`` within
        ``MAX_ITERATION_DEPTH``, OR
      * the engine reached canonical state but the output is
        byte-identical to the input (nothing to decode — the input
        was already canonical or the engine's current transformation
        set could not reduce it).

    The ``None`` fallthrough is intentional: it keeps legacy paths
    responsible for cases the engine has not yet modelled, so
    integration is strictly additive with zero regression surface.
    """
    if not isinstance(payload, str) or not payload:
        return None
    try:
        result = converge(Artifact.from_input(payload))
    except (TypeError, ValueError):
        return None
    if not result.canonical:
        return None
    if result.final_artifact.content == payload:
        return None
    return _build_response(payload, result)


__all__ = ["convergence_decode"]
