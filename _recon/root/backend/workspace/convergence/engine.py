"""
Convergence Engine loop · M1.

Runs the four passes in canonical order (Structural → Content →
Decoder → Semantic) repeatedly until the Canonical State Contract is
satisfied or the max-depth safeguard trips. In M1 every pass is a
no-op, so the loop MUST terminate in exactly one iteration on every
input (spec §"Concrete implementation footholds" · M1 verification).

Termination rules
-----------------
The engine terminates on the FIRST iteration whose ``any_change`` is
False, i.e. the content hash matches the previous state AND no pass
reported a change. This is the direct application of Canonical State
Contract conditions #1, #2, and #6.

Interpreter-ownership invariance (contract condition #4) is checked
after every iteration and short-circuits with ``terminated_reason =
"interpreter_drift"`` if violated. M1 no-ops never touch the
interpreter, so this branch cannot fire in M1 — but its presence in the
loop is what allows M4/M5 to add decoder ownership safely later.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from . import content as content_pass
from . import decoder as decoder_pass
from . import semantic as semantic_pass
from . import structural as structural_pass
from .artifact import Artifact
from .certificate import ConvergenceCertificate, build_certificate
from .provenance import IterationRecord, PassRecord

# Spec §"Concrete implementation footholds" recommends 16.
MAX_ITERATION_DEPTH: int = 16

# Canonical pass order. This ordering is a hard architectural invariant
# (Recovery Program invariant #1 · Decoder Ordering Contract).
_PASS_PIPELINE: tuple[tuple[str, Callable[[Artifact], tuple[Artifact, PassRecord]]], ...] = (
    ("structural", structural_pass.run),
    ("content", content_pass.run),
    ("decoder", decoder_pass.run),
    ("semantic", semantic_pass.run),
)


@dataclass(frozen=True)
class ConvergenceResult:
    """The complete outcome of a convergence run."""

    final_artifact: Artifact
    iterations: tuple[IterationRecord, ...]
    certificate: ConvergenceCertificate
    terminated_reason: str  # "canonical_state" | "max_depth" | "interpreter_drift"

    @property
    def canonical(self) -> bool:
        return self.certificate.canonical_state


@dataclass
class _EngineState:
    artifact: Artifact
    iterations: list[IterationRecord] = field(default_factory=list)


def _run_one_iteration(
    artifact: Artifact, iteration_index: int
) -> tuple[Artifact, IterationRecord]:
    """Execute all four passes in canonical order for a single iteration.

    Returns the post-pipeline artifact AND the iteration record so the
    engine loop never re-executes passes.
    """
    hash_before = artifact.content_hash
    interp_before = artifact.interpreter
    records: list[PassRecord] = []

    current = artifact
    for _pass_name, fn in _PASS_PIPELINE:
        current, record = fn(current)
        records.append(record)

    return current, IterationRecord(
        iteration=iteration_index,
        passes=tuple(records),
        content_hash_before=hash_before,
        content_hash_after=current.content_hash,
        interpreter_before=interp_before,
        interpreter_after=current.interpreter,
    )


def converge(
    artifact: Artifact,
    *,
    max_depth: int = MAX_ITERATION_DEPTH,
) -> ConvergenceResult:
    """Run the deterministic convergence loop over ``artifact``.

    Returns a :class:`ConvergenceResult` containing the final artifact,
    all iteration records, and a machine-readable Convergence
    Certificate. This function has NO side effects; it never mutates
    the input artifact.
    """
    if not isinstance(artifact, Artifact):
        raise TypeError("converge() requires an Artifact instance")
    if max_depth < 1:
        raise ValueError("max_depth must be >= 1")

    initial_hash = artifact.content_hash
    state = _EngineState(artifact=artifact)
    terminated_reason = "canonical_state"
    max_depth_reached = False
    canonical = False

    for i in range(1, max_depth + 1):
        # Execute one full pass pipeline; capture BOTH the post-pipeline
        # artifact and the iteration record. Passes are pure functions,
        # so the returned artifact is the authoritative next state.
        next_artifact, record = _run_one_iteration(state.artifact, i)
        state.iterations.append(record)
        state.artifact = next_artifact

        # Interpreter-drift check (Canonical State Contract #4).
        if record.interpreter_before != record.interpreter_after and i > 1:
            terminated_reason = "interpreter_drift"
            canonical = False
            break

        # Canonical State Contract #1, #2, #6:
        # If nothing changed this iteration, we have converged.
        if not record.any_change:
            terminated_reason = "canonical_state"
            canonical = True
            break

        if i == max_depth:
            terminated_reason = "max_depth"
            max_depth_reached = True
            canonical = False
            break

    certificate = build_certificate(
        initial_hash=initial_hash,
        final_hash=state.artifact.content_hash,
        iterations=state.iterations,
        canonical_state=canonical,
        max_depth_reached=max_depth_reached,
        terminated_reason=terminated_reason,
        interpreter=state.artifact.interpreter,
    )

    return ConvergenceResult(
        final_artifact=state.artifact,
        iterations=tuple(state.iterations),
        certificate=certificate,
        terminated_reason=terminated_reason,
    )


__all__ = [
    "MAX_ITERATION_DEPTH",
    "ConvergenceResult",
    "converge",
]
