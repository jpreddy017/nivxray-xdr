"""
Provenance records emitted by every convergence iteration.

Each pass returns a :class:`PassRecord`; the engine aggregates one
:class:`IterationRecord` per iteration. These records feed:

* Human-readable Transformation Provenance blocks (spec §Transformation
  Provenance).
* The machine-readable Convergence Certificate.
* Regression debugging when the engine terminates unexpectedly.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class PassRecord:
    """Outcome of a single transformation pass within one iteration."""

    name: str  # "structural" | "content" | "decoder" | "semantic"
    changed: bool
    transformations: tuple[str, ...] = field(default_factory=tuple)
    # Optional short notes explaining what the pass observed / skipped;
    # kept small so certificates remain compact.
    notes: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "changed": self.changed,
            "transformations": list(self.transformations),
            "notes": list(self.notes),
        }


@dataclass(frozen=True)
class IterationRecord:
    """Everything that happened during one convergence iteration."""

    iteration: int  # 1-indexed
    passes: tuple[PassRecord, ...]
    content_hash_before: str
    content_hash_after: str
    interpreter_before: str | None
    interpreter_after: str | None

    @property
    def any_change(self) -> bool:
        return self.content_hash_before != self.content_hash_after or any(
            p.changed for p in self.passes
        )

    def to_dict(self) -> dict:
        return {
            "iteration": self.iteration,
            "passes": [p.to_dict() for p in self.passes],
            "content_hash_before": self.content_hash_before,
            "content_hash_after": self.content_hash_after,
            "interpreter_before": self.interpreter_before,
            "interpreter_after": self.interpreter_after,
            "any_change": self.any_change,
        }


__all__ = ["IterationRecord", "PassRecord"]
