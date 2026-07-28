"""Recursive Transformation Engine (RTE) · canonical models.

The RTE answers ONE question, repeatedly:

    "Is there a deterministic transformation that changes THIS artefact
     into a more understandable form?"

If yes — apply it, reclassify, remember the step, and ask again.
If no — stop. The remaining artefact is the effective plaintext the
Investigation Brain will analyze semantically.

Every layer is preserved. Every step emits canonical Evidence. Every
step is deterministic and side-effect-free. The engine is transformation-
agnostic: adding a new transformation is a one-file change under
``transformations/``.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from ..evidence import Evidence
from ..iu.models import ArtefactClassification


class StopReason(str, Enum):
    """Why the recursive transformation loop halted.

    NEVER "decoder finished" — the engine only stops for one of the
    principled reasons below.
    """
    NO_TRANSFORMATION = "no_transformation"   # nothing more applies
    LOOP              = "loop"                # produced a state we've seen
    MAX_DEPTH         = "max_depth"           # safety cap hit
    UNSUPPORTED       = "unsupported"         # artefact type has no handler
    EMPTY_INPUT       = "empty_input"         # nothing to transform


@dataclass(frozen=True)
class Artifact:
    """One layer in the transformation chain.

    Layer 0 is the original input. Every subsequent layer is the OUTPUT
    of applying a single deterministic transformation to the layer above.

    `content` is always a ``str`` because analyst-facing evidence must
    be greppable. Byte outputs are text-decoded (utf-8/latin-1) and the
    binary hash is recorded in ``meta`` for provenance.
    """
    content: str
    classification: ArtefactClassification
    layer: int
    content_hash: str          # sha256[:16] of the utf-8 encoded content
    parent_hash: str | None    # ``None`` for layer 0
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "content":         self.content,
            "classification":  self.classification.to_dict(),
            "layer":           self.layer,
            "content_hash":    self.content_hash,
            "parent_hash":     self.parent_hash,
            "meta":            self.meta,
        }


@dataclass(frozen=True)
class TransformationStep:
    """One deterministic transformation applied to a specific Artifact.

    Records enough information for an analyst — or the Evidence Graph —
    to replay the transformation and to understand *why* it was applied.
    """
    transformation: str
    input_layer: int
    output_layer: int
    input_hash: str
    output_hash: str
    input_length: int
    output_length: int
    evidence: list[Evidence]
    confidence: int

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["evidence"] = [e.to_dict() for e in self.evidence]
        return d


@dataclass(frozen=True)
class DecodeDiagnostic:
    """A per-layer diagnostic emitted when a transformation *detected*
    a plausible pattern but could not decode it deterministically.

    Introduced in v1.5.0 to satisfy the DoD requirement:

        "Reports deterministic failure reasons when decoding cannot
         continue."

    Diagnostics are surfaced through :attr:`TransformationChain.diagnostics`
    so the analyst can see WHY the pipeline stopped instead of a silent
    ``no_transformation``. Diagnostics MUST be evidence-anchored and
    MUST NOT fabricate a decoded value.
    """
    layer: int                 # the artifact layer this diagnostic refers to
    detector: str              # which transformation plugin produced it
    attempted: str             # short description of what was attempted
    outcome: str               # "decode_failed" / "detection_only" / "malformed_input"
    reason: str                # deterministic explanation for the analyst
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TransformationChain:
    """Full history of transformations applied to the original input.

    ``artifacts[0]`` is always the original untouched input. ``artifacts[-1]``
    is the effective plaintext (or the last layer we could reach). Every
    transformation between layers ``i`` and ``i+1`` is recorded in
    ``steps[i]``.
    """
    artifacts: list[Artifact]
    steps: list[TransformationStep]
    stop_reason: StopReason
    determinism_hash: str = ""
    # v1.5.0 — per-layer decode diagnostics. Populated by transformation
    # plugins whose ``diagnose()`` reports a "detected but couldn't
    # decode" outcome (e.g. base64 misaligned, gzip truncated, XOR key
    # ambiguous). See :class:`DecodeDiagnostic`.
    diagnostics: list[DecodeDiagnostic] = field(default_factory=list)

    @property
    def final(self) -> Artifact:
        return self.artifacts[-1]

    @property
    def depth(self) -> int:
        return len(self.artifacts) - 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifacts":        [a.to_dict() for a in self.artifacts],
            "steps":            [s.to_dict() for s in self.steps],
            "stop_reason":      self.stop_reason.value,
            "depth":            self.depth,
            "final_layer":      self.final.layer,
            "determinism_hash": self.determinism_hash,
            "diagnostics":      [d.to_dict() for d in self.diagnostics],
        }


__all__ = [
    "Artifact",
    "TransformationStep",
    "TransformationChain",
    "StopReason",
    "DecodeDiagnostic",
]
