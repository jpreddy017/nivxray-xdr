"""
Convergence Certificate — the machine-readable artifact emitted at
the end of every convergence run.

Format matches the specification (§Convergence Certificate). It is
JSON-serializable and hash-stable across identical inputs, which is
what CI-side determinism gates verify.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from .provenance import IterationRecord


@dataclass(frozen=True)
class ConvergenceCertificate:
    iterations_executed: int
    structural_changes: int
    content_changes: int
    decoder_changes: int
    semantic_changes: int
    canonical_state: bool
    remaining_deterministic_ops: int  # 0 when canonical_state is True
    residual_obfuscation: str  # "NONE" | descriptor
    final_artifact_hash_sha256: str
    initial_artifact_hash_sha256: str
    max_depth_reached: bool
    terminated_reason: str  # e.g. "canonical_state" | "max_depth" | "hash_stable"
    ready_for_behavioral_analysis: bool
    # M1 does not perform transformations; a future milestone will
    # extend this with the winning candidate id, interpreter, etc.
    interpreter: str | None = None
    engine_version: str = "M1-1.0.0"

    def to_dict(self) -> dict[str, Any]:
        return {
            "iterations_executed": self.iterations_executed,
            "structural_changes": self.structural_changes,
            "content_changes": self.content_changes,
            "decoder_changes": self.decoder_changes,
            "semantic_changes": self.semantic_changes,
            "canonical_state": self.canonical_state,
            "remaining_deterministic_ops": self.remaining_deterministic_ops,
            "residual_obfuscation": self.residual_obfuscation,
            "final_artifact_hash_sha256": self.final_artifact_hash_sha256,
            "initial_artifact_hash_sha256": self.initial_artifact_hash_sha256,
            "max_depth_reached": self.max_depth_reached,
            "terminated_reason": self.terminated_reason,
            "ready_for_behavioral_analysis": self.ready_for_behavioral_analysis,
            "interpreter": self.interpreter,
            "engine_version": self.engine_version,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @property
    def fingerprint(self) -> str:
        """SHA-256 of the canonical-JSON encoding. Used by CI to prove
        certificates are hash-stable across repeated runs."""
        return hashlib.sha256(self.to_json().encode("utf-8")).hexdigest()


def build_certificate(
    initial_hash: str,
    final_hash: str,
    iterations: list[IterationRecord],
    canonical_state: bool,
    max_depth_reached: bool,
    terminated_reason: str,
    interpreter: str | None,
) -> ConvergenceCertificate:
    """Aggregate iteration records into a single certificate."""
    def _count(pass_name: str) -> int:
        return sum(1 for it in iterations for p in it.passes if p.name == pass_name and p.changed)

    return ConvergenceCertificate(
        iterations_executed=len(iterations),
        structural_changes=_count("structural"),
        content_changes=_count("content"),
        decoder_changes=_count("decoder"),
        semantic_changes=_count("semantic"),
        canonical_state=canonical_state,
        remaining_deterministic_ops=0 if canonical_state else -1,
        residual_obfuscation="NONE" if canonical_state else "UNRESOLVED",
        final_artifact_hash_sha256=final_hash,
        initial_artifact_hash_sha256=initial_hash,
        max_depth_reached=max_depth_reached,
        terminated_reason=terminated_reason,
        ready_for_behavioral_analysis=canonical_state,
        interpreter=interpreter,
    )


__all__ = ["ConvergenceCertificate", "build_certificate"]
