"""
Artifact — the immutable payload state that flows through the
Convergence Engine.

Design contract
---------------
* Immutable. Every pass returns a *new* Artifact if it changed anything.
* Content is stored as ``str`` (the canonical decode-pipeline payload
  is always text at pass boundaries).
* Every Artifact carries a stable SHA-256 hash of its content; the
  engine terminates when the hash stops changing.
* Interpreter ownership is tracked here so Canonical State Contract
  condition #4 can be enforced (interpreter must not change across
  iterations).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

# Module-level sentinel so callers of :meth:`Artifact.replace` can
# distinguish "keep existing value" from "clear to None".
_UNSET: Any = object()


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


@dataclass(frozen=True)
class Artifact:
    """Immutable payload state.

    ``metadata`` is an opaque dict for pass-authored annotations
    (e.g., an emitted decoder-candidate list). It participates in
    equality but not in the content hash — the engine terminates on
    *content* stability, not metadata churn.
    """

    content: str
    interpreter: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def content_hash(self) -> str:
        return _sha256(self.content)

    @classmethod
    def from_input(
        cls,
        raw_input: str,
        interpreter: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> "Artifact":
        return cls(
            content=raw_input if isinstance(raw_input, str) else str(raw_input),
            interpreter=interpreter,
            metadata=dict(metadata or {}),
        )

    def replace(
        self,
        *,
        content: str | None = None,
        interpreter: Any = _UNSET,
        metadata: dict[str, Any] | None = None,
    ) -> "Artifact":
        return Artifact(
            content=self.content if content is None else content,
            interpreter=self.interpreter if interpreter is _UNSET else interpreter,
            metadata=dict(self.metadata) if metadata is None else dict(metadata),
        )


__all__ = ["Artifact"]
