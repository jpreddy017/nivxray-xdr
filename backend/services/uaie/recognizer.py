"""UAIE Contract #2 · Recognizer (Rule R25)

Answers ONE question: "what is this artifact?"  Never decodes,
never analyses — only classifies.  Emits a Recognition with an
explainable ``reasons[]`` chain.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing      import List, Protocol, runtime_checkable

from .artifact import Artifact


# ── Global confidence semantics · Rule R25 amendment #4 ──
#   0.00  Unknown        0.25  Possible     0.50  Likely
#   0.75  High           0.90+ Certain
UNKNOWN, POSSIBLE, LIKELY, HIGH, CERTAIN = 0.00, 0.25, 0.50, 0.75, 0.90


@dataclass(frozen=True)
class Reason:
    signal:  str         # "magic_bytes" / "grammar" / "entropy" / …
    score:   float       # signed contribution to confidence
    detail:  str = ""


@dataclass(frozen=True)
class Recognition:
    artifact_type:  str          # what THIS recognizer claims the artifact is
    confidence:     float        # 0.00 – 1.00, global scale
    reasons:        List[Reason] = field(default_factory=list)
    recognizer:     str = ""     # populated by the registry


@runtime_checkable
class Recognizer(Protocol):
    """Every recognizer implements this protocol.  Pure function —
    same artifact in, same Recognition out."""

    name: str

    def recognize(self, artifact: Artifact) -> List[Recognition]: ...
