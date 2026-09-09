"""Canonical Evidence object — the single evidence primitive every
Workspace engine must emit.

Every conclusion the Investigation Brain reaches must trace back to
one or more Evidence objects. Because every engine (Input Understanding,
CRE, Decoder, Semantic, Behavior, IOC, ATT&CK, Verdict) emits the
same shape, the Phase 5 Evidence Graph can walk the entire
investigation as a homogeneous DAG with no per-engine adapters.

Guarantees:
    · immutable   — once emitted, evidence is not rewritten
    · truthful    — `observation` must be a direct quote / verbatim
                     signal, never a paraphrase or fabrication
    · confident   — `confidence` reflects the strength of the SIGNAL,
                     not the analyst's opinion of it
    · explainable — `rationale` is one sentence an analyst can read
                     to understand why this signal matters
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class Evidence:
    """One atomic piece of evidence supporting a Workspace conclusion.

    Fields:
        source       — the engine / module that emitted this evidence
                        (e.g. "input_understanding.command_line",
                        "cre.wmic", "decoder.base64", "semantic.ast",
                        "behavior.webclient_downloadstring").
        observation  — the verbatim / structured signal detected. Kept
                        short and truthful. Never a summary — the
                        analyst must be able to grep the original
                        input for this string.
        confidence   — 0-100, strength of the signal. 100 = the source's
                        own grammar proves the conclusion; lower values
                        reflect heuristic / lossy matches.
        rationale    — one-sentence analyst-facing explanation of WHY
                        this observation is meaningful.
        meta         — free-form structured context (line offset,
                        wrapper depth, decoder step index, etc.).
                        Consumers must not rely on any specific key
                        beyond what their emitting engine documents.
    """
    source: str
    observation: str
    confidence: int
    rationale: str
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


__all__ = ["Evidence"]
