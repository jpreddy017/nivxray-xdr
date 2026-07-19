"""BaseDecoder — abstract plugin contract for L2.

Every atomic decoder subclasses this. The contract:
    - `id`, `name`, `category`, `cost`, `tags`, `schema_version` (class attrs)
    - `detect(payload, fingerprint, ctx) -> DetectResult`
    - `decode(payload, args, ctx)      -> DecodeResult`

Guidelines
----------
* detect() must be cheap — it may run for many candidates per layer.
* decode() may be more expensive; it runs at most `max_branches` times per layer.
* Neither method should raise on ordinary "does not apply" — return low confidence
  or an empty output instead. Uncaught exceptions ARE caught by the orchestrator
  and logged as a failed step, but this should be treated as a bug.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict

from .models import (
    AnalysisContext,
    DecodeResult,
    DetectResult,
    Fingerprint,
)


class BaseDecoder(ABC):
    id: str = "base"
    name: str = "Base Decoder"
    category: str = "encoding"          # encoding | compression | cipher | reconstruct | normalize
    cost: int = 1                       # perf hint; higher = more expensive
    tags: tuple[str, ...] = ()
    schema_version: str = "1.0"

    @abstractmethod
    def detect(
        self,
        payload: str,
        fingerprint: Fingerprint,
        ctx: AnalysisContext,
    ) -> DetectResult: ...

    @abstractmethod
    def decode(
        self,
        payload: str,
        args: Dict[str, Any],
        ctx: AnalysisContext,
    ) -> DecodeResult: ...

    # Convenience for logs/debug
    def __repr__(self) -> str:                       # pragma: no cover
        return f"<{self.__class__.__name__} id={self.id!r} v{self.schema_version}>"
