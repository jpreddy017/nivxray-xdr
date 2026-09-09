"""Universal Parser contract.

Turns an adapter-agnostic byte stream into a structured intermediate
`ParsedEvent`. Phase 1 ships the Protocol only — no implementations.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterator, Protocol, runtime_checkable

from v2.adapters.base import RawEvent, Source


@dataclass(frozen=True)
class ParsedEvent:
    """Adapter-agnostic but still not yet normalized."""
    adapter: str
    sequence: int
    kind_hint: str | None
    payload: dict[str, Any]
    extras: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class Parser(Protocol):
    name: str
    version: str

    def parse(self, raw: RawEvent) -> ParsedEvent:
        """Return a single ParsedEvent per RawEvent."""

    def stream(self, source: Source) -> Iterator[ParsedEvent]:
        """Optional streaming parse — falls back to RawEvent iteration."""
