"""Normalizer contract · turns ParsedEvent → CanonicalEvent(s).

Phase 1 ships the Protocol only. Concrete normalizers register per
adapter name in later phases and remain SHADOW-mode-only until
their regression gates close.
"""
from __future__ import annotations

from typing import Iterator, Protocol, runtime_checkable

from v2.cem.v1.schema import CanonicalEvent
from v2.parser.base import ParsedEvent


@runtime_checkable
class Normalizer(Protocol):
    adapter: str        # matches InputAdapter.name
    cem_version: str    # matches CEM registry key, e.g. "v1"

    def normalize(self, parsed: ParsedEvent, *, case_id: str) -> Iterator[CanonicalEvent]:
        """One ParsedEvent may yield 0..N CanonicalEvents."""
