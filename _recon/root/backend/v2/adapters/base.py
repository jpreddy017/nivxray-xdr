"""Adapter base contracts.

Adapters are Protocol implementations discovered by
`v2.adapters.registry.discover()`. In Phase 1, adapters are STUB
CLASSES with no logic — they publish a name/version, declare their
CEM version, and return 0.0 from `detect()`.

Adapter logic ships in later phases, gated by the ADAPTERS feature
flag being SHADOW or ENABLED.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterator, Protocol, runtime_checkable


# ─── Data carriers ───────────────────────────────────────────────────
@dataclass(frozen=True)
class Source:
    """Streamable source for the adapter."""
    kind: str                              # "path" | "bytes" | "sse"
    ref: Any                               # filesystem path, bytes, or stream ref
    hints: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RawEvent:
    """Adapter-agnostic (not yet normalized) event carrier."""
    adapter: str
    sequence: int
    payload: dict[str, Any]
    raw_bytes: bytes | None = None


# ─── Adapter Protocol ────────────────────────────────────────────────
@runtime_checkable
class InputAdapter(Protocol):
    name: str
    version: str
    supported_formats: tuple[str, ...]
    capabilities: frozenset[str]
    cem_version: str

    def detect(self, sample: bytes | str) -> float:
        """Return confidence 0.0–1.0 that this adapter can read `sample`."""

    def stream(self, source: Source, *, chunk_size: int = 4096) -> Iterator[RawEvent]:
        """Yield RawEvent objects. Must be back-pressure friendly."""


# ─── Optional base class for stubs ───────────────────────────────────
class BaseAdapter:
    """Convenience base for adapter stubs. Concrete adapters override
    `detect` and `stream` in later phases."""
    name: str = "unnamed"
    version: str = "0.0.0"
    supported_formats: tuple[str, ...] = ()
    capabilities: frozenset[str] = frozenset()
    cem_version: str = "v1"

    def detect(self, sample: bytes | str) -> float:  # pragma: no cover · overridden later
        return 0.0

    def stream(self, source: Source, *, chunk_size: int = 4096) -> Iterator[RawEvent]:  # pragma: no cover
        return iter(())
