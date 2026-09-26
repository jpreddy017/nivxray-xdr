"""Engine interface — the contract every future NivXForge engine must satisfy.

The North Star describes engines as append-only processors: each engine
receives the CIO, appends its findings via `cio.append(...)`, and returns
the same CIO. No engine may overwrite or delete prior data.

Phase 0 defines the Protocol only. No implementations exist yet.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from nivxforge.core.cio import CIO


@runtime_checkable
class Engine(Protocol):
    """The stable contract every NivXForge engine must implement.

    Attributes:
        name: Human-readable identifier. Used as the `engine` value on
              every CIOEntry and Finding this engine emits.

    Methods:
        process(cio): Read from the CIO, append findings via
                      `cio.append(...)`, return the same CIO.
                      MUST NOT overwrite or remove prior entries.
    """

    name: str

    def process(self, cio: CIO) -> CIO:
        ...
