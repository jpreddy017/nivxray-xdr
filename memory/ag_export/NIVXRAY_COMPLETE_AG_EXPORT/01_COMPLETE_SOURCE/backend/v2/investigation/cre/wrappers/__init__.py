"""Wrapper parser registry.

Each wrapper is implemented as a module exposing a WrapperParser
instance. Adding a new wrapper is a one-file change:

    1. Create `wrappers/<name>.py` defining `PARSER = MyWrapper()`.
    2. Import it below and register into `WRAPPER_REGISTRY`.

No engine modification is required. The registry is ORDER-SENSITIVE
during a single peel — parsers are tried in the sequence declared
here. Put the most specific / highest-confidence parsers first so
they win the match race (e.g. `powershell` before `cmd`, because a
`cmd /c powershell -c "..."` line is peelable by either but the cmd
parser should own that peel).
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..models import WrapperChainStep


@runtime_checkable
class WrapperParser(Protocol):
    """The single interface every wrapper parser must implement."""

    NAME: str          # canonical lowercase wrapper name

    def match(self, cmdline: str) -> bool:
        """Cheap boolean pre-check — is this cmdline a candidate for
        the parser's `extract` step? Must be side-effect-free."""
        ...

    def extract(self, cmdline: str) -> WrapperChainStep | None:
        """Return the WrapperChainStep for a single peel, or None if
        the input didn't match the parser's grammar. Must never raise
        for well-formed str input — return None on ambiguous cases so
        the engine can try the next parser."""
        ...


# ── Registry (ORDER-SENSITIVE — most specific parsers first) ────
from .cmd import PARSER as _CMD               # noqa: E402
from .pcalua import PARSER as _PCALUA         # noqa: E402
from .powershell import PARSER as _POWERSHELL # noqa: E402
from .runas import PARSER as _RUNAS           # noqa: E402
from .schtasks import PARSER as _SCHTASKS     # noqa: E402
from .start import PARSER as _START           # noqa: E402
from .wmic import PARSER as _WMIC             # noqa: E402


WRAPPER_REGISTRY: list[WrapperParser] = [
    _WMIC,        # wmic process call create CommandLine="..."
    _SCHTASKS,    # schtasks /create ... /tr "..."
    _RUNAS,       # runas /user:X "..."
    _PCALUA,      # pcalua.exe -a "..." (LOLBAS wrapper)
    _START,       # start "" "..." | start "..."
    _POWERSHELL,  # powershell -Command "..." | -EncodedCommand ...
    _CMD,         # cmd /c "..." | /k "..."
]

__all__ = ["WrapperParser", "WRAPPER_REGISTRY"]
