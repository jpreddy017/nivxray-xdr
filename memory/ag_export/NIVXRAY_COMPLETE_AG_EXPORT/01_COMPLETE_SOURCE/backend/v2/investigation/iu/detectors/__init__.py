"""Artefact detector registry.

Each detector implements the ArtefactDetector protocol. Adding a new
artefact type is a one-file change with no engine modification.

Order in `DETECTOR_REGISTRY` is CONFIDENCE-BASED, not exclusive — the
engine runs every detector, collects positive signals, then decides
the primary type from the highest-confidence unique signal set.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..models import ArtefactType, Capability
from ...evidence import Evidence


@runtime_checkable
class ArtefactDetector(Protocol):
    """The interface every artefact detector must implement."""

    NAME: str
    ARTEFACT_TYPE: ArtefactType
    CAPABILITIES: tuple[Capability, ...]   # what this artefact needs

    def score(self, text: str) -> Evidence | None:
        """Return an Evidence object with confidence 1-100 if the input
        matches this detector's grammar; None otherwise. MUST be side-
        effect-free and MUST NOT raise on well-formed input."""
        ...


# ── Registry ────────────────────────────────────────────────────
from .bash import DETECTOR as _BASH                    # noqa: E402
from .command_line import DETECTOR as _CMD_LINE        # noqa: E402
from .javascript import DETECTOR as _JS                # noqa: E402
from .powershell_script import DETECTOR as _PS         # noqa: E402
from .python import DETECTOR as _PY                    # noqa: E402
from .vbscript import DETECTOR as _VBS                 # noqa: E402


DETECTOR_REGISTRY: list[ArtefactDetector] = [
    _CMD_LINE,    # any wmic/cmd/schtasks/runas/pcalua/start-shaped input
    _PS,          # naked PowerShell script or -EncodedCommand
    _BASH,        # #!/bin/bash or POSIX-shell shape
    _PY,          # #!/usr/bin/env python or Py syntax
    _JS,          # JavaScript (mshta, HTA, ActiveX)
    _VBS,         # VBScript (WScript.Shell etc.)
]

__all__ = ["ArtefactDetector", "DETECTOR_REGISTRY"]
