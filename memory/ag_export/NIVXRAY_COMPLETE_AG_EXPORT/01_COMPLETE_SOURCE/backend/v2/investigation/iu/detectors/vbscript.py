"""VBScript detector — WScript.Shell, Dim, Set primitives."""
from __future__ import annotations

import re

from ...evidence import Evidence
from ..models import ArtefactType, Capability

_VBS_STRONG_RE = re.compile(
    r"(?im)"
    # Structural VBA/VBScript markers — Sub … End Sub, CreateObject(WScript.Shell)
    r"^\s*Sub\s+\w+\s*\(.*?\).*?End\s+Sub"
    r"|CreateObject\s*\(\s*['\"]WScript\.Shell['\"]\s*\)"
    r"|CreateObject\s*\(\s*['\"]Scripting\."
    r"|\bWScript\.Shell\b",
    re.DOTALL,
)
_VBS_WEAK_RE = re.compile(
    r"(?im)"
    r"^\s*Set\s+\w+\s*=\s*"
    r"|^\s*Dim\s+\w+"
    r"|\bMsgBox\s+"
    r"|\bWShell\.Run\b"
)


class VBScriptDetector:
    NAME = "vbscript"
    ARTEFACT_TYPE = ArtefactType.VBSCRIPT
    CAPABILITIES = (Capability.VBSCRIPT_ENGINE, Capability.DECODER,
                    Capability.IOC, Capability.MITRE, Capability.VERDICT)

    def score(self, text: str) -> Evidence | None:
        if not text:
            return None
        # Strong structural markers score 95 (outrank generic PS token
        # matches found inside a string literal). Weak markers score 80.
        m = _VBS_STRONG_RE.search(text)
        conf = 95
        if not m:
            m = _VBS_WEAK_RE.search(text)
            conf = 80
        if not m:
            return None
        return Evidence(
            source=f"input_understanding.{self.NAME}",
            observation=m.group(0)[:60],
            confidence=conf,
            rationale=(
                "VBScript / VBA-shape detected — structural markers "
                "(`Sub`/`End Sub`, `CreateObject('WScript.Shell')`) or "
                "declaration primitives (`Set` / `Dim`)."
            ),
            meta={"detector": self.NAME},
        )


DETECTOR = VBScriptDetector()
