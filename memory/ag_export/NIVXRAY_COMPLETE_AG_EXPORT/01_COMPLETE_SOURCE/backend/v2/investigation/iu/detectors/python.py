"""Python-script detector."""
from __future__ import annotations

import re

from ...evidence import Evidence
from ..models import ArtefactType, Capability

_PY_RE = re.compile(
    r"(?m)"
    r"^\s*#!/(?:usr/)?bin/(?:env\s+)?python[23]?\b"
    r"|^\s*(?:from\s+\S+\s+)?import\s+\w+"
    r"|\b__import__\s*\("
    r"|\beval\s*\(\s*compile\("
    r"|\bexec\s*\(\s*compile\("
    r"|\bos\.system\s*\(|\bsubprocess\.(?:call|Popen|run)\("
)


class PythonDetector:
    NAME = "python"
    ARTEFACT_TYPE = ArtefactType.PYTHON
    CAPABILITIES = (Capability.DECODER, Capability.SEMANTIC,
                    Capability.IOC, Capability.MITRE, Capability.VERDICT)

    def score(self, text: str) -> Evidence | None:
        if not text:
            return None
        m = _PY_RE.search(text)
        if not m:
            return None
        return Evidence(
            source=f"input_understanding.{self.NAME}",
            observation=m.group(0)[:80],
            confidence=85,
            rationale=(
                "Python-shape detected (shebang, import, __import__, "
                "eval/exec compile, or subprocess primitive)."
            ),
            meta={"detector": self.NAME},
        )


DETECTOR = PythonDetector()
