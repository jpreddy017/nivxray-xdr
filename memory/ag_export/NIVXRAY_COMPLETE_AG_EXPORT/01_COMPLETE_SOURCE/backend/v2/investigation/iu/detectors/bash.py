"""bash / POSIX-shell detector."""
from __future__ import annotations

import re

from ...evidence import Evidence
from ..models import ArtefactType, Capability

_BASH_RE = re.compile(
    r"(?m)"
    r"^\s*#!/(?:usr/)?bin/(?:env\s+)?(?:sh|bash|zsh|dash)\b"
    r"|\bcurl\s+-[a-zA-Z]+\s+http|\bwget\s+http"
    r"|\becho\s+.+?\|\s*sh\b|\bcat\s+/etc/passwd\b|\/dev/tcp/"
)


class BashDetector:
    NAME = "bash"
    ARTEFACT_TYPE = ArtefactType.BASH
    CAPABILITIES = (Capability.DECODER, Capability.SEMANTIC,
                    Capability.IOC, Capability.MITRE, Capability.VERDICT)

    def score(self, text: str) -> Evidence | None:
        if not text:
            return None
        m = _BASH_RE.search(text)
        if not m:
            return None
        return Evidence(
            source=f"input_understanding.{self.NAME}",
            observation=m.group(0)[:64],
            confidence=88,
            rationale=(
                "POSIX-shell shape detected — shebang line, curl/wget "
                "pipe-to-shell pattern, or /dev/tcp reverse-shell "
                "primitive."
            ),
            meta={"detector": self.NAME},
        )


DETECTOR = BashDetector()
