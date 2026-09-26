"""command_line detector — any Windows-shell launcher / scheduler /
LOLBAS wrapper. The CRE will do the actual peeling; this detector
only classifies the input so the pipeline knows to dispatch the CRE."""
from __future__ import annotations

import re

from ...evidence import Evidence
from ..models import ArtefactType, Capability

_CMDLINE_MARKERS_RE = re.compile(
    r"(?ix)"
    r"^\s*(?:c:\\[^\s]*\\)?(?:"
    r"wmic|cmd|powershell|pwsh|schtasks|runas|pcalua|start|"
    r"mshta|rundll32|regsvr32|certutil|bitsadmin|msiexec|"
    r"installutil|regasm|regsvcs|msbuild|wscript|cscript|conhost"
    r")(?:\.exe)?\b"
)


class CommandLineDetector:
    NAME = "command_line"
    ARTEFACT_TYPE = ArtefactType.COMMAND_LINE
    CAPABILITIES = (Capability.CRE, Capability.DECODER, Capability.SEMANTIC,
                    Capability.BEHAVIOR, Capability.IOC,
                    Capability.MITRE, Capability.VERDICT)

    def score(self, text: str) -> Evidence | None:
        if not text:
            return None
        m = _CMDLINE_MARKERS_RE.match(text)
        if not m:
            return None
        binary = m.group(0).strip().lower()
        return Evidence(
            source=f"input_understanding.{self.NAME}",
            observation=binary,
            confidence=95,
            rationale=(
                f"Input begins with a known Windows launcher / LOLBIN "
                f"(`{binary}`). Command Reconstruction Engine can peel "
                f"any wrapper chain from here."
            ),
            meta={"detector": self.NAME},
        )


DETECTOR = CommandLineDetector()
