"""powershell_script detector — naked PS content, PS-obfuscation
tokens, or `-EncodedCommand` sequences."""
from __future__ import annotations

import re

from ...evidence import Evidence
from ..models import ArtefactType, Capability

_PS_TOKENS_RE = re.compile(
    r"(?ix)"
    r"-encodedcommand\b|-enc\b|-ec\b"
    r"|\biex\b|\binvoke-expression\b"
    r"|\binvoke-webrequest\b|\biwr\b|\binvoke-restmethod\b|\birm\b"
    r"|\[net\.webclient\]|\[system\.net\.webclient\]"
    r"|\[string\]::(?:join|format)\b"
    r"|\[convert\]::(?:toint16|toint32|frombase64string)\b"
    r"|\bnew-object\b|\bwrite-host\b|\bwrite-output\b"
    r"|\b(?:Get|Set|New|Add|Remove|Test|Start|Stop|Where|ForEach|Select|"
    r"Sort|Format|Import|Export|Invoke|Register)-[A-Z][A-Za-z0-9]+\b"
)


class PowerShellScriptDetector:
    NAME = "powershell_script"
    ARTEFACT_TYPE = ArtefactType.POWERSHELL_SCRIPT
    CAPABILITIES = (Capability.CRE, Capability.DECODER, Capability.SEMANTIC,
                    Capability.BEHAVIOR, Capability.IOC,
                    Capability.MITRE, Capability.VERDICT)

    def score(self, text: str) -> Evidence | None:
        if not text:
            return None
        m = _PS_TOKENS_RE.search(text)
        if not m:
            return None
        token = m.group(0)
        return Evidence(
            source=f"input_understanding.{self.NAME}",
            observation=token,
            confidence=90,
            rationale=(
                f"PowerShell-specific token `{token}` detected — script "
                f"will be routed to the PS semantic + deobfuscation "
                f"pipeline."
            ),
            meta={"detector": self.NAME},
        )


DETECTOR = PowerShellScriptDetector()
