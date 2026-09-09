"""ps_encoded_command · extract the ``-EncodedCommand`` argument from
a ``powershell.exe`` invocation, decode it as base64 → UTF-16LE, and
surface the resulting script as the next layer.

This is the classic Windows evasion shape:
    powershell.exe -NoP -W Hidden -EncodedCommand <base64-utf-16-le>

The CRE already peels wrapper chains structurally, but its output is
still the command-line with the argument in place. The RTE runs one
extra step to reveal the script payload as an independent artefact so
Input Understanding can reclassify it as ``powershell_script`` — this
is exactly the "reclassify after every transformation" requirement.
"""
from __future__ import annotations

import base64
import re

from ...evidence import Evidence
from ..models import Artifact
from ._util import printable_ratio

_ENCODED_ARG_RE = re.compile(
    r"(?ix)"
    r"(?:^|\s)(?:powershell|pwsh)(?:\.exe)?\b[^\n]*?"
    r"-(?:e|ec|enc|encoded|encodedcommand)\s+"
    r"([A-Za-z0-9+/=]{16,})",
)


class PsEncodedCommandTransformation:
    NAME = "ps_encoded_command"

    def _blob(self, artifact: Artifact) -> str | None:
        m = _ENCODED_ARG_RE.search(artifact.content)
        if not m:
            return None
        blob = m.group(1)
        # Blob length must be a base64 multiple of 4.
        if len(blob) % 4 != 0:
            return None
        return blob

    def applicable(self, artifact: Artifact) -> Evidence | None:
        blob = self._blob(artifact)
        if blob is None:
            return None
        try:
            raw = base64.b64decode(blob, validate=True)
        except Exception:
            return None
        try:
            decoded = raw.decode("utf-16-le")
        except UnicodeDecodeError:
            return None
        if printable_ratio(decoded) < 0.90:
            return None
        return Evidence(
            source=f"rte.{self.NAME}",
            observation=f"powershell -EncodedCommand blob of {len(blob)} chars",
            confidence=98,
            rationale=(
                "Command line contains a `-EncodedCommand` argument whose "
                "bytes decode as printable UTF-16LE PowerShell. Peeling "
                "reveals the script payload as an independent artefact."
            ),
            meta={"blob_length": len(blob)},
        )

    def apply(self, artifact: Artifact) -> tuple[str, list[Evidence]]:
        blob = self._blob(artifact)
        assert blob is not None
        raw = base64.b64decode(blob, validate=True)
        decoded = raw.decode("utf-16-le")
        ev = Evidence(
            source=f"rte.{self.NAME}",
            observation=decoded[:120],
            confidence=98,
            rationale=(
                "Extracted and decoded the PowerShell -EncodedCommand "
                "argument. Next layer is the raw PowerShell script."
            ),
            meta={
                "in_len":  len(artifact.content),
                "out_len": len(decoded),
                "encoding": "utf-16-le",
            },
        )
        return decoded, [ev]


TRANSFORMATION = PsEncodedCommandTransformation()
