"""base64_utf16le · decode a base64 blob whose bytes are a valid
UTF-16LE PowerShell script.

This is the canonical Windows ``-EncodedCommand`` shape. When the
blob decodes cleanly to UTF-16LE printable text the transformation
fires with very high confidence — it is the single most reliable
transformation in the Windows adversarial toolkit.
"""
from __future__ import annotations

import base64
import re

from ...evidence import Evidence
from ..models import Artifact
from ._util import printable_ratio, strip_quotes

# Base64 alphabet only. Whitespace stripping happens before match.
_B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


class Base64Utf16LeTransformation:
    NAME = "base64_utf16le"

    def _candidate(self, artifact: Artifact) -> str | None:
        text = strip_quotes(artifact.content).strip()
        if len(text) < 12:
            return None
        # Base64 length must be a multiple of 4 when normalized.
        compact = "".join(text.split())
        if len(compact) % 4 != 0:
            return None
        if not _B64_RE.match(compact):
            return None
        return compact

    def applicable(self, artifact: Artifact) -> Evidence | None:
        blob = self._candidate(artifact)
        if blob is None:
            return None
        try:
            raw = base64.b64decode(blob, validate=True)
        except Exception:
            return None
        # UTF-16LE test — every other byte should be NUL for ASCII text.
        if len(raw) < 4 or len(raw) % 2 != 0:
            return None
        try:
            decoded = raw.decode("utf-16-le")
        except UnicodeDecodeError:
            return None
        if printable_ratio(decoded) < 0.90:
            return None
        return Evidence(
            source=f"rte.{self.NAME}",
            observation=f"base64 blob of {len(blob)} chars",
            confidence=95,
            rationale=(
                "Input is a well-formed base64 blob whose bytes decode "
                "as printable UTF-16LE — the canonical Windows "
                "-EncodedCommand shape."
            ),
            meta={"blob_length": len(blob), "byte_length": len(raw)},
        )

    def apply(self, artifact: Artifact) -> tuple[str, list[Evidence]]:
        blob = self._candidate(artifact)
        assert blob is not None, "apply() called without applicable()==Evidence"
        raw = base64.b64decode(blob, validate=True)
        decoded = raw.decode("utf-16-le")
        ev = Evidence(
            source=f"rte.{self.NAME}",
            observation=decoded[:120],
            confidence=95,
            rationale=(
                "base64 → UTF-16LE decode produced printable PowerShell "
                "text. Reclassification will re-run Input Understanding "
                "against the plaintext."
            ),
            meta={
                "in_len":  len(artifact.content),
                "out_len": len(decoded),
                "encoding": "utf-16-le",
            },
        )
        return decoded, [ev]


TRANSFORMATION = Base64Utf16LeTransformation()
