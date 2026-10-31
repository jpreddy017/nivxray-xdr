"""base64_utf8 · decode a base64 blob whose bytes are printable UTF-8.

Fires when the input is a standalone base64 blob (not the UTF-16LE
Windows form). Lower confidence than :mod:`base64_utf16le` because
UTF-8 base64 is more common in benign contexts (config strings, CSS
data-URIs, etc.).
"""
from __future__ import annotations

import base64
import re

from ...evidence import Evidence
from ..models import Artifact
from ._util import printable_ratio, strip_quotes

_B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


class Base64Utf8Transformation:
    NAME = "base64_utf8"

    def _candidate(self, artifact: Artifact) -> str | None:
        text = strip_quotes(artifact.content).strip()
        if len(text) < 12:
            return None
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
        # Skip UTF-16LE candidates so the higher-priority plugin wins.
        if len(raw) >= 4 and raw[1::2].count(0) / max(1, len(raw) // 2) >= 0.7:
            return None
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError:
            return None
        if printable_ratio(decoded) < 0.90:
            return None
        return Evidence(
            source=f"rte.{self.NAME}",
            observation=f"base64 blob of {len(blob)} chars (utf-8 body)",
            confidence=85,
            rationale=(
                "Input is a well-formed base64 blob whose bytes decode "
                "as printable UTF-8 text."
            ),
            meta={"blob_length": len(blob), "byte_length": len(raw)},
        )

    def apply(self, artifact: Artifact) -> tuple[str, list[Evidence]]:
        blob = self._candidate(artifact)
        assert blob is not None
        raw = base64.b64decode(blob, validate=True)
        decoded = raw.decode("utf-8")
        ev = Evidence(
            source=f"rte.{self.NAME}",
            observation=decoded[:120],
            confidence=85,
            rationale="base64 → UTF-8 decode produced printable text.",
            meta={"in_len": len(artifact.content), "out_len": len(decoded)},
        )
        return decoded, [ev]


TRANSFORMATION = Base64Utf8Transformation()
