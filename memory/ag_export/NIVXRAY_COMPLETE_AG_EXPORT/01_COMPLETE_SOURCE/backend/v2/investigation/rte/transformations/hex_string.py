"""hex_string · convert a long run of hex nibbles into printable text.

Fires only when the entire artefact is a hex string AND the decoded
bytes are predominantly printable text. Non-textual hex is handled by
the compression / binary transformations, not here.
"""
from __future__ import annotations

import re

from ...evidence import Evidence
from ..models import Artifact
from ._util import printable_ratio, strip_quotes

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


class HexStringTransformation:
    NAME = "hex_string"

    def _bytes(self, artifact: Artifact) -> bytes | None:
        text = strip_quotes(artifact.content).strip()
        # Strip an optional "0x" prefix on the outermost blob only.
        if text.lower().startswith("0x"):
            text = text[2:]
        if len(text) < 20 or len(text) % 2 != 0:
            return None
        if not _HEX_RE.match(text):
            return None
        try:
            return bytes.fromhex(text)
        except ValueError:
            return None

    def applicable(self, artifact: Artifact) -> Evidence | None:
        raw = self._bytes(artifact)
        if raw is None:
            return None
        try:
            candidate = raw.decode("utf-8")
        except UnicodeDecodeError:
            return None
        if printable_ratio(candidate) < 0.90:
            return None
        return Evidence(
            source=f"rte.{self.NAME}",
            observation=f"{len(raw)} bytes hex → printable text",
            confidence=80,
            rationale="Input is a hex-encoded byte string that decodes as UTF-8 text.",
            meta={"byte_length": len(raw)},
        )

    def apply(self, artifact: Artifact) -> tuple[str, list[Evidence]]:
        raw = self._bytes(artifact)
        assert raw is not None
        decoded = raw.decode("utf-8")
        ev = Evidence(
            source=f"rte.{self.NAME}",
            observation=decoded[:120],
            confidence=80,
            rationale="hex → UTF-8 decode produced printable text.",
            meta={"in_len": len(artifact.content), "out_len": len(decoded)},
        )
        return decoded, [ev]


TRANSFORMATION = HexStringTransformation()
