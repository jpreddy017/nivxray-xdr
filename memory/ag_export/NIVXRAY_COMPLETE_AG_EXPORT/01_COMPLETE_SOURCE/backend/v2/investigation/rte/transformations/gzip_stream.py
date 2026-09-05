"""gzip_stream · decompress a gzip stream surfaced as a hex artefact.

Fires when the previous transformation surfaced opaque bytes whose
magic header is ``1F 8B`` (gzip). The plugin expects the hex-form
produced by :mod:`base64_bytes` (``meta.output_kind == "hex_bytes"``)
or any content that starts with those two hex nibbles.
"""
from __future__ import annotations

import gzip
import re

from ...evidence import Evidence
from ..models import Artifact
from ._util import bytes_to_text

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


class GzipTransformation:
    NAME = "gzip_stream"

    def _bytes(self, artifact: Artifact) -> bytes | None:
        text = artifact.content.strip()
        if not _HEX_RE.match(text) or len(text) % 2 != 0:
            return None
        try:
            raw = bytes.fromhex(text)
        except ValueError:
            return None
        if not raw.startswith(b"\x1f\x8b"):
            return None
        return raw

    def applicable(self, artifact: Artifact) -> Evidence | None:
        raw = self._bytes(artifact)
        if raw is None:
            return None
        return Evidence(
            source=f"rte.{self.NAME}",
            observation=f"gzip magic 1F 8B · {len(raw)} bytes",
            confidence=95,
            rationale=(
                "Input is a hex-encoded byte stream beginning with the "
                "gzip magic header (1F 8B). Deterministic decompression."
            ),
            meta={"byte_length": len(raw)},
        )

    def apply(self, artifact: Artifact) -> tuple[str, list[Evidence]]:
        raw = self._bytes(artifact)
        assert raw is not None
        decompressed = gzip.decompress(raw)
        text = bytes_to_text(decompressed)
        if text is None:
            # Non-textual gzip output — surface as hex so the loop can
            # continue with another transformation (or stop cleanly).
            text = decompressed.hex()
            kind = "hex_bytes"
        else:
            kind = "text"
        ev = Evidence(
            source=f"rte.{self.NAME}",
            observation=text[:120] if kind == "text" else f"{len(decompressed)} decompressed bytes",
            confidence=95,
            rationale="gzip decompression succeeded.",
            meta={
                "in_bytes":    len(raw),
                "out_bytes":   len(decompressed),
                "output_kind": kind,
            },
        )
        return text, [ev]


TRANSFORMATION = GzipTransformation()
