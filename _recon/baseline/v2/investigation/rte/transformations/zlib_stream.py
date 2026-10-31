"""zlib_stream · decompress a zlib / DEFLATE stream surfaced as hex."""
from __future__ import annotations

import re
import zlib

from ...evidence import Evidence
from ..models import Artifact
from ._util import bytes_to_text

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_ZLIB_PREFIXES = (b"\x78\x01", b"\x78\x9c", b"\x78\xda", b"\x78\x5e")


class ZlibTransformation:
    NAME = "zlib_stream"

    def _bytes(self, artifact: Artifact) -> bytes | None:
        text = artifact.content.strip()
        if not _HEX_RE.match(text) or len(text) % 2 != 0:
            return None
        try:
            raw = bytes.fromhex(text)
        except ValueError:
            return None
        if not any(raw.startswith(p) for p in _ZLIB_PREFIXES):
            return None
        return raw

    def applicable(self, artifact: Artifact) -> Evidence | None:
        raw = self._bytes(artifact)
        if raw is None:
            return None
        return Evidence(
            source=f"rte.{self.NAME}",
            observation=f"zlib header {raw[:2].hex()} · {len(raw)} bytes",
            confidence=90,
            rationale="Input is a hex-encoded zlib/DEFLATE stream.",
            meta={"byte_length": len(raw)},
        )

    def apply(self, artifact: Artifact) -> tuple[str, list[Evidence]]:
        raw = self._bytes(artifact)
        assert raw is not None
        try:
            decompressed = zlib.decompress(raw)
        except zlib.error:
            # Should be caught by applicable(), but keep the plugin safe.
            return artifact.content, [
                Evidence(
                    source=f"rte.{self.NAME}",
                    observation="zlib decompression failed after header match",
                    confidence=0,
                    rationale="Header matched but stream body was corrupted.",
                    meta={},
                )
            ]
        text = bytes_to_text(decompressed)
        if text is None:
            text = decompressed.hex()
            kind = "hex_bytes"
        else:
            kind = "text"
        ev = Evidence(
            source=f"rte.{self.NAME}",
            observation=text[:120] if kind == "text" else f"{len(decompressed)} decompressed bytes",
            confidence=90,
            rationale="zlib/DEFLATE decompression succeeded.",
            meta={
                "in_bytes":    len(raw),
                "out_bytes":   len(decompressed),
                "output_kind": kind,
            },
        )
        return text, [ev]


TRANSFORMATION = ZlibTransformation()
