"""ps_compression_stream · resolve ``[IO.Compression.*]`` calls that
decompress a literal base64 stream inside a PowerShell script.

Delegates to :func:`v2.semantic.ps_deobfuscate._resolve_compression_stream`
which recognises Gzip / Deflate / Brotli streams with a static
``[Convert]::FromBase64String`` argument.
"""
from __future__ import annotations

import re

from ...evidence import Evidence
from ..models import Artifact


def _resolve():
    from ....semantic.ps_deobfuscate import _resolve_compression_stream
    return _resolve_compression_stream


_MARKER_RE = re.compile(
    r"(?i)io\.compression\.(?:gzip|deflate|brotli)stream|"
    r"deflatestream|gzipstream|brotlistream",
)


class PsCompressionStreamTransformation:
    NAME = "ps_compression_stream"

    def applicable(self, artifact: Artifact) -> Evidence | None:
        if not _MARKER_RE.search(artifact.content):
            return None
        _, changed = _resolve()(artifact.content, [])
        if not changed:
            return None
        return Evidence(
            source=f"rte.{self.NAME}",
            observation="[IO.Compression.*Stream] literal detected",
            confidence=90,
            rationale=(
                "Script contains a `[IO.Compression.*Stream]` decompression "
                "of a literal base64 blob — deterministic decompression."
            ),
            meta={},
        )

    def apply(self, artifact: Artifact) -> tuple[str, list[Evidence]]:
        new_content, changed = _resolve()(artifact.content, [])
        assert changed
        ev = Evidence(
            source=f"rte.{self.NAME}",
            observation=new_content[:120],
            confidence=90,
            rationale="Decompressed the embedded static compression stream.",
            meta={"in_len": len(artifact.content), "out_len": len(new_content)},
        )
        return new_content, [ev]


TRANSFORMATION = PsCompressionStreamTransformation()
