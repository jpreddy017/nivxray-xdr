"""ps_indirect_compression_stream · variable-bound base64 → compression.

v1.5.0 Decoder Convergence · P0 gap identified 2026-07-28.

Handles the classic Windows evasion idiom where the base64 literal is
bound to a variable via ``New-Object IO.MemoryStream`` **before** the
compression stream reads it:

    $s = New-Object IO.MemoryStream(,[Convert]::FromBase64String("H4sI..."));
    IEX (New-Object IO.StreamReader(
           New-Object IO.Compression.GzipStream(
             $s, [IO.Compression.CompressionMode]::Decompress))).ReadToEnd();

The strict-order :mod:`ps_compression_stream` cannot match this shape
because its regex assumes ``GzipStream`` appears BEFORE
``FromBase64String`` in source order. This plugin closes that gap by
delegating to :func:`v2.semantic.ps_deobfuscate._resolve_variable_bound_compression_stream`
which links assignments and consumers by variable name.

Deterministic — only fires when the base64 argument is a LITERAL,
the variable name matches exactly, and decompression succeeds.
"""
from __future__ import annotations

import re

from ...evidence import Evidence
from ..models import Artifact


def _resolve():
    from ....semantic.ps_deobfuscate import (
        _resolve_variable_bound_compression_stream,
    )
    return _resolve_variable_bound_compression_stream


# Two markers must BOTH appear in the artefact for this plugin to even
# consider firing. This keeps ``applicable()`` cheap on non-matching
# artefacts (constant-time regex scan of the whole text).
_ASSIGN_MARKER_RE = re.compile(r"(?i)convert\]?\s*::\s*frombase64string")
_CONSUMER_MARKER_RE = re.compile(
    r"(?i)io\.compression\.(?:gzip|deflate|brotli)stream|"
    r"deflatestream|gzipstream|brotlistream",
)


class PsIndirectCompressionStreamTransformation:
    NAME = "ps_indirect_compression_stream"

    def _try(self, artifact: Artifact) -> tuple[str, bool] | None:
        # Cheap prefilter — both idioms must be present or we can't
        # possibly match.
        if not _ASSIGN_MARKER_RE.search(artifact.content):
            return None
        if not _CONSUMER_MARKER_RE.search(artifact.content):
            return None
        new_txt, changed = _resolve()(artifact.content, [])
        if not changed:
            return None
        return new_txt, True

    def applicable(self, artifact: Artifact) -> Evidence | None:
        result = self._try(artifact)
        if result is None:
            return None
        return Evidence(
            source=f"rte.{self.NAME}",
            observation="variable-bound base64 → compression stream detected",
            confidence=94,
            rationale=(
                "PowerShell script binds a `[Convert]::FromBase64String(\"…\")` "
                "literal to a variable and later consumes that variable inside "
                "`[IO.Compression.*Stream]($var, …::Decompress)`. Deterministic "
                "decompression."
            ),
            meta={},
        )

    def apply(self, artifact: Artifact) -> tuple[str, list[Evidence]]:
        result = self._try(artifact)
        assert result is not None
        new_content, _ = result
        ev = Evidence(
            source=f"rte.{self.NAME}",
            observation=new_content[:120],
            confidence=94,
            rationale=(
                "Linked the variable-bound base64 assignment to its downstream "
                "compression consumer and inlined the decompressed plaintext."
            ),
            meta={
                "in_len":  len(artifact.content),
                "out_len": len(new_content),
            },
        )
        return new_content, [ev]


TRANSFORMATION = PsIndirectCompressionStreamTransformation()
