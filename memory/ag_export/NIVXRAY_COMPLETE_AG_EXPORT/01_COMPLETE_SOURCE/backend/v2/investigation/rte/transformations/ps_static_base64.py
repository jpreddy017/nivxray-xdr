"""ps_static_base64 · resolve ``[Convert]::FromBase64String("<blob>")``
static calls embedded inside a larger PowerShell script.

Delegates to :func:`v2.semantic.ps_deobfuscate._resolve_static_base64`
which handles both the raw form and the composite
``[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(…))``.
"""
from __future__ import annotations

import re

from ...evidence import Evidence
from ..models import Artifact


def _resolvers():
    from ....semantic.ps_deobfuscate import (
        _resolve_static_base64,
        _resolve_utf16le_base64,
    )
    return _resolve_static_base64, _resolve_utf16le_base64


_MARKER_RE = re.compile(r"(?i)convert\]?\s*::\s*frombase64string")


class PsStaticBase64Transformation:
    NAME = "ps_static_base64"

    def _try(self, artifact: Artifact) -> tuple[str, bool] | None:
        if not _MARKER_RE.search(artifact.content):
            return None
        r_static, r_utf16le = _resolvers()
        # Try UTF-16LE-composite first (higher-fidelity match), then
        # fall back to the plain form.
        new_txt, changed = r_utf16le(artifact.content, [])
        if changed:
            return new_txt, True
        new_txt, changed = r_static(artifact.content, [])
        if changed:
            return new_txt, True
        return None

    def applicable(self, artifact: Artifact) -> Evidence | None:
        result = self._try(artifact)
        if result is None:
            return None
        return Evidence(
            source=f"rte.{self.NAME}",
            observation="[Convert]::FromBase64String('<literal>') detected",
            confidence=93,
            rationale=(
                "PowerShell script contains a static "
                "`[Convert]::FromBase64String(\"…\")` call — folding it "
                "reveals the literal base64-decoded string."
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
            confidence=93,
            rationale="Folded the embedded static base64 call to its literal.",
            meta={"in_len": len(artifact.content), "out_len": len(new_content)},
        )
        return new_content, [ev]


TRANSFORMATION = PsStaticBase64Transformation()
