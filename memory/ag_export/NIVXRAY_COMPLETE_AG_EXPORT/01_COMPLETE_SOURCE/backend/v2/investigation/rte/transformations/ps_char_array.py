"""ps_char_array · resolve numeric char-array joins to their literal string.

Delegates to :func:`v2.semantic.ps_deobfuscate._resolve_numeric_char_reconstruction`
which already handles hex / octal / binary / decimal / mixed-base
char reconstructions.
"""
from __future__ import annotations

import re

from ...evidence import Evidence
from ..models import Artifact


def _resolve():
    from ....semantic.ps_deobfuscate import _resolve_numeric_char_reconstruction
    return _resolve_numeric_char_reconstruction


# Cheap pre-filter: char-array joins ALWAYS contain the numeric
# pipeline or a `[char]` cast. Skip the expensive resolver when there
# is nothing that could plausibly match.
_MARKER_RE = re.compile(
    r"(?i)\[char(?:\[\])?\]|"
    r"convert::to(?:int16|int32|byte)|"
    r"-join\s*\(?\s*\(?\s*(?:0x[0-9a-f]+|[0-9]+)"
)


class PsCharArrayTransformation:
    NAME = "ps_char_array"

    def applicable(self, artifact: Artifact) -> Evidence | None:
        if not _MARKER_RE.search(artifact.content):
            return None
        _, changed = _resolve()(artifact.content, [])
        if not changed:
            return None
        return Evidence(
            source=f"rte.{self.NAME}",
            observation="PowerShell numeric char-array join detected",
            confidence=92,
            rationale=(
                "Input contains a resolvable numeric → char array "
                "reconstruction (hex / octal / binary / decimal). "
                "Folding it produces the literal script."
            ),
            meta={},
        )

    def apply(self, artifact: Artifact) -> tuple[str, list[Evidence]]:
        new_content, changed = _resolve()(artifact.content, [])
        assert changed
        ev = Evidence(
            source=f"rte.{self.NAME}",
            observation=new_content[:120],
            confidence=92,
            rationale="Reconstructed char-array literal(s) from numeric encoding.",
            meta={"in_len": len(artifact.content), "out_len": len(new_content)},
        )
        return new_content, [ev]


TRANSFORMATION = PsCharArrayTransformation()
