"""ps_iex_peel · unwrap the outermost ``Invoke-Expression '<literal>'`` /
``iex(<literal>)`` when the argument is a static string literal.

Delegates to :func:`v2.semantic.ps_deobfuscate._resolve_nested_iex`.
Only applied when the argument is a static literal — dynamic
``iex $var`` calls are left alone so downstream execution-simulation
can reason about them.
"""
from __future__ import annotations

import re

from ...evidence import Evidence
from ..models import Artifact


def _resolve():
    from ....semantic.ps_deobfuscate import _resolve_nested_iex
    return _resolve_nested_iex


_MARKER_RE = re.compile(
    r"(?i)(?:invoke-expression|\biex\b)\s*[\(\s]*['\"]",
)


class PsIexPeelTransformation:
    NAME = "ps_iex_peel"

    def applicable(self, artifact: Artifact) -> Evidence | None:
        if not _MARKER_RE.search(artifact.content):
            return None
        _, changed = _resolve()(artifact.content, [])
        if not changed:
            return None
        return Evidence(
            source=f"rte.{self.NAME}",
            observation="Static Invoke-Expression / iex literal detected",
            confidence=90,
            rationale=(
                "Input contains an `Invoke-Expression '<literal>'` "
                "wrapper — peeling it exposes the wrapped script for "
                "further transformation."
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
            rationale="Peeled the static Invoke-Expression / iex literal wrapper.",
            meta={"in_len": len(artifact.content), "out_len": len(new_content)},
        )
        return new_content, [ev]


TRANSFORMATION = PsIexPeelTransformation()
