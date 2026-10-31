"""ps_format · resolve PowerShell ``"{0}{1}" -f 'a','b'`` format strings.

Thin adapter over :func:`v2.semantic.ps_deobfuscate._resolve_format` so
the RTE gets the same battle-tested string-format resolver without
duplicating logic.
"""
from __future__ import annotations

from ...evidence import Evidence
from ..models import Artifact

# Local import so this module has no import-time side effects on the
# semantic package (the semantic package can safely import RTE later).
def _resolve():
    from ....semantic.ps_deobfuscate import _resolve_format
    return _resolve_format


class PsFormatTransformation:
    NAME = "ps_format_string"

    def applicable(self, artifact: Artifact) -> Evidence | None:
        if "-f " not in artifact.content and "-f'" not in artifact.content \
                and '-f"' not in artifact.content:
            return None
        # Attempt a dry-run — the resolver reports ``changed=True`` when
        # at least one format expression was folded.
        _, changed = _resolve()(artifact.content, [])
        if not changed:
            return None
        return Evidence(
            source=f"rte.{self.NAME}",
            observation="PowerShell -f format expression detected",
            confidence=90,
            rationale=(
                "Input contains a resolvable `\"{0}{1}\" -f 'a','b'` "
                "expression — folding it exposes the literal string "
                "for further transformations."
            ),
            meta={},
        )

    def apply(self, artifact: Artifact) -> tuple[str, list[Evidence]]:
        new_content, changed = _resolve()(artifact.content, [])
        assert changed, "apply() called without applicable() firing"
        ev = Evidence(
            source=f"rte.{self.NAME}",
            observation=new_content[:120],
            confidence=90,
            rationale="Resolved -f format expression(s) to their literal form.",
            meta={"in_len": len(artifact.content), "out_len": len(new_content)},
        )
        return new_content, [ev]


TRANSFORMATION = PsFormatTransformation()
