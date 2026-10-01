"""pcalua.exe — Program Compatibility Assistant LOLBAS wrapper.

Syntax: `pcalua.exe -a "<inner>" [-c "<args>"]` — pcalua launches the
`-a` target with the `-c` arguments appended, bypassing several EDR
process-tree heuristics. Well-documented LOLBAS technique.
"""
from __future__ import annotations

import re

from ..models import WrapperChainStep

_PCALUA_RE = re.compile(
    r"""(?ix)
    ^\s*pcalua(?:\.exe)?\s+
    (?:.*?\s+)?
    -a\s+(?P<q1>['"]?)(?P<target>[^'"\s]+)(?P=q1)
    (?:\s+-c\s+(?P<q2>['"])(?P<args>.*)(?P=q2))?
    """,
    re.DOTALL,
)


class PcaluaWrapper:
    NAME = "pcalua"

    def match(self, cmdline: str) -> bool:
        return "pcalua" in cmdline.lower() and "-a" in cmdline.lower()

    def extract(self, cmdline: str) -> WrapperChainStep | None:
        m = _PCALUA_RE.match(cmdline)
        if not m:
            return None
        target = m.group("target").strip()
        args = (m.group("args") or "").strip()
        inner = (target + (" " + args if args else "")).strip()
        return WrapperChainStep(
            wrapper=self.NAME,
            command="-a",
            inner_command=inner,
            normalized_command=inner,
            evidence=(
                "Matched `pcalua.exe -a <target> [-c <args>]` — Program "
                "Compatibility Assistant is being used as a launcher "
                "proxy (LOLBAS). The `-a` target is what pcalua will "
                "spawn; `-c` args are appended verbatim."
            ),
            confidence=100,
        )


PARSER = PcaluaWrapper()
