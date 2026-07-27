"""runas — `runas /user:<principal> "<inner>"`."""
from __future__ import annotations

import re

from ..models import WrapperChainStep

_RUNAS_RE = re.compile(
    r"""(?ix)
    ^\s*runas(?:\.exe)?\s+
    (?:/[^\s]+\s+)+                              # at least one /switch
    (?P<q>['"])(?P<inner>.*)(?P=q)\s*$
    """,
    re.DOTALL,
)


class RunasWrapper:
    NAME = "runas"

    def match(self, cmdline: str) -> bool:
        low = cmdline.lstrip().lower()
        return low.startswith("runas ") and ("/user:" in low or "/profile" in low)

    def extract(self, cmdline: str) -> WrapperChainStep | None:
        m = _RUNAS_RE.match(cmdline)
        if not m:
            return None
        inner = m.group("inner")
        return WrapperChainStep(
            wrapper=self.NAME,
            command="/user",
            inner_command=inner,
            normalized_command=inner.strip(),
            evidence=(
                "Matched `runas /user:… \"…\"` — the trailing quoted "
                "argument is the command runas.exe will launch under the "
                "specified principal. Extraction proved by runas grammar."
            ),
            confidence=100,
        )


PARSER = RunasWrapper()
