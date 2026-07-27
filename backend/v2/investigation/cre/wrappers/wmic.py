"""WMIC wrapper — `wmic process call create CommandLine="<inner>"`."""
from __future__ import annotations

import re

from ..models import WrapperChainStep

_WMIC_CREATE_RE = re.compile(
    r"""(?ix)
    ^\s*wmic(?:\.exe)?\s+
    (?:/[^\s]+\s+)*                              # optional /switches
    process\s+                                   # 'process' verb
    (?:where\s+[^\s]+\s+)?                       # optional filter
    call\s+create\s+
    (?:CommandLine\s*=\s*)?                     # optional keyword
    (?P<q>['"])(?P<inner>.*)(?P=q)               # quoted inner cmdline
    """,
    re.DOTALL,
)


class WmicWrapper:
    NAME = "wmic"

    def match(self, cmdline: str) -> bool:
        return "wmic" in cmdline.lower() and "call create" in cmdline.lower()

    def extract(self, cmdline: str) -> WrapperChainStep | None:
        m = _WMIC_CREATE_RE.match(cmdline)
        if not m:
            return None
        inner = m.group("inner")
        return WrapperChainStep(
            wrapper=self.NAME,
            command="process call create",
            inner_command=inner,
            normalized_command=inner.strip(),
            evidence=(
                "Matched WMIC `process call create CommandLine=\"…\"` — "
                "the wrapper spawns the quoted inner command as a new "
                "process. Extraction is proved by WMIC's own grammar."
            ),
            confidence=100,
        )


PARSER = WmicWrapper()
