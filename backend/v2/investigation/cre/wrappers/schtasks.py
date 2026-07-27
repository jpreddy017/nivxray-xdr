"""schtasks — `schtasks /create ... /tr "<inner>" ...`."""
from __future__ import annotations

import re

from ..models import WrapperChainStep

_SCHTASKS_TR_RE = re.compile(
    r"""(?ix)
    ^\s*schtasks(?:\.exe)?\b
    (?=.*?/tr\s+)                                # /tr must be present
    .*?/tr\s+
    (?P<q>['"])(?P<inner>.*?)(?P=q)
    """,
    re.DOTALL,
)


class SchtasksWrapper:
    NAME = "schtasks"

    def match(self, cmdline: str) -> bool:
        low = cmdline.lstrip().lower()
        return low.startswith("schtasks") and "/tr" in low

    def extract(self, cmdline: str) -> WrapperChainStep | None:
        m = _SCHTASKS_TR_RE.match(cmdline)
        if not m:
            return None
        inner = m.group("inner")
        return WrapperChainStep(
            wrapper=self.NAME,
            command="/tr",
            inner_command=inner,
            normalized_command=inner.strip(),
            evidence=(
                "Matched `schtasks … /tr \"…\"` — the /tr (Task-Run) "
                "argument is the exact command line the Task Scheduler "
                "will execute when the trigger fires. Extraction proved "
                "by schtasks.exe grammar."
            ),
            confidence=100,
        )


PARSER = SchtasksWrapper()
