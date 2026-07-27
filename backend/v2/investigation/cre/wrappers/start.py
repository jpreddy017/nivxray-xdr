"""start — `start "" "<inner>"` and `start "<inner>"`.

The `start` built-in accepts an optional window-title arg. When two
quoted args are present, the SECOND is the inner command. When one
quoted arg is present, IT is the inner command.
"""
from __future__ import annotations

import re

from ..models import WrapperChainStep

_START_TWO_ARG_RE = re.compile(
    r"""(?ix)
    ^\s*start\s+
    (?P<qt>['"])(?P<title>.*?)(?P=qt)\s+
    (?P<qc>['"])(?P<inner>.*)(?P=qc)\s*$
    """,
    re.DOTALL,
)
_START_ONE_ARG_RE = re.compile(
    r"""(?ix)
    ^\s*start\s+
    (?P<qc>['"])(?P<inner>.*)(?P=qc)\s*$
    """,
    re.DOTALL,
)


class StartWrapper:
    NAME = "start"

    def match(self, cmdline: str) -> bool:
        low = cmdline.lstrip().lower()
        return low.startswith("start ") or low.startswith("start\t")

    def extract(self, cmdline: str) -> WrapperChainStep | None:
        m = _START_TWO_ARG_RE.match(cmdline)
        title = ""
        if m:
            title = m.group("title")
            inner = m.group("inner")
            note = f"with window title \"{title}\""
        else:
            m = _START_ONE_ARG_RE.match(cmdline)
            if not m:
                return None
            inner = m.group("inner")
            note = "single-argument form"
        return WrapperChainStep(
            wrapper=self.NAME,
            command="start",
            inner_command=inner,
            normalized_command=inner.strip(),
            evidence=(
                f"Matched CMD built-in `start` {note} — the quoted "
                "inner argument is what will be launched in a new "
                "process window."
            ),
            confidence=95,
        )


PARSER = StartWrapper()
