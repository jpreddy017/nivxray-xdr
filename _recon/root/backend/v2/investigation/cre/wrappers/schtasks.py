"""schtasks — `schtasks /create ... /tr "<inner>" ...`.

Uses the shared escape-aware quoted-string scanner so `/tr` values that
contain nested `\\"…\\"` sequences (common when the task runs a
powershell -Command "…" line) are captured in full instead of being
truncated at the first escaped quote.
"""
from __future__ import annotations

import re

from ..models import WrapperChainStep
from ._quoting import find_quoted_after, normalize_escaped_quotes

_SCHTASKS_HEAD_RE = re.compile(r"(?i)^\s*schtasks(?:\.exe)?\b")


class SchtasksWrapper:
    NAME = "schtasks"

    def match(self, cmdline: str) -> bool:
        low = cmdline.lstrip().lower()
        return low.startswith("schtasks") and "/tr" in low

    def extract(self, cmdline: str) -> WrapperChainStep | None:
        if not _SCHTASKS_HEAD_RE.match(cmdline):
            return None
        found = find_quoted_after(cmdline, r"/tr\s+")
        if not found:
            return None
        _flag, inner = found
        normalized = normalize_escaped_quotes(inner).strip()
        return WrapperChainStep(
            wrapper=self.NAME,
            command="/tr",
            inner_command=inner,
            normalized_command=normalized,
            evidence=(
                "Matched `schtasks … /tr \"…\"` — the /tr (Task-Run) "
                "argument is the exact command line the Task Scheduler "
                "will execute when the trigger fires. Escape-aware "
                "quote scanner handles nested `\\\"…\\\"` sequences "
                "correctly."
            ),
            confidence=100,
        )


PARSER = SchtasksWrapper()
