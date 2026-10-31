"""WMIC wrapper — `wmic process call create CommandLine="<inner>"`.

Uses the shared escape-aware quoted-string scanner so nested wrappers
that contain `\\"…\\"` sequences (common when wmic wraps schtasks or
another wmic call) are parsed correctly instead of terminating on the
first escaped quote.
"""
from __future__ import annotations

import re

from ..models import WrapperChainStep
from ._quoting import find_quoted_after, normalize_escaped_quotes

_WMIC_HEAD_RE = re.compile(
    r"(?i)^\s*wmic(?:\.exe)?\s+.*?call\s+create\b"
)


class WmicWrapper:
    NAME = "wmic"

    def match(self, cmdline: str) -> bool:
        return "wmic" in cmdline.lower() and "call create" in cmdline.lower()

    def extract(self, cmdline: str) -> WrapperChainStep | None:
        if not _WMIC_HEAD_RE.match(cmdline):
            return None
        # Try `CommandLine="..."` first, then a bare trailing quoted arg.
        found = find_quoted_after(cmdline, r"CommandLine\s*=\s*")
        if not found:
            found = find_quoted_after(cmdline, r"call\s+create\s+")
        if not found:
            return None
        _flag, inner = found
        normalized = normalize_escaped_quotes(inner).strip()
        return WrapperChainStep(
            wrapper=self.NAME,
            command="process call create",
            inner_command=inner,
            normalized_command=normalized,
            evidence=(
                "Matched WMIC `process call create CommandLine=\"…\"` — "
                "the wrapper spawns the quoted inner command as a new "
                "process. Escape-aware quote scanner ensures nested "
                "`\\\"…\\\"` sequences are peeled as ONE argument."
            ),
            confidence=100,
        )


PARSER = WmicWrapper()
