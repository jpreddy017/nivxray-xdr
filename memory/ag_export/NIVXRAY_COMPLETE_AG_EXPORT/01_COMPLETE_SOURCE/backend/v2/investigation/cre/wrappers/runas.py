"""runas — `runas /user:<principal> "<inner>"`.

Uses the shared escape-aware quoted-string scanner so nested inner
commands (`runas /user:X "cmd /c powershell -C \\"…\\""`) survive
peeling without early truncation.
"""
from __future__ import annotations

import re

from ..models import WrapperChainStep
from ._quoting import extract_quoted, normalize_escaped_quotes

_RUNAS_HEAD_RE = re.compile(r"(?i)^\s*runas(?:\.exe)?\s+")


class RunasWrapper:
    NAME = "runas"

    def match(self, cmdline: str) -> bool:
        low = cmdline.lstrip().lower()
        return low.startswith("runas ") and ("/user:" in low or "/profile" in low)

    def extract(self, cmdline: str) -> WrapperChainStep | None:
        m = _RUNAS_HEAD_RE.match(cmdline)
        if not m:
            return None
        # Scan for the trailing quoted argument. runas takes all its
        # /switches first, then a single quoted command.
        tail = cmdline[m.end():]
        # Skip past /switch tokens
        idx = 0
        while idx < len(tail):
            if tail[idx] == '"':
                break
            # Consume a token (a /switch or a bare word) then whitespace
            while idx < len(tail) and not tail[idx].isspace():
                idx += 1
            while idx < len(tail) and tail[idx].isspace():
                idx += 1
        if idx >= len(tail) or tail[idx] != '"':
            return None
        got = extract_quoted(tail, idx)
        if not got:
            return None
        inner, _ = got
        normalized = normalize_escaped_quotes(inner).strip()
        return WrapperChainStep(
            wrapper=self.NAME,
            command="/user",
            inner_command=inner,
            normalized_command=normalized,
            evidence=(
                "Matched `runas /user:… \"…\"` — the trailing quoted "
                "argument is the command runas.exe will launch under "
                "the specified principal. Escape-aware quote scanner "
                "handles nested `\\\"…\\\"` sequences correctly."
            ),
            confidence=100,
        )


PARSER = RunasWrapper()
