"""start — `start "" "<inner>"` and `start "<inner>"`.

Uses the shared escape-aware quoted-string scanner so nested wrappers
that carry `\\"…\\"` escapes are parsed as a single argument.
"""
from __future__ import annotations

import re

from ..models import WrapperChainStep
from ._quoting import extract_quoted, normalize_escaped_quotes

_START_HEAD_RE = re.compile(r"(?i)^\s*start(?:\.exe)?\s+")


class StartWrapper:
    NAME = "start"

    def match(self, cmdline: str) -> bool:
        low = cmdline.lstrip().lower()
        return low.startswith("start ") or low.startswith("start\t")

    def extract(self, cmdline: str) -> WrapperChainStep | None:
        m = _START_HEAD_RE.match(cmdline)
        if not m:
            return None
        pos = m.end()
        # Try two-arg form first: "<title>" "<cmd>"
        while pos < len(cmdline) and cmdline[pos].isspace():
            pos += 1
        if pos >= len(cmdline) or cmdline[pos] != '"':
            return None
        title_ex = extract_quoted(cmdline, pos)
        if not title_ex:
            return None
        title_val, end_title = title_ex
        # Skip whitespace to next arg
        p2 = end_title
        while p2 < len(cmdline) and cmdline[p2].isspace():
            p2 += 1
        cmd_ex = None
        if p2 < len(cmdline) and cmdline[p2] == '"':
            cmd_ex = extract_quoted(cmdline, p2)
        if cmd_ex:
            inner, _ = cmd_ex
            note = f"with window title \"{title_val}\""
        else:
            # Single-arg form — title slot IS the command
            inner = title_val
            note = "single-argument form (title slot is the command)"
        normalized = normalize_escaped_quotes(inner).strip()
        return WrapperChainStep(
            wrapper=self.NAME,
            command="start",
            inner_command=inner,
            normalized_command=normalized,
            evidence=(
                f"Matched CMD built-in `start` {note} — the quoted "
                "inner argument is what will be launched in a new "
                "process window. Escape-aware quote scanner handles "
                "nested `\\\"…\\\"` sequences."
            ),
            confidence=95,
        )


PARSER = StartWrapper()
