"""
UIL · Mixed-input splitter (2026-03-02)
────────────────────────────────────────
Real analysts rarely paste one thing.  A single paste often mixes:

    https://vendor/threat-report
    powershell -EncodedCommand SQBFAFgA...
    SHA256:  094fd325049b8a...
    C2: 185.220.101.4
    HKLM\\Software\\Run\\Payload

`split_mixed()` classifies each non-empty line into a typed fragment
so the downstream pipeline can route each one to its correct engine
without asking the analyst to sort them by hand.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List
import re

from .classifier import InputKind, classify


@dataclass
class TypedFragment:
    index: int
    kind:  InputKind
    text:  str
    line:  int = 0

    def to_dict(self) -> Dict:
        return {"index": self.index, "kind": self.kind.value,
                 "text":  self.text,  "line": self.line}


_RE_BLANK = re.compile(r"^\s*$")


def split_mixed(text: str) -> List[TypedFragment]:
    """Line-scoped fragment classifier.  Groups consecutive lines of
    the same kind into a single fragment (e.g. an IOC list stays as
    one fragment; a URL + a PowerShell command below it become two)."""
    out: List[TypedFragment] = []
    if not text or not text.strip():
        return out

    buffer: List[str] = []
    cur_kind: InputKind = InputKind.PLAIN_TEXT
    start_line: int    = 1

    def flush(end_line: int):
        if not buffer:
            return
        joined = "\n".join(buffer).strip()
        if joined:
            out.append(TypedFragment(
                index=len(out), kind=cur_kind, text=joined, line=start_line,
            ))
        buffer.clear()

    for lineno, raw in enumerate(text.splitlines(), start=1):
        if _RE_BLANK.match(raw):
            flush(lineno - 1)
            cur_kind = InputKind.PLAIN_TEXT
            start_line = lineno + 1
            continue

        kind = classify(raw.strip())
        # IOC list and CSV are usually multi-line — coalesce siblings.
        if kind in (InputKind.IOC_LIST, InputKind.CSV):
            kind = kind
        if not buffer:
            cur_kind = kind
            start_line = lineno
            buffer.append(raw)
            continue

        if kind == cur_kind or (
            cur_kind in (InputKind.IOC_LIST, InputKind.PLAIN_TEXT)
            and kind in (InputKind.IOC_LIST, InputKind.PLAIN_TEXT)
        ):
            buffer.append(raw)
        else:
            flush(lineno - 1)
            cur_kind = kind
            start_line = lineno
            buffer.append(raw)

    flush(lineno if 'lineno' in locals() else 1)
    return out
