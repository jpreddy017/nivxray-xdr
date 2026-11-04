"""Shared quoted-string extraction for wrapper parsers.

Every Windows wrapper that carries an inner command inside a quoted
argument uses the same escape convention: the shell that emits the
outer command doubles / backslashes the inner quotes so the OS parses
the value as ONE argument. When we peel the OUTER layer we must:
    1. Locate the matching close-quote while respecting escape sequences
       (`\"` and `""` inside a double-quoted string do NOT terminate it).
    2. Unescape ONE layer of quoting so the next wrapper parser sees
       the raw form (e.g. `\"…\"` after our peel becomes `"…"` in the
       normalized command — the input the NEXT layer will match).

This module is used by every wrapper parser so quoting behavior stays
consistent as new wrappers are added.
"""
from __future__ import annotations

import re


def extract_quoted(text: str, start: int) -> tuple[str, int] | None:
    """Extract an escape-aware double-quoted string starting at
    `text[start]` (which MUST be `"`). Returns (raw_inner, end_index)
    where `end_index` points to the char AFTER the closing quote.

    Recognises escape sequences ONLY for the purpose of finding the
    matching close-quote — the returned inner value is the RAW text
    between the quotes with escape sequences INTACT. This preserves
    one full layer of escaping so the caller can either:
        · hand the raw text to the next wrapper parser as-is (deep
          nesting uses raw form so each layer parses with its own
          escape convention), or
        · call `normalize_escaped_quotes(raw)` to strip exactly ONE
          layer of escaping when producing `normalized_command`.

    Returns None on unterminated input rather than raising, so the
    caller can gracefully fall through to another parser.
    """
    if start >= len(text) or text[start] != '"':
        return None
    i = start + 1
    inner_start = i
    while i < len(text):
        ch = text[i]
        if ch == "\\" and i + 1 < len(text) and text[i + 1] in ('"', '\\'):
            # Escape sequence — skip both chars, keep them in the raw
            # inner value.
            i += 2
            continue
        if ch == '"':
            if i + 1 < len(text) and text[i + 1] == '"':
                # SQL-style doubled quote — content, not terminator.
                i += 2
                continue
            # Real close-quote
            return text[inner_start:i], i + 1
        i += 1
    return None   # unterminated


def normalize_escaped_quotes(text: str) -> str:
    """Strip one layer of Windows shell escape sequences. Idempotent
    on already-unescaped input. Used by the parsers to fill
    `WrapperChainStep.normalized_command` so the next wrapper parser
    sees the raw form.

    Handles the two conventions Windows shells use inside a quoted
    argument:
        · `\\\\`  →  `\\`   (backslash-escaped backslash)
        · `\\"`   →  `"`    (backslash-escaped double quote)
        · `""`    →  `"`    (doubled double quote — SQL-style)
    Applied strictly left-to-right so that `\\\\"` becomes `\\"`
    (one literal backslash + escaped quote) rather than being
    prematurely re-scanned."""
    out: list[str] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\\" and i + 1 < len(text):
            nxt = text[i + 1]
            if nxt == "\\":
                out.append("\\")
                i += 2
                continue
            if nxt == '"':
                out.append('"')
                i += 2
                continue
        if ch == '"' and i + 1 < len(text) and text[i + 1] == '"':
            out.append('"')
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


# ── Argument locator ─────────────────────────────────────────────
# Find the FIRST occurrence of `<flag>` followed by a quoted string,
# honoring the escape-aware quote scanner. Used by wmic (CommandLine=),
# schtasks (/tr), runas trailing arg, etc.
def find_quoted_after(text: str, flag_pattern: str) -> tuple[str, str] | None:
    """Locate the first occurrence of a token matching `flag_pattern`
    (a raw regex — e.g. `r"/tr\\s+"`, `r"CommandLine\\s*=\\s*"`) and
    return `(matched_flag_text, quoted_inner_value)` where the quoted
    value is extracted with escape awareness. Returns None on no match
    or unterminated quoting."""
    m = re.search(flag_pattern, text, re.IGNORECASE)
    if not m:
        return None
    after = m.end()
    # Skip whitespace between the flag and the opening quote
    while after < len(text) and text[after].isspace():
        after += 1
    if after >= len(text) or text[after] != '"':
        return None
    got = extract_quoted(text, after)
    if not got:
        return None
    inner, _ = got
    return m.group(0), inner
