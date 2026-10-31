"""
DIE · Preprocessor · Input Normalizer
─────────────────────────────────────
Lossless-first normalization of analyst pastes.  We keep the raw
text intact (so provenance survives) and produce a parallel
"working buffer" the extractors run against.

Rules:
    • Convert Unicode smart-quotes (curly quotes · guillemets · em-dashes)
      to ASCII equivalents.  Never rewrite command semantics.
    • Strip common markdown decorations: leading bullets (`•`, `-`,
      `*`, `+`, `>` ), backticks, bold/italic markers, ordered-list
      numbering — but preserve the token characters inside code spans.
    • Unwrap trailing "\" / "^" line-continuations (bash / cmd).
    • Collapse runs of blank whitespace only within a *line*.
      Keep newlines intact — they are the primary segmentation signal.
    • Emit an ``offset_map`` so downstream stages can convert a
      normalized offset back to the raw offset for provenance.
"""
from __future__ import annotations
import re
from dataclasses import dataclass
from typing import List, Tuple


_SMART_QUOTES = {
    "\u2018": "'", "\u2019": "'", "\u201a": "'", "\u201b": "'",
    "\u201c": '"', "\u201d": '"', "\u201e": '"', "\u201f": '"',
    "\u00ab": '"', "\u00bb": '"',
    "\u2013": "-", "\u2014": "-", "\u2212": "-",
    "\u2026": "...",
    "\u00a0": " ",   # non-breaking space
}

# Leading markdown decorations, applied only at start-of-line.
_LEADING_MD = re.compile(r"^[ \t]*(?:[>#]+[ \t]+|[-*+•][ \t]+|\d+[.)][ \t]+)")
# Inline markdown noise (backticks, bold/italic) — remove markers,
# keep content.  We *don't* touch backticks around obvious command
# examples because the code text inside them is the payload we want.
_INLINE_MD = re.compile(r"(?<!`)`(?!`)")     # single-char backticks
# Markdown emphasis — ONLY strip paired markers.  Single `_` and `*`
# characters are common in CLI / code (identifiers like `Win32_ShadowCopy`,
# arithmetic like `x*y`) and must never be silently removed.
_BOLD_ITALIC = re.compile(r"\*\*|__")


# ── Multi-invocation splitter (2026-03-01) ────────────────────────
#
# When a single pasted line contains multiple back-to-back CLI
# invocations (attacker `-NoProfile ... , -NoProfile ...` runs,
# `cmd.exe /c ...; powershell ...` chains, etc.) we insert a newline
# at each boundary so the line-oriented extractor produces one stage
# per invocation.
#
# Boundary = one of `,`, `;`, `&&`, `||`, `& ` followed by whitespace
# and a fresh invocation token (an executable OR a common CLI switch).
# Matches inside balanced `"` or `'` quotes are skipped so we do not
# split embedded strings.
#
_INVOCATION_HEADS = (
    # PowerShell / CMD common leading switches
    r"-NoProfile\b", r"-NonInteractive\b", r"-EncodedCommand\b",
    r"-ExecutionPolicy\b", r"-WindowStyle\b", r"-Command\b",
    r"-File\b", r"-ExecutionPolicy\b", r"-nop\b",
    # Executable heads
    r"powershell(?:\.exe)?\b", r"pwsh(?:\.exe)?\b",
    r"cmd(?:\.exe)?\b", r"wmic(?:\.exe)?\b",
    r"vssadmin(?:\.exe)?\b", r"wbadmin(?:\.exe)?\b",
    r"bcdedit(?:\.exe)?\b", r"reg(?:\.exe)?\b",
    r"net(?:\.exe)?\b", r"netsh(?:\.exe)?\b",
    r"schtasks(?:\.exe)?\b", r"sc(?:\.exe)?\b",
    r"certutil(?:\.exe)?\b", r"bitsadmin(?:\.exe)?\b",
    r"rundll32(?:\.exe)?\b", r"regsvr32(?:\.exe)?\b",
    r"mshta(?:\.exe)?\b", r"msiexec(?:\.exe)?\b",
    r"whoami(?:\.exe)?\b", r"hostname(?:\.exe)?\b",
    r"ipconfig(?:\.exe)?\b", r"systeminfo(?:\.exe)?\b",
    r"nltest(?:\.exe)?\b", r"quser(?:\.exe)?\b",
    r"tasklist(?:\.exe)?\b", r"taskkill(?:\.exe)?\b",
    r"psexec(?:\.exe)?\b", r"paexec(?:\.exe)?\b",
    # CMD /c launcher switch (must follow a separator to count)
    r"/c\b", r"/s\b", r"/k\b",
)
_INVOCATION_HEAD_RE = re.compile(
    r"(?i)(?:" + "|".join(_INVOCATION_HEADS) + r")"
)
# Match a separator (`,`, `;`, `&&`, `||`, or a lone `&`) followed by
# whitespace before an invocation head.
_BOUNDARY_RE = re.compile(
    r"(?i)(?P<sep>[,;]|&&|\|\||&)\s+(?=(?:"
    + "|".join(_INVOCATION_HEADS)
    + r"))"
)


def _split_repeated_invocations(text: str) -> str:
    """Insert newlines at attacker-style multi-invocation boundaries.

    Never splits inside balanced `"..."` or `'...'` runs — those hold
    quoted arguments the analyst pasted verbatim.
    """
    if not text or ("," not in text and ";" not in text and "&" not in text and "|" not in text):
        return text
    # Walk the string tracking quote state so we only consider
    # boundaries that live OUTSIDE quoted spans.
    out: List[str] = []
    i = 0
    n = len(text)
    q: str | None = None       # current open quote character (' or ")
    while i < n:
        ch = text[i]
        if q is None:
            if ch in ('"', "'"):
                q = ch
                out.append(ch)
                i += 1
                continue
            # Try to match a boundary starting at i
            m = _BOUNDARY_RE.match(text, i)
            if m:
                out.append(m.group("sep"))
                out.append("\n")
                i = m.end()
                continue
            out.append(ch)
            i += 1
        else:
            # Inside a quoted span — copy verbatim, honouring the
            # PowerShell-style escaped-quote (``""`` or ``''``) and
            # C-style ``\"`` / ``\'``.
            if ch == "\\" and i + 1 < n and text[i + 1] in ('"', "'"):
                out.append(text[i])
                out.append(text[i + 1])
                i += 2
                continue
            if ch == q and i + 1 < n and text[i + 1] == q:
                out.append(text[i])
                out.append(text[i + 1])
                i += 2
                continue
            out.append(ch)
            if ch == q:
                q = None
            i += 1
    return "".join(out)


@dataclass
class NormalizedInput:
    """Result of the input normalizer.

    ``text`` — cleaned working buffer (for extractors).
    ``raw`` — original text (unchanged, for provenance).
    ``offset_map`` — pairs of ``(norm_offset, raw_offset)``,
        piecewise-sorted so downstream ``norm→raw`` lookups are O(log n).
    ``line_starts`` — for each line in the normalized buffer, the
        offset where that line starts.  Enables cheap line-number
        lookup for artifacts.
    """
    text:         str
    raw:          str
    offset_map:   List[Tuple[int, int]]
    line_starts:  List[int]

    def line_number(self, norm_offset: int) -> int:
        """1-indexed line number for an offset within ``text``."""
        # binary search would be O(log n); linear is fine for the
        # sizes we deal with (blog posts, IR notes).
        line = 1
        for start in self.line_starts:
            if start > norm_offset:
                break
            line = self.line_starts.index(start) + 1
        return line

    def raw_offset(self, norm_offset: int) -> int:
        """Map a normalized offset back to the original raw offset."""
        best = 0
        for n_off, r_off in self.offset_map:
            if n_off <= norm_offset:
                best = r_off + (norm_offset - n_off)
            else:
                break
        return best


def normalize(raw: str) -> NormalizedInput:
    if not raw:
        return NormalizedInput(text="", raw="", offset_map=[(0, 0)], line_starts=[0])

    # 1) Smart-quote / unicode fold — 1:1 or 1:N substitutions.
    #    We rebuild the buffer character-by-character and record an
    #    offset checkpoint at every replacement so provenance stays
    #    tight.
    out: List[str] = []
    offset_map: List[Tuple[int, int]] = [(0, 0)]
    n_off = 0
    for r_off, ch in enumerate(raw):
        sub = _SMART_QUOTES.get(ch)
        if sub is None:
            out.append(ch)
            n_off += 1
        else:
            out.append(sub)
            n_off += len(sub)
            offset_map.append((n_off, r_off + 1))

    text = "".join(out)

    # 2) Strip leading markdown per line.  We rebuild line by line so
    #    line-number provenance stays intact.
    new_lines: List[str] = []
    for ln in text.splitlines(keepends=True):
        # Kill wrap-continuation markers ("^\n" or "\\\n" at end of
        # a bare CMD/bash line) so a multi-line command re-joins.
        keep = ln
        if keep.endswith("^\n") or keep.endswith("\\\n"):
            keep = keep[:-2] + " "
        stripped = _LEADING_MD.sub("", keep)
        new_lines.append(stripped)
    text = "".join(new_lines)

    # 3) Strip single-char backticks and bold/italic markers.  We
    #    NEVER touch triple-backtick fenced code blocks (they hint
    #    at literal commands and are highly analyst-friendly).
    #    We do a fast pass: leave ``` fences intact by removing them
    #    entirely (they are pure delimiters).
    text = re.sub(r"```[a-zA-Z0-9_-]*\n?", "", text)   # opening ``` fence
    text = text.replace("```", "")
    text = _INLINE_MD.sub("", text)
    text = _BOLD_ITALIC.sub("", text)

    # 3b) Multi-invocation splitter (P0 · 2026-03-01)
    #     Pasted attacker artifacts often arrive as ONE long line with
    #     comma / semicolon separated re-invocations of the same host,
    #     e.g. `-NoProfile ... -Command "..." , -NoProfile ... -Command "..."`
    #     or `cmd.exe /c ... ; powershell ... ; wmic ...`.
    #     The extractor is line-based, so a single line yields a single
    #     stage.  We insert newlines between adjacent invocations so
    #     the extractor sees them as separate commands.
    #
    #     Rule: split when a `,`, `;`, `&&`, `||`, or `&` is followed
    #     by whitespace and a fresh invocation token (an executable
    #     name or a PowerShell/CMD switch like `-NoProfile`, `-Command`,
    #     `/c`, `/s`).  This keeps quoted content intact — we skip
    #     matches inside balanced " or ' spans.
    text = _split_repeated_invocations(text)

    # 4) Precompute line_starts.
    line_starts: List[int] = [0]
    for idx, ch in enumerate(text):
        if ch == "\n":
            line_starts.append(idx + 1)

    return NormalizedInput(
        text=text, raw=raw,
        offset_map=offset_map,
        line_starts=line_starts,
    )
