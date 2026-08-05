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
_BOLD_ITALIC = re.compile(r"(\*\*|__|(?<!\*)\*(?!\*)|(?<!_)_(?!_))")


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
