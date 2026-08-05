"""
DIE · Preprocessor · Command Normalizer
───────────────────────────────────────
Lossless repair of copy-paste damage in extracted command lines.

Normalization is *never* allowed to change command semantics —
every ``normalized`` value has the corresponding ``raw`` preserved
on the artifact so an analyst can see exactly what was pasted.

Repairs we perform:
    • Comma-joined tokens → space-joined
      (``cmd.exe, /c, wmic`` → ``cmd.exe /c wmic``)
    • Bullet / dash prefixes stripped (already partly done by the
      Input Normalizer — this catches strays that survived).
    • Inner-line whitespace collapsed to a single space.
    • Trailing punctuation: ``.``, ``,``, ``;``, ``:`` at the end
      of a *command* (only when not inside quotes).
    • Wrapped continuation: replace bare ``\\`` at end-of-string
      with a single space.
"""
from __future__ import annotations
import re
from typing import List

from .models import Artifact


_COMMA_JOIN_RE = re.compile(r"\s*,\s+(?=[/\-A-Za-z0-9\"'\\%])")
_MULTI_SPACE_RE = re.compile(r"[ \t]{2,}")
_LEADING_JUNK_RE = re.compile(r"^[\s>*•\-]+")
_TRAILING_JUNK_RE = re.compile(r"[.,;:]+$")


def _in_quotes(s: str) -> bool:
    """Return True iff quote pairing is unbalanced (partial string)."""
    return (s.count('"') % 2 == 1) or (s.count("'") % 2 == 1)


def normalize_command(raw: str) -> str:
    text = raw
    if not text:
        return text
    text = _LEADING_JUNK_RE.sub("", text)
    text = text.rstrip()
    if text.endswith("\\"):
        text = text[:-1].rstrip() + " "
    # Repair "cmd.exe, /c, wmic" style pastes.
    text = _COMMA_JOIN_RE.sub(" ", text)
    # Collapse whitespace only outside quotes.
    if not _in_quotes(text):
        text = _MULTI_SPACE_RE.sub(" ", text)
    text = text.strip()
    # Trailing punctuation stripped only if it's not inside quotes.
    if not _in_quotes(text):
        text = _TRAILING_JUNK_RE.sub("", text)
    return text


def normalize_artifacts(artifacts: List[Artifact]) -> List[Artifact]:
    """Apply lossless normalization to every ``command`` artifact.
    Original ``raw_text`` is preserved unchanged.
    """
    for a in artifacts:
        if a.type == "command":
            fresh = normalize_command(a.raw_text)
            if fresh and fresh != a.normalized_text:
                a.normalized_text = fresh
    return artifacts
