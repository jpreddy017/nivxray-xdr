"""
DIE · Preprocessor · Command Normalizer
───────────────────────────────────────
Lossless repair of copy-paste damage in extracted command lines PLUS
deterministic decoding of common wrapper layers (PowerShell
``-EncodedCommand``) so downstream stages see the analyst-meaningful
form of the command instead of a base64 blob.

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
    • PowerShell ``-EncodedCommand``/``-e``/``-ec``/``-en`` — the
      base64 argument is decoded (base64 → UTF-16LE → text) and the
      recovered script is used as the normalized form.  The raw
      wrapper stays on ``raw_text`` for provenance.
"""
from __future__ import annotations
import base64
import binascii
import re
from typing import List, Optional

from .models import Artifact


_COMMA_JOIN_RE = re.compile(r"\s*,\s+(?=[/\-A-Za-z0-9\"'\\%])")
_MULTI_SPACE_RE = re.compile(r"[ \t]{2,}")
_LEADING_JUNK_RE = re.compile(r"^[\s>*•\-]+")
_TRAILING_JUNK_RE = re.compile(r"[.,;:]+$")

# Match ``-EncodedCommand``, ``-e``, ``-ec``, ``-en`` (case-insensitive)
# followed by a base64 argument (optionally quoted).  We accept every
# PowerShell short form because attackers use them interchangeably.
_ENC_CMD_RE = re.compile(
    r"(?i)"
    r"-(?:e(?:c|n|nc(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:nd?)?)?)?)?)?)?)?)?)?)?)?)"
    r"\s+"
    r"[\"']?"
    r"(?P<b64>[A-Za-z0-9+/=]{16,})"
    r"[\"']?",
)


def _decode_encoded_command(text: str) -> Optional[str]:
    """Return the decoded PowerShell script if ``text`` carries an
    ``-EncodedCommand`` base64 payload — else ``None``.

    Deterministic: same input → same output.  No LLM, no heuristics
    beyond the well-documented PowerShell wire format:
        base64 → UTF-16LE → PowerShell script.
    """
    if not text:
        return None
    m = _ENC_CMD_RE.search(text)
    if not m:
        return None
    b64 = m.group("b64")
    # Base64 length must be a multiple of 4 after padding — pad if
    # the analyst pasted an unterminated blob.
    padded = b64 + "=" * (-len(b64) % 4)
    try:
        raw = base64.b64decode(padded, validate=False)
    except (binascii.Error, ValueError):
        return None
    if not raw:
        return None
    # PowerShell -EncodedCommand is always UTF-16LE.  Fall back to
    # utf-8 only if the UTF-16LE decode yields non-printable garbage
    # (analysts sometimes wrap non-standard payloads under -e).
    try:
        decoded = raw.decode("utf-16-le", errors="strict")
    except UnicodeDecodeError:
        try:
            decoded = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return None
    # Very short decodes (< 4 chars) are almost always wrong — reject.
    if len(decoded.strip()) < 4:
        return None
    # PowerShell scripts are effectively 100% ASCII printable.  Require
    # ≥ 85% ASCII-printable (plus \r\n\t) so we don't surface random
    # UTF-16 unicode noise as "the normalized command".
    def _ascii_printable(c: str) -> bool:
        o = ord(c)
        return (32 <= o < 127) or o in (9, 10, 13)
    ascii_ok = sum(1 for c in decoded if _ascii_printable(c))
    if ascii_ok / max(1, len(decoded)) < 0.85:
        return None
    return decoded.strip()


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
    # Deterministically peel PowerShell -EncodedCommand payloads.
    # When present, the decoded script IS the normalized form the
    # analyst wants to read — the base64 wrapper stays on raw_text.
    decoded = _decode_encoded_command(text)
    if decoded:
        return decoded
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
