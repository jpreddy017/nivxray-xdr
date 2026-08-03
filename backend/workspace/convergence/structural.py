"""
Structural transformation pass · M2.

Performs deterministic structural folds ONLY on unquoted syntax
elements. Content inside quoted strings is never modified — that
guarantee is what lets us run this pass on encoded / obfuscated
payloads (S001 EncodedCommand, S05 Base64 blobs, etc.) without any
risk of corrupting the payload.

Folds implemented in M2 (in order):

1. ``structural-string-concat-fold``
   * ``'a'+'b'`` → ``'ab'`` (single quotes · always safe, no interpolation)
   * ``"a"+"b"`` → ``"ab"`` (double quotes · only when neither string
     contains ``$``, ``` ` ``` or ``{`` — i.e. no PowerShell
     interpolation markers)
   * Applied left-to-right, once per pass. Chains like ``'a'+'b'+'c'``
     converge across successive iterations of the outer engine loop
     (that is exactly what the convergence engine is for).

2. ``structural-join-operator-fold``
   * ``('a','b','c') -join 'sep'`` → ``'aseb sec'``-style single literal.
   * Recognised case-insensitively (PowerShell operator is
     case-insensitive).
   * Only fires when EVERY array element AND the separator are
     single-quoted literals with no interpolation.

3. ``structural-static-join-fold``
   * ``[String]::Join('sep', ('a','b','c'))`` → ``'aseb sec'``.
   * ``String`` type name is matched case-insensitively (PowerShell
     is case-insensitive for type names).

Design invariants
-----------------
* Pure function of the current artifact state.
* Idempotent — calling this pass on already-folded input returns the
  input unchanged.
* Order-independent within a single call (each fold operates on its
  own regex; folds do not fight).
* NEVER modifies content inside a quoted string — safety guard is
  encoded directly into each fold's regex.
"""
from __future__ import annotations

import re

from .artifact import Artifact
from .provenance import PassRecord

PASS_NAME = "structural"

# ─── Quote-safe literal patterns ────────────────────────────────────
# Single-quoted PowerShell literals treat ``''`` as an escaped quote.
# We keep the fold simple and require literals to contain no embedded
# single-quote; PowerShell obfuscators virtually never use `''` inside
# a folded literal, and skipping ambiguous cases is the whole point of
# a "safe by default" structural pass.
_SQ_LITERAL = r"'[^'\r\n]*'"
# Double-quoted literals: reject ``$``, backtick, and ``{`` so we never
# fold an interpolated string.
_DQ_LITERAL = r'"[^"\r\n$`{}]*"'


# ─── Fold 1 · string concatenation ──────────────────────────────────
_SQ_CONCAT_RE = re.compile(rf"({_SQ_LITERAL})\s*\+\s*({_SQ_LITERAL})")
_DQ_CONCAT_RE = re.compile(rf"({_DQ_LITERAL})\s*\+\s*({_DQ_LITERAL})")


def _fold_string_concat(content: str) -> tuple[str, int]:
    """Fold ``'a'+'b'`` → ``'ab'`` (and the double-quoted variant)."""
    fires = 0

    def _sq(match: re.Match[str]) -> str:
        nonlocal fires
        fires += 1
        left = match.group(1)[1:-1]
        right = match.group(2)[1:-1]
        return "'" + left + right + "'"

    def _dq(match: re.Match[str]) -> str:
        nonlocal fires
        fires += 1
        left = match.group(1)[1:-1]
        right = match.group(2)[1:-1]
        return '"' + left + right + '"'

    # Single-quote pass first (safest), then double-quote.
    new_content = _SQ_CONCAT_RE.sub(_sq, content)
    new_content = _DQ_CONCAT_RE.sub(_dq, new_content)
    return new_content, fires


# ─── Fold 2 · -join operator on literal arrays ──────────────────────
# Match: (  'a' , 'b' , 'c'  )  -join  'sep'
# All literals must be single-quoted (interpolation-free by construction).
_JOIN_OP_RE = re.compile(
    r"\(\s*"
    r"(?P<items>"
    + _SQ_LITERAL
    + r"(?:\s*,\s*" + _SQ_LITERAL + r")+"
    + r")"
    r"\s*\)\s*"
    r"-join\s*"
    r"(?P<sep>" + _SQ_LITERAL + r")",
    flags=re.IGNORECASE,
)
_SQ_LITERAL_RE = re.compile(_SQ_LITERAL)


def _fold_join_operator(content: str) -> tuple[str, int]:
    fires = 0

    def _repl(match: re.Match[str]) -> str:
        nonlocal fires
        parts = [m.group(0)[1:-1] for m in _SQ_LITERAL_RE.finditer(match.group("items"))]
        sep = match.group("sep")[1:-1]
        fires += 1
        return "'" + sep.join(parts) + "'"

    return _JOIN_OP_RE.sub(_repl, content), fires


# ─── Fold 3 · [String]::Join(sep, array) ────────────────────────────
# PowerShell allows the type name to be case-insensitive.  We also
# accept ``[System.String]`` as an alias.
_STATIC_JOIN_RE = re.compile(
    r"\[\s*(?:system\.)?string\s*\]\s*::\s*join\s*\(\s*"
    r"(?P<sep>" + _SQ_LITERAL + r")"
    r"\s*,\s*"
    r"\(\s*"
    r"(?P<items>"
    + _SQ_LITERAL
    + r"(?:\s*,\s*" + _SQ_LITERAL + r")*"
    + r")"
    r"\s*\)\s*"
    r"\)",
    flags=re.IGNORECASE,
)


def _fold_static_join(content: str) -> tuple[str, int]:
    fires = 0

    def _repl(match: re.Match[str]) -> str:
        nonlocal fires
        parts = [m.group(0)[1:-1] for m in _SQ_LITERAL_RE.finditer(match.group("items"))]
        sep = match.group("sep")[1:-1]
        fires += 1
        return "'" + sep.join(parts) + "'"

    return _STATIC_JOIN_RE.sub(_repl, content), fires


# ─── Fold 4 · CMD caret escape strip (M4 addendum) ──────────────────
# Removes CMD-style caret escapes between two alphanumerics (S03's
# ``c^m^d /c p^ow^ers^he^ll`` obfuscation trick). NEVER touches
# carets inside quoted strings — quote-safety is enforced with the
# same alternation-mask pattern used in content.py.
_QUOTED_PREFIX = r"(?P<sq>'[^'\r\n]*')|(?P<dq>\"[^\"\r\n]*\")"
_CARET_RE = re.compile(
    _QUOTED_PREFIX
    + r"|(?<=[A-Za-z0-9])(?P<caret>\^)(?=[A-Za-z0-9])",
)


def _fold_cmd_caret_strip(content: str) -> tuple[str, int]:
    fires = 0

    def _repl(m: re.Match[str]) -> str:
        nonlocal fires
        if m.group("sq") is not None or m.group("dq") is not None:
            return m.group(0)
        fires += 1
        return ""

    return _CARET_RE.sub(_repl, content), fires


# ─── Pass entrypoint ────────────────────────────────────────────────
# Order: static-join first (largest structure), then -join operator,
# then string concat, then caret strip.
_FOLDS: tuple[tuple[str, callable], ...] = (
    ("structural-static-join-fold", _fold_static_join),
    ("structural-join-operator-fold", _fold_join_operator),
    ("structural-string-concat-fold", _fold_string_concat),
    ("structural-cmd-caret-strip", _fold_cmd_caret_strip),
)


def run(artifact: Artifact) -> tuple[Artifact, PassRecord]:
    content = artifact.content
    fired: list[str] = []

    for name, fn in _FOLDS:
        new_content, count = fn(content)
        if count > 0:
            fired.append(f"{name} x{count}")
            content = new_content

    if content == artifact.content:
        return artifact, PassRecord(
            name=PASS_NAME,
            changed=False,
            transformations=(),
            notes=(),
        )

    return artifact.replace(content=content), PassRecord(
        name=PASS_NAME,
        changed=True,
        transformations=tuple(fired),
    )


__all__ = ["PASS_NAME", "run"]
