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


# ─── JavaScript split/reverse/join ──────────────────────────────────
# Matches `'STRING'.split('SEP').reverse().join('SEP2')` — one of the
# canonical JS obfuscation idioms used by GootLoader, SocGholish,
# ClearFake and phishing kits. Evaluates deterministically to the
# resulting single-quoted string literal so downstream decoder passes
# (atob, unicode-escape) can consume the reconstructed payload.
_JS_SRJ_RE = re.compile(
    r"""
    ('(?P<inner>[^'\r\n]*)')
    \s*\.\s*split\s*\(\s*
      '(?P<sep>[^'\r\n]*)'
    \s*\)
    \s*\.\s*reverse\s*\(\s*\)
    \s*\.\s*join\s*\(\s*
      '(?P<sep2>[^'\r\n]*)'
    \s*\)
    """,
    re.VERBOSE,
)

# Matches `'STRING'.split('SEP').join('SEP2')` — same family without
# the reverse step. Effectively a string-replace-all in JavaScript.
_JS_SJ_RE = re.compile(
    r"""
    ('(?P<inner>[^'\r\n]*)')
    \s*\.\s*split\s*\(\s*
      '(?P<sep>[^'\r\n]*)'
    \s*\)
    \s*\.\s*join\s*\(\s*
      '(?P<sep2>[^'\r\n]*)'
    \s*\)
    """,
    re.VERBOSE,
)


def _fold_js_split_reverse_join(content: str) -> tuple[str, int]:
    fires = 0

    def _repl(m: re.Match[str]) -> str:
        nonlocal fires
        inner = m.group("inner")
        sep = m.group("sep")
        sep2 = m.group("sep2")
        parts = inner.split(sep) if sep else list(inner)
        parts.reverse()
        joined = sep2.join(parts)
        # Suppress trivial identity fold (SEP not present in input).
        if joined == inner and sep and sep not in inner:
            return m.group(0)
        fires += 1
        escaped = joined.replace("'", "\\'")
        return "'" + escaped + "'"

    return _JS_SRJ_RE.sub(_repl, content), fires


def _fold_js_split_join(content: str) -> tuple[str, int]:
    fires = 0

    def _repl(m: re.Match[str]) -> str:
        nonlocal fires
        inner = m.group("inner")
        sep = m.group("sep")
        sep2 = m.group("sep2")
        if not sep:
            # split('') on a string produces per-character list; join('')
            # reassembles it into the identity. Skip identity to avoid
            # spurious fires.
            if sep2 == "":
                return m.group(0)
            joined = sep2.join(list(inner))
        else:
            if sep not in inner:
                return m.group(0)
            joined = sep2.join(inner.split(sep))
        fires += 1
        escaped = joined.replace("'", "\\'")
        return "'" + escaped + "'"

    return _JS_SJ_RE.sub(_repl, content), fires


# ─── PowerShell invocation simplifier ───────────────────────────────
# Fold the PowerShell call operator `&` when it wraps a parenthesised
# expression whose first element is a string literal (i.e. the target
# cmdlet name is deterministically known).
#
# Handles the following forms (all with optional whitespace):
#   1) `&('Get-Process')`                        → `Get-Process`
#   2) `&('Get-Process') 'lsass'`                → `Get-Process lsass`
#   3) `&(('Get-Process') 'lsass')`              → `Get-Process lsass`
#   4) `&(('Get-'+'Process') 'lsass')`  (after   → `Get-Process lsass`
#      structural-string-concat-fold has already
#      folded the inner `'a'+'b'` on a prior pass)
#
# Rule 19 positive-ID guard: fires ONLY when the artifact carries a
# positive PowerShell identifier (interpreter attribute OR an inline
# PowerShell launcher / `-Command` / `-EncodedCommand` marker). This
# prevents the fold from touching bash `& (subshell)` or CMD `&`
# command-separator syntax.
#
# Args are unquoted only when they are safe (no whitespace / no PS
# special chars); otherwise the SQ literal is preserved so semantic
# meaning is retained.
_PS_INVOKE_RE = re.compile(
    r"""
    &\s*\(                              # opening call:  & (
      \s*(?:\(\s*)?                     # optional inner paren:  (
      ('[^'\r\n]*')                     # captured primary SQ literal (cmdlet)
      (?:\s*\))?                        # optional inner close:  )
      ((?:\s+'[^'\r\n]*')*)             # captured trailing SQ args INSIDE outer paren
      \s*
    \)                                  # outer close
    ((?:\s+'[^'\r\n]*')*)               # captured trailing SQ args AFTER outer paren (same line)
    """,
    re.VERBOSE,
)

_PS_POSITIVE_ID_RE = re.compile(
    r"powershell(?:\.exe)?|pwsh(?:\.exe)?|-EncodedCommand|-Command\b|-NoProfile\b",
    re.IGNORECASE,
)

_PS_ARG_UNSAFE_RE = re.compile(r"[\s\"'`$;|&<>()]")


def _is_powershell_context(content: str, interpreter: str | None) -> bool:
    if interpreter and interpreter.lower() in {"powershell", "pwsh"}:
        return True
    return bool(_PS_POSITIVE_ID_RE.search(content))


def _fold_ps_invocation_simplify(content: str, interpreter: str | None) -> tuple[str, int]:
    """Fold `&('cmdlet') 'arg'` → `cmdlet arg` for deterministic call-operator invocations."""
    if not _is_powershell_context(content, interpreter):
        return content, 0

    fires = 0

    def _repl(m: re.Match[str]) -> str:
        nonlocal fires
        primary_raw = m.group(1)
        primary = primary_raw[1:-1]  # strip surrounding single-quotes
        # Refuse to fold empty cmdlet or one with unsafe chars.
        if not primary or _PS_ARG_UNSAFE_RE.search(primary):
            return m.group(0)
        args_blob = (m.group(2) or "") + (m.group(3) or "")
        arg_literals = re.findall(r"'([^'\r\n]*)'", args_blob)
        parts = [primary]
        for arg in arg_literals:
            if arg and not _PS_ARG_UNSAFE_RE.search(arg):
                parts.append(arg)
            else:
                # keep the quotes when the arg contains whitespace or specials
                parts.append("'" + arg + "'")
        fires += 1
        return " ".join(parts)

    return _PS_INVOKE_RE.sub(_repl, content), fires


# ─── PowerShell launcher unwrap ─────────────────────────────────────
# Strip the outer `powershell(.exe)? [switches] -Command|-c "<script>"`
# launcher wrapper when the inner script is already canonical. The
# launcher's own switches (`-NoProfile`, `-ExecutionPolicy Bypass`,
# `-WindowStyle Hidden`, etc.) are MITRE-relevant metadata but the
# analyst-facing DECODED OUTPUT should show the script that actually
# runs — matching the "Decoded Script Text" convention used by other
# analyst platforms.
#
# The pre-canonical launcher information is preserved in the
# provenance trace (KILL-CHAIN graph shows `POWERSHELL-NORMALIZE` as
# a distinct stage), so unwrapping the wrapper does NOT lose evidence.
#
# Rule 19 positive-ID: only fires when the payload starts with a
# powershell launcher token.
_PS_LAUNCHER_RE = re.compile(
    r"""
    ^\s*                                        # start of line
    (?:powershell(?:\.exe)?|pwsh(?:\.exe)?)     # launcher
    (?P<switches>(?:\s+-[A-Za-z]+(?:\s+[^\s\"'-][^\s]*)?)*)  # optional switches
    \s+-(?:C|c)(?:ommand)?\s+                   # -Command / -c
    "(?P<script>[^\"\r\n]*)"                    # DQ script body
    \s*$                                        # end of line
    """,
    re.VERBOSE | re.IGNORECASE,
)


def _fold_ps_launcher_unwrap(content: str, interpreter: str | None) -> tuple[str, int]:
    """Strip the powershell launcher wrapper when the inner script is canonical.

    The inner script is considered canonical when it no longer contains
    the PS call operator `&(`, the concat operator between literals
    (`'a'+'b'`), or the `-EncodedCommand` marker. This ensures we do
    not unwrap prematurely — a wrapper that still has obfuscation
    inside must be handled by the other folds first.
    """
    m = _PS_LAUNCHER_RE.match(content.strip())
    if not m:
        return content, 0
    script = m.group("script")
    # Canonical inner-script guard: refuse to unwrap if any of these
    # obfuscation markers are still present.
    if "&(" in script or re.search(r"'[^']*'\s*\+\s*'", script):
        return content, 0
    if re.search(r"-Encoded(?:Command)?\b", script, re.IGNORECASE):
        return content, 0
    return script, 1


# ─── Pass entrypoint ────────────────────────────────────────────────
# Order: static-join first (largest structure), then -join operator,
# then string concat, then caret strip, then JS structural folds,
# then PS invocation simplify (runs last so concat/join folds on the
# inner literals have already produced the primary literal).
_FOLDS: tuple[tuple[str, callable], ...] = (
    ("structural-static-join-fold", _fold_static_join),
    ("structural-join-operator-fold", _fold_join_operator),
    ("structural-string-concat-fold", _fold_string_concat),
    ("structural-cmd-caret-strip", _fold_cmd_caret_strip),
    ("structural-js-split-reverse-join", _fold_js_split_reverse_join),
    ("structural-js-split-join", _fold_js_split_join),
)


def run(artifact: Artifact) -> tuple[Artifact, PassRecord]:
    content = artifact.content
    fired: list[str] = []

    for name, fn in _FOLDS:
        new_content, count = fn(content)
        if count > 0:
            fired.append(f"{name} x{count}")
            content = new_content

    # PS invocation simplifier needs the interpreter context, so it is
    # invoked separately (function signature differs from the plain
    # (content) -> (content, count) fold contract).
    new_content, count = _fold_ps_invocation_simplify(content, artifact.interpreter)
    invocation_fired = count > 0
    if invocation_fired:
        fired.append(f"structural-ps-invocation-simplify x{count}")
        content = new_content

    # PS launcher unwrap fires LAST and ONLY when at least one other
    # structural deobfuscation fold fired in the same iteration. This
    # keeps `powershell -Command "IEX (…)"` payloads with their
    # launcher visible (nothing was deobfuscated inside), while
    # canonicalising `powershell -Command "&(('Get-'+'Process') 'lsass')"`
    # → `Get-Process lsass` where the fold chain proved the wrapper is
    # concealing simplifiable obfuscation.
    if fired:  # something deobfuscated → strip the now-redundant wrapper
        new_content, count = _fold_ps_launcher_unwrap(content, artifact.interpreter)
        if count > 0:
            fired.append(f"structural-ps-launcher-unwrap x{count}")
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
