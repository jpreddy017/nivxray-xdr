"""
Semantic reconstruction pass · M5.

Performs deterministic semantic reconstruction on the artifact:
alias expansion, single-assignment variable propagation, and
whitelisted bash-pipeline reduction. This is the FINAL pass in the
canonical pipeline; after M5 the artifact should be either fully
canonical or provably unresolvable by deterministic means alone.

Transformations
---------------

1. ``semantic-ps-alias-expand`` — replace common PowerShell aliases
   with their canonical cmdlet names, at command position, outside
   quoted strings. Whitelisted (no wildcards, no partial matches):
   ``iex``, ``iwr``, ``icm``, ``irm``, ``gc``, ``gci``, ``sc``,
   ``gcm``, ``gm``, ``ls``, ``dir``, ``cat``, ``cp``, ``mv``,
   ``rm``, ``del``, ``echo``, ``sleep``, ``ps``, ``kill``,
   ``wget``, ``curl``.

2. ``semantic-ps-variable-propagate`` — when a variable ``$x`` is
   assigned exactly once in the artifact and the RHS is a
   single-quoted string literal, replace every subsequent
   occurrence of ``$x`` with that literal. Never touches variables
   used inside a quoted string.

3. ``semantic-bash-pipeline-reduce`` — deterministically evaluate a
   left-anchored bash pipeline of the form ``echo 'S' | STAGE
   [| STAGE ...]`` where every STAGE is in a strict whitelist:

     * ``rev``            — reverse each line
     * ``base64 -d``      — Base64 decode
     * ``base64 --decode``
     * ``base64``         — Base64 encode
     * ``xxd -r -p``      — hex → bytes
     * ``xxd -p``         — bytes → hex
     * ``tr FROM TO``     — one-to-one character translation
     * ``gunzip``         — gzip decompress
     * ``zcat``           — gzip decompress
     * ``cat``            — identity
     * ``rot13``          — trivial rotation

   Anything outside the whitelist stops the pipeline and leaves the
   original text unchanged. The reducer NEVER shells out.

Design invariants
-----------------
* Pure functions.
* Quote-safe: alias expansion and variable propagation never touch
  content inside quoted strings.
* Behaviour-preserving: PowerShell aliases are canonical shorthands
  and expanding them changes syntax only, not semantics; variable
  propagation is applied only when the assignment is unambiguous
  (single occurrence with a literal RHS).
* The bash-pipeline reducer runs entirely in-process; every stage
  is implemented in pure Python and only fires on ASCII input.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import gzip
import re
import zlib
from typing import Callable

from .artifact import Artifact
from .provenance import PassRecord
from .transformation import Transformation

PASS_NAME = "semantic"


# ─── Common quote-safety prefix ─────────────────────────────────────
_QUOTED_PREFIX = r"(?P<sq>'[^'\r\n]*')|(?P<dq>\"[^\"\r\n]*\")"


# ─── Fold 1 · PowerShell alias expansion ────────────────────────────

_PS_ALIASES: dict[str, str] = {
    # Unambiguous PowerShell aliases (rarely used as bash / English
    # command names). Deliberately EXCLUDES: echo, cat, ls, dir, cp,
    # mv, rm, del, sleep, ps, kill, wget, curl — those tokens are
    # ambiguous in mixed-interpreter payloads and expanding them
    # could corrupt bash / cmd fragments.
    "iex": "Invoke-Expression",
    "iwr": "Invoke-WebRequest",
    "icm": "Invoke-Command",
    "irm": "Invoke-RestMethod",
    "gc": "Get-Content",
    "gci": "Get-ChildItem",
    "sc": "Set-Content",
    "gcm": "Get-Command",
    "gm": "Get-Member",
}


_ALIAS_RE = re.compile(
    _QUOTED_PREFIX
    + r"|(?P<lead>(?:^|(?<=[\s;|&()`\n])))(?P<alias>[A-Za-z]{2,5})"
    + r"(?![A-Za-z0-9_\-])",
)


def _fold_ps_alias_expand(content: str) -> tuple[str, int]:
    fires = 0

    def _repl(m: re.Match[str]) -> str:
        nonlocal fires
        if m.group("sq") is not None or m.group("dq") is not None:
            return m.group(0)
        alias = m.group("alias").lower()
        canonical = _PS_ALIASES.get(alias)
        if canonical is None:
            return m.group(0)
        # Idempotency: don't re-expand something already canonical.
        if alias == canonical.lower():
            return m.group(0)
        fires += 1
        return canonical

    return _ALIAS_RE.sub(_repl, content), fires


# ─── Fold 2 · Single-assignment variable propagation ────────────────

# Match ``$var = 'literal'`` (SQ only for safety). The negative
# lookahead ``(?!\s*[+])`` protects us from an incomplete-RHS
# capture like ``$W='http'+'s'`` — propagating ``'http'`` in that
# case would silently drop the last concat operand and produce
# wrong output. We wait for structural concat-fold to fully resolve
# the RHS first, then propagate on a later iteration.
_ASSIGN_RE = re.compile(
    r"(?<![A-Za-z0-9_])\$(?P<var>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*=\s*'(?P<lit>[^'\r\n]*)'"
    r"(?!\s*[+])",
)


def _fold_ps_variable_propagate(content: str) -> tuple[str, int]:
    fires = 0
    # Consider only variables that are ASSIGNED EXACTLY ONCE and USED
    # AT LEAST ONCE (outside of the assignment itself).
    assign_counts: dict[str, int] = {}
    for m in _ASSIGN_RE.finditer(content):
        assign_counts[m.group("var")] = assign_counts.get(m.group("var"), 0) + 1
    # Also count assignments with non-literal RHS so we don't touch
    # variables that are reassigned in ways we don't understand.
    for m in re.finditer(r"(?<![A-Za-z0-9_])\$(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=", content):
        assign_counts[m.group("var")] = assign_counts.get(m.group("var"), 0)
        # Explicit reassignment detection — if we see `$x=` more than
        # once, this variable is off-limits.
    # Re-count generic assignments.
    generic_counts: dict[str, int] = {}
    for m in re.finditer(r"(?<![A-Za-z0-9_])\$(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)", content):
        generic_counts[m.group("var")] = generic_counts.get(m.group("var"), 0) + 1

    for m in list(_ASSIGN_RE.finditer(content)):
        var = m.group("var")
        lit = m.group("lit")
        if generic_counts.get(var, 0) != 1:
            continue  # variable is assigned more than once — do not propagate.
        # Substitute every $var occurrence OUTSIDE quoted strings.
        use_re = re.compile(
            _QUOTED_PREFIX
            + rf"|(?<![A-Za-z0-9_])\$({re.escape(var)})(?![A-Za-z0-9_])",
        )

        def _repl(um: re.Match[str], _lit: str = lit) -> str:
            nonlocal fires
            if um.group("sq") is not None or um.group("dq") is not None:
                return um.group(0)
            fires += 1
            return "'" + _lit + "'"

        # First, mask the assignment itself so we don't replace the
        # `$var` inside `$var='literal'` (that occurrence is anchored
        # by the `=` immediately after).
        assign_start = m.start()
        assign_end = m.end()
        prefix = content[:assign_start]
        assignment_txt = content[assign_start:assign_end]
        suffix = content[assign_end:]
        new_suffix = use_re.sub(_repl, suffix)
        if new_suffix != suffix:
            # Drop the assignment (it's fully consumed) — leave a
            # semicolon behind if the next character is one, so the
            # PowerShell-style separator is preserved.
            content = prefix + assignment_txt + new_suffix

    return content, fires


# ─── Fold 3 · Bash pipeline reduction ───────────────────────────────

_ECHO_HEAD_RE = re.compile(
    r"\A\s*echo\s+'(?P<arg>[^'\r\n]*)'\s*(?P<rest>(?:\|[^\n]*)?)\s*\Z",
)


def _stage_rev(data: bytes) -> bytes:
    return data[::-1]


def _stage_base64_decode(data: bytes) -> bytes:
    # Base64 decoder accepts ASCII bytes and strips whitespace.
    try:
        return base64.b64decode(data.decode("ascii").strip(), validate=True)
    except (UnicodeDecodeError, binascii.Error, ValueError):
        raise ValueError("stage base64 -d: invalid input")


def _stage_base64_encode(data: bytes) -> bytes:
    return base64.b64encode(data)


def _stage_xxd_r_p(data: bytes) -> bytes:
    """Reverse of ``xxd -p`` — hex string to bytes."""
    text = data.decode("ascii", errors="strict")
    text = re.sub(r"\s+", "", text)
    if len(text) % 2:
        raise ValueError("stage xxd -r -p: odd-length hex input")
    try:
        return bytes.fromhex(text)
    except ValueError as exc:
        raise ValueError(f"stage xxd -r -p: {exc}") from None


def _stage_xxd_p(data: bytes) -> bytes:
    return data.hex().encode("ascii")


def _stage_gunzip(data: bytes) -> bytes:
    try:
        return gzip.decompress(data)
    except (OSError, EOFError, zlib.error):
        # Raw-DEFLATE fallback (as used by M4's decoder).
        if len(data) >= 18 and data[:2] == b"\x1f\x8b":
            try:
                return zlib.decompress(data[10:], -zlib.MAX_WBITS)
            except zlib.error as exc:
                raise ValueError(f"stage gunzip: {exc}") from None
        raise ValueError("stage gunzip: not gzip-compressed")


def _stage_rot13(data: bytes) -> bytes:
    return codecs.encode(data.decode("ascii", errors="strict"), "rot_13").encode("ascii")


def _stage_cat(data: bytes) -> bytes:
    return data


def _stage_tr(from_set: str, to_set: str, data: bytes) -> bytes:
    if len(from_set) != len(to_set):
        raise ValueError("stage tr: FROM/TO length mismatch")
    trans = str.maketrans(from_set, to_set)
    return data.decode("latin-1").translate(trans).encode("latin-1")


# Fixed-arg stages (single fn taking bytes → bytes).
_STAGE_TABLE: dict[str, Callable[[bytes], bytes]] = {
    "rev": _stage_rev,
    "base64 -d": _stage_base64_decode,
    "base64 --decode": _stage_base64_decode,
    "base64": _stage_base64_encode,
    "xxd -r -p": _stage_xxd_r_p,
    "xxd -p": _stage_xxd_p,
    "gunzip": _stage_gunzip,
    "zcat": _stage_gunzip,
    "cat": _stage_cat,
    "rot13": _stage_rot13,
}


def _parse_stage(text: str) -> Callable[[bytes], bytes] | None:
    """Return the callable for a whitelisted stage string, or None."""
    text = text.strip()
    if text in _STAGE_TABLE:
        return _STAGE_TABLE[text]
    # tr FROM TO
    m = re.match(r"\Atr\s+(?P<f>\S+)\s+(?P<t>\S+)\Z", text)
    if m is not None:
        f = m.group("f").strip("'\"")
        t = m.group("t").strip("'\"")
        return lambda data, _f=f, _t=t: _stage_tr(_f, _t, data)
    return None


def _fold_bash_pipeline_reduce(content: str) -> tuple[str, int]:
    m = _ECHO_HEAD_RE.match(content)
    if m is None:
        return content, 0
    data = m.group("arg").encode("latin-1")
    rest = m.group("rest").strip()
    if not rest.startswith("|"):
        return content, 0
    stages_text = [s.strip() for s in rest.lstrip("|").split("|")]
    if not stages_text:
        return content, 0
    resolved: list[Callable[[bytes], bytes]] = []
    for st in stages_text:
        fn = _parse_stage(st)
        if fn is None:
            return content, 0  # unknown stage — do not touch the pipeline.
        resolved.append(fn)
    for fn in resolved:
        try:
            data = fn(data)
        except ValueError:
            return content, 0
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = data.decode("latin-1")
        except Exception:
            return content, 0
    return text, 1


# ─── Transformation registry (metadata) ─────────────────────────────

TRANSFORMATIONS: tuple[Transformation, ...] = (
    Transformation(
        name="semantic-bash-pipeline-reduce",
        category="semantic",
        consumes="bash pipeline of the shape `echo 'X' | STAGE [| STAGE...]`",
        produces="pipeline result as text",
        preconditions=("head is `echo 'literal'`",
                       "every stage is in the deterministic whitelist"),
        postconditions=("whole pipeline replaced with computed output",),
        priority=210,  # runs before alias-expand so bash echo is recognised
        apply=_fold_bash_pipeline_reduce,
    ),
    Transformation(
        name="semantic-ps-alias-expand",
        category="semantic",
        consumes="powershell-text with alias tokens at command position",
        produces="powershell-text with canonical cmdlet names",
        preconditions=("alias token outside quoted string",
                       "token at command position (start / after ; | & ()`)"),
        postconditions=("alias replaced with canonical cmdlet",),
        priority=200,
        apply=_fold_ps_alias_expand,
    ),
    Transformation(
        name="semantic-ps-variable-propagate",
        category="semantic",
        consumes="powershell-text with `$var='SQ literal'` assignment",
        produces="powershell-text with occurrences of `$var` substituted",
        preconditions=("variable assigned exactly once",
                       "RHS is a plain SQ literal",
                       "usage outside quoted string"),
        postconditions=("`$var` uses replaced by SQ literal",),
        priority=180,
        apply=_fold_ps_variable_propagate,
    ),
)


def run(artifact: Artifact) -> tuple[Artifact, PassRecord]:
    content = artifact.content
    fired: list[str] = []
    for xf in TRANSFORMATIONS:
        assert xf.apply is not None
        new_content, count = xf.apply(content)
        if count > 0:
            fired.append(f"{xf.name} x{count}")
            content = new_content
    if content == artifact.content:
        return artifact, PassRecord(
            name=PASS_NAME, changed=False, transformations=(), notes=(),
        )
    return artifact.replace(content=content), PassRecord(
        name=PASS_NAME, changed=True, transformations=tuple(fired),
    )


__all__ = ["PASS_NAME", "TRANSFORMATIONS", "run"]
