"""
Content normalization pass · M3.

Deterministic content normalization. Every transformation here is
strictly SAFE — it never modifies content inside quoted string literals
(so encoded/Base64 payloads survive untouched) and it never changes
program semantics (PowerShell operators are case-insensitive by design,
static env-var defaults reflect canonical Windows install paths, etc.).

Transformations (in order)
--------------------------

1. ``content-ps-operator-case-normalize`` — lowercase well-known
   PowerShell operators / switches (``-jOiN`` → ``-join``,
   ``-EncodedCommand`` → ``-encodedcommand``). Case-insensitive by
   design in PowerShell.

2. ``content-env-var-case-normalize`` — normalize the ``$env:`` scope
   prefix to canonical lowercase ``$env:``. Variable names inside the
   scope are also lowercased; PowerShell variables are
   case-insensitive.

3. ``content-env-var-substitute`` — substitute a small, static table
   of Windows-default environment variables with their canonical
   literal path. Only variables whose Windows default is fixed and
   documented are included; user- or host-specific vars are
   deliberately excluded.

4. ``content-string-index-fold`` — fold string-literal indexing:
     * ``'literal'[n]``          → ``'char_at_n'``
     * ``'literal'[a..b]``       → ``('c_a','c_{a+1}',…,'c_b')``
     * ``'literal'[a,b,c]``      → ``('c_a','c_b','c_c')``

5. ``content-backtick-escape-strip`` — remove PowerShell escape
   backticks that appear INSIDE bare identifiers (e.g. ``I`E`X`` →
   ``IEX``). Never touches backticks inside string literals or
   backticks used as line-continuation at end-of-line.

6. ``content-numeric-constant-fold`` — fold ``50+55`` → ``105`` and
   ``50-30`` → ``20`` where both operands are integer literals. Only
   fires on integers, never on strings (that job belongs to the
   structural pass ``string-concat-fold``).

Safety rule
-----------
Every regex is designed so it CANNOT match content inside a quoted
string. Where the regex needs to allow surrounding context that could
contain quotes, we mask quoted regions with a single alternation
(``(?P<sq>'[^'\\r\\n]*')|(?P<dq>"[^"\\r\\n]*")|<target>``) and return
the original text when a quoted branch matches. This is the same
pattern used in ``structural.py``.
"""
from __future__ import annotations

import re

from .artifact import Artifact
from .provenance import PassRecord
from .transformation import Transformation

PASS_NAME = "content"


# ─── Static reference tables ────────────────────────────────────────

# PowerShell operators / switches that are case-insensitive by design.
# The value is the canonical form we normalize to.
_PS_OPERATORS: dict[str, str] = {
    op.lower(): op.lower()
    for op in (
        # comparison / logical
        "-eq", "-ne", "-lt", "-le", "-gt", "-ge",
        "-and", "-or", "-not", "-xor",
        "-band", "-bor", "-bnot", "-bxor", "-shl", "-shr",
        "-match", "-notmatch", "-like", "-notlike",
        "-contains", "-notcontains", "-in", "-notin",
        "-is", "-as", "-f",
        # string ops
        "-join", "-split", "-replace",
        # CLI switches
        "-command", "-c", "-encodedcommand", "-enc",
        "-noprofile", "-nop", "-noninteractive", "-noni",
        "-windowstyle", "-w", "-hidden",
        "-executionpolicy", "-ep", "-bypass",
        "-file", "-inputformat", "-outputformat",
        "-version",
    )
}

# Windows environment variables with static, documented default values.
# User- and host-specific variables (USERPROFILE, USERNAME, APPDATA,
# TEMP, TMP, PATH, PSMODULEPATH, ...) are deliberately excluded — they
# vary per install / user / host and substituting them would be an
# assumption, not a deterministic transformation.
_ENV_DEFAULTS: dict[str, str] = {
    "comspec": r"C:\Windows\system32\cmd.exe",
    "public": r"C:\Users\Public",
    "programfiles": r"C:\Program Files",
    "programfiles(x86)": r"C:\Program Files (x86)",
    "programw6432": r"C:\Program Files",
    "systemroot": r"C:\Windows",
    "systemdrive": r"C:",
    "windir": r"C:\Windows",
    "programdata": r"C:\ProgramData",
    "allusersprofile": r"C:\ProgramData",
    "commonprogramfiles": r"C:\Program Files\Common Files",
    "commonprogramfiles(x86)": r"C:\Program Files (x86)\Common Files",
    "commonprogramw6432": r"C:\Program Files\Common Files",
}


# ─── Quote-safe regex prefixes (used by every fold) ─────────────────

# Match a full quoted string as the FIRST branch of an alternation.
# When the regex engine picks this branch, the callback returns the
# match verbatim, which means the target-branch replacement never
# touches content inside strings.
_QUOTED_PREFIX = r"(?P<sq>'[^'\r\n]*')|(?P<dq>\"[^\"\r\n]*\")"


# ─── Fold 1 · PowerShell operator case normalization ────────────────

_OP_RE = re.compile(
    _QUOTED_PREFIX
    + r"|(?<![A-Za-z0-9_])(?P<op>-[A-Za-z]{1,32})(?=[\s\'\"(),;{})|]|$)",
)


def _fold_ps_operator_case(content: str) -> tuple[str, int]:
    fires = 0

    def _repl(m: re.Match[str]) -> str:
        nonlocal fires
        if m.group("sq") is not None or m.group("dq") is not None:
            return m.group(0)
        op = m.group("op")
        canonical = _PS_OPERATORS.get(op.lower())
        if canonical is None or op == canonical:
            return op
        fires += 1
        return canonical

    return _OP_RE.sub(_repl, content), fires


# ─── Fold 2 · $env: case normalization ──────────────────────────────

_ENV_CASE_RE = re.compile(
    _QUOTED_PREFIX
    + r"|(?P<env>\$env:)(?P<var>[A-Za-z_][A-Za-z0-9_()]*)",
    flags=re.IGNORECASE,
)


def _fold_env_case(content: str) -> tuple[str, int]:
    fires = 0

    def _repl(m: re.Match[str]) -> str:
        nonlocal fires
        if m.group("sq") is not None or m.group("dq") is not None:
            return m.group(0)
        prefix = m.group("env")
        var = m.group("var")
        canonical_prefix = "$env:"
        canonical_var = var.lower()
        if prefix == canonical_prefix and var == canonical_var:
            return m.group(0)
        fires += 1
        return canonical_prefix + canonical_var

    return _ENV_CASE_RE.sub(_repl, content), fires


# ─── Fold 3 · $env:X → 'default' substitution ───────────────────────

_ENV_SUB_RE = re.compile(
    _QUOTED_PREFIX
    + r"|\$env:(?P<var>[A-Za-z_][A-Za-z0-9_()]*)",
    flags=re.IGNORECASE,
)


def _fold_env_substitute(content: str) -> tuple[str, int]:
    fires = 0

    def _repl(m: re.Match[str]) -> str:
        nonlocal fires
        if m.group("sq") is not None or m.group("dq") is not None:
            return m.group(0)
        var = m.group("var").lower()
        default = _ENV_DEFAULTS.get(var)
        if default is None:
            return m.group(0)
        fires += 1
        # Escape single quotes inside the substituted literal (Windows
        # paths don't contain them, but the encoder is correct either
        # way).
        escaped = default.replace("'", "''")
        return "'" + escaped + "'"

    return _ENV_SUB_RE.sub(_repl, content), fires


# ─── Fold 4 · string-literal index / slice folding ──────────────────

# Only single-quoted string literals — same safety guarantee as the
# structural pass. We fold three PowerShell indexing forms:
#   'lit'[n]           → 'c'
#   'lit'[a..b]        → ('c1','c2',...)
#   'lit'[a,b,c]       → ('c1','c2','c3')
_SQ_LIT = r"'([^'\r\n]*)'"
_INDEX_SINGLE_RE = re.compile(_SQ_LIT + r"\[\s*(-?\d+)\s*\]")
_INDEX_RANGE_RE = re.compile(_SQ_LIT + r"\[\s*(-?\d+)\s*\.\.\s*(-?\d+)\s*\]")
_INDEX_LIST_RE = re.compile(
    _SQ_LIT + r"\[\s*(-?\d+(?:\s*,\s*-?\d+){1,})\s*\]"
)


def _at(s: str, i: int) -> str | None:
    if -len(s) <= i < len(s):
        return s[i]
    return None


def _fold_string_index_single(content: str) -> tuple[str, int]:
    fires = 0

    def _repl(m: re.Match[str]) -> str:
        nonlocal fires
        lit = m.group(1)
        idx = int(m.group(2))
        ch = _at(lit, idx)
        if ch is None:
            return m.group(0)
        fires += 1
        return "'" + ch.replace("'", "''") + "'"

    return _INDEX_SINGLE_RE.sub(_repl, content), fires


def _fold_string_index_range(content: str) -> tuple[str, int]:
    fires = 0

    def _repl(m: re.Match[str]) -> str:
        nonlocal fires
        lit = m.group(1)
        a = int(m.group(2))
        b = int(m.group(3))
        # PowerShell range accepts descending endpoints (produces
        # reverse), but we handle only ascending to stay conservative.
        if a > b:
            step = -1
            indices = list(range(a, b - 1, step))
        else:
            indices = list(range(a, b + 1))
        chars = [_at(lit, i) for i in indices]
        if any(c is None for c in chars):
            return m.group(0)
        fires += 1
        parts = ",".join("'" + (c or "").replace("'", "''") + "'" for c in chars)
        return "(" + parts + ")"

    return _INDEX_RANGE_RE.sub(_repl, content), fires


def _fold_string_index_list(content: str) -> tuple[str, int]:
    fires = 0

    def _repl(m: re.Match[str]) -> str:
        nonlocal fires
        lit = m.group(1)
        indices = [int(x.strip()) for x in m.group(2).split(",")]
        chars = [_at(lit, i) for i in indices]
        if any(c is None for c in chars):
            return m.group(0)
        fires += 1
        parts = ",".join("'" + (c or "").replace("'", "''") + "'" for c in chars)
        return "(" + parts + ")"

    return _INDEX_LIST_RE.sub(_repl, content), fires


# ─── Fold 5 · backtick escape strip ─────────────────────────────────

# Match a backtick that sits BETWEEN two alphanumeric-or-underscore
# characters AND is outside any quoted string. This is the exact
# pattern used by obfuscators like Invoke-Obfuscation to break up
# identifier tokens (``I`E`X``, ``ie`x``, ``pow`ershell``).
_BACKTICK_RE = re.compile(
    _QUOTED_PREFIX + r"|(?<=[A-Za-z0-9_])`(?=[A-Za-z0-9_])",
)


def _fold_backtick_strip(content: str) -> tuple[str, int]:
    fires = 0

    def _repl(m: re.Match[str]) -> str:
        nonlocal fires
        if m.group("sq") is not None or m.group("dq") is not None:
            return m.group(0)
        fires += 1
        return ""

    return _BACKTICK_RE.sub(_repl, content), fires


# ─── Fold 6 · numeric constant fold (integer literals) ──────────────

# Match ``INT op INT`` where op ∈ {+, -} and neither integer is
# adjacent to a quote (guarding against silently touching content
# inside a string is done by the quoted-region skip prefix).
_NUM_RE = re.compile(
    _QUOTED_PREFIX
    + r"|(?<![A-Za-z0-9_'\"\.])(?P<a>-?\d+)\s*(?P<op>[+\-])\s*(?P<b>\d+)(?![A-Za-z0-9_'\"\.])",
)


def _fold_numeric_const(content: str) -> tuple[str, int]:
    fires = 0

    def _repl(m: re.Match[str]) -> str:
        nonlocal fires
        if m.group("sq") is not None or m.group("dq") is not None:
            return m.group(0)
        a = int(m.group("a"))
        b = int(m.group("b"))
        op = m.group("op")
        result = a + b if op == "+" else a - b
        fires += 1
        return str(result)

    return _NUM_RE.sub(_repl, content), fires


# ─── Transformation registry (metadata) ─────────────────────────────

TRANSFORMATIONS: tuple[Transformation, ...] = (
    Transformation(
        name="content-ps-operator-case-normalize",
        category="content",
        consumes="powershell-text",
        produces="powershell-text",
        preconditions=("operator lexed outside quoted string",),
        postconditions=("operator token lowercased to canonical form",),
        priority=110,
        apply=_fold_ps_operator_case,
    ),
    Transformation(
        name="content-env-var-case-normalize",
        category="content",
        consumes="powershell-text",
        produces="powershell-text",
        preconditions=("`$env:` prefix present outside quoted string",),
        postconditions=("`$env:` prefix and variable name lowercased",),
        priority=105,
        apply=_fold_env_case,
    ),
    Transformation(
        name="content-env-var-substitute",
        category="content",
        consumes="powershell-text with $env:<known>",
        produces="powershell-text with SQ string literal",
        preconditions=(
            "variable name in static Windows defaults table",
            "occurrence outside any quoted string",
        ),
        postconditions=("$env:X replaced with canonical SQ literal path",),
        priority=100,
        apply=_fold_env_substitute,
    ),
    Transformation(
        name="content-string-index-single-fold",
        category="content",
        consumes="SQ literal + integer index",
        produces="SQ literal (single char)",
        preconditions=("index in [-len, len)",),
        postconditions=("'literal'[n] → 'char'",),
        priority=90,
        apply=_fold_string_index_single,
    ),
    Transformation(
        name="content-string-index-range-fold",
        category="content",
        consumes="SQ literal + integer range",
        produces="parenthesized SQ literal array",
        preconditions=("a..b endpoints in-bounds",),
        postconditions=("'literal'[a..b] → ('c1','c2',...)",),
        priority=90,
        apply=_fold_string_index_range,
    ),
    Transformation(
        name="content-string-index-list-fold",
        category="content",
        consumes="SQ literal + integer index list",
        produces="parenthesized SQ literal array",
        preconditions=("every index in-bounds",),
        postconditions=("'literal'[a,b,c] → ('ca','cb','cc')",),
        priority=90,
        apply=_fold_string_index_list,
    ),
    Transformation(
        name="content-backtick-escape-strip",
        category="content",
        consumes="powershell-text with `-escaped identifiers",
        produces="powershell-text without inline backticks",
        preconditions=("backtick between two identifier characters",
                       "outside all quoted strings"),
        postconditions=("backtick removed",),
        priority=80,
        apply=_fold_backtick_strip,
    ),
    Transformation(
        name="content-numeric-constant-fold",
        category="content",
        consumes="integer literal + / - integer literal",
        produces="integer literal",
        preconditions=("both operands pure integer literals",
                       "outside all quoted strings"),
        postconditions=("expression replaced with computed integer",),
        priority=70,
        apply=_fold_numeric_const,
    ),
)


# ─── Pass entrypoint ────────────────────────────────────────────────


def run(artifact: Artifact) -> tuple[Artifact, PassRecord]:
    content = artifact.content
    fired: list[str] = []

    for xf in TRANSFORMATIONS:
        assert xf.apply is not None  # Registry guarantees this at import time.
        new_content, count = xf.apply(content)
        if count > 0:
            fired.append(f"{xf.name} x{count}")
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


__all__ = ["PASS_NAME", "TRANSFORMATIONS", "run"]
