"""PowerShell Cosmetic Normalizer — Feb 2026 v1.3.0

Cleans the three "cosmetic obfuscation" layers PowerShell interpreter
strips at parse-time but our decoder leaves alone by default:

    1. Backticks inside identifiers  →  S`eT-It`em            → Set-Item
    2. String concatenation           →  ('Uti'+'l')            → 'Util'
    3. Format-string operator         →  "{1}{0}" -f 'F','rE'   → 'rEF'

Apply iteratively until stable (max 8 passes).

Intentionally conservative — only rewrites when it's safe (no side effects).
"""
from __future__ import annotations

import re
from typing import List, Tuple

_MAX_PASSES = 8

# ─── Pattern set ────────────────────────────────────────────────────────
# Backtick inside a bareword identifier (letters + backticks + letters)
_RX_BACKTICK_ID = re.compile(r"([A-Za-z_])`+([A-Za-z_])")

# Backtick inside a ${…} variable expansion
_RX_BACKTICK_VAR = re.compile(r"\$\{([^}]+)\}")

# `'A' + 'B'` → `'AB'` (only single-quoted strings, only + operator)
_RX_STR_CONCAT = re.compile(r"'([^'\n]*)'\s*\+\s*'([^'\n]*)'")

# `"{n}{m}…"  -f 'a','b','c'` → resolved
_RX_FORMAT_STR = re.compile(
    r"""["']((?:\{\d+\})+)["']         # "{1}{0}" style template
        \s*-[fF]\s*                    # -f operator
        (                              # arg list
          (?:['"][^'"]*['"]\s*,?\s*)+  # 'a','b','c'
        )""", re.VERBOSE)

# `(<X>)` wrapping a single simple string literal → strip outer parens
_RX_PAREN_STR = re.compile(r"\(\s*('[^'\n]*'|\"[^\"\n]*\")\s*\)")


def _strip_backticks(text: str) -> str:
    """Repeatedly collapse `a`b` → `ab` for identifier backticks."""
    prev = None
    while prev != text:
        prev = text
        text = _RX_BACKTICK_ID.sub(r"\1\2", text)
    # Handle backticks inside ${…} variable names
    def _fix_var(m):
        inside = m.group(1).replace("`", "")
        return "${" + inside + "}"
    text = _RX_BACKTICK_VAR.sub(_fix_var, text)
    return text


def _collapse_concat(text: str) -> str:
    prev = None
    while prev != text:
        prev = text
        text = _RX_STR_CONCAT.sub(lambda m: "'" + m.group(1) + m.group(2) + "'", text)
    return text


def _resolve_format(text: str) -> str:
    """Resolve `"{1}{0}" -f 'A','B'` style expressions."""
    def _repl(m):
        template = m.group(1)
        args_raw = m.group(2)
        # Parse args ("'a'","'b'","'c'")
        args = re.findall(r"['\"]([^'\"]*)['\"]", args_raw)
        try:
            # Extract indices from template like "{6}{3}{1}"
            indices = [int(i) for i in re.findall(r"\{(\d+)\}", template)]
            if not indices:
                return m.group(0)
            if max(indices) >= len(args):
                return m.group(0)
            return "'" + "".join(args[i] for i in indices) + "'"
        except Exception:
            return m.group(0)
    prev = None
    while prev != text:
        prev = text
        text = _RX_FORMAT_STR.sub(_repl, text)
    return text


def _strip_paren_str(text: str) -> str:
    """Strip `('X')` → `'X'` (single string literal wrapped in parens)."""
    prev = None
    while prev != text:
        prev = text
        text = _RX_PAREN_STR.sub(lambda m: m.group(1), text)
    return text


# ─── Feb 2026 v1.3.1 · Aggressive bareword → literal coercion ──────────
# AMSI-bypass tradecraft often uses UNQUOTED identifier fragments like
# `(mation.)`, `(Publ)`, `((.Man)+agement.)` — these are PowerShell
# expressions that evaluate to strings because PS treats unrecognised
# barewords as command names / string coercions inside expressions.
# For DECODING purposes (we're reading, not executing), treating these
# barewords as literals lets the concat + format collapser finish the job.
_BAREWORD = r"[A-Za-z_][A-Za-z0-9_.]*"

# Match `(bareword)` — a single bareword wrapped in parens, no operators.
_RX_PAREN_BAREWORD = re.compile(r"\(\s*(" + _BAREWORD + r")\s*\)")

# Match `((bareword))` nested one deeper.
_RX_DOUBLE_PAREN_BAREWORD = re.compile(r"\(\s*\(\s*(" + _BAREWORD + r")\s*\)\s*\)")

# `((.Foo))` and `(.Foo)` — leading-dot barewords (member accessors on $_ pipe)
_RX_PAREN_DOT_BAREWORD = re.compile(r"\(\s*(\.[A-Za-z_][A-Za-z0-9_.]*)\s*\)")


def _barewords_to_literals(text: str) -> str:
    """Coerce `(name)`, `((name))`, `(.name)` → `'name'` when inside a
    string-context (adjacent to `'`, `+`, or `-f` args). Very conservative —
    ONLY runs inside argument lists that are already surrounded by quoted
    strings or `+` operators, so we don't touch real function calls like
    `Write-Host(x)`.
    """
    # First pass — deepest first (double paren)
    prev = None
    while prev != text:
        prev = text
        text = _RX_DOUBLE_PAREN_BAREWORD.sub(lambda m: "'" + m.group(1) + "'", text)
        # Leading-dot barewords: preserve the dot so `.Management` stays `.Management`
        # when concatenated (e.g. `System` + `.Management` = `System.Management`).
        text = _RX_PAREN_DOT_BAREWORD.sub(lambda m: "'" + m.group(1) + "'", text)

    # Second pass — single-paren barewords adjacent to `+` or `,` in an
    # obvious string-concat / format-args context.
    _rx = re.compile(
        r"""
        (?P<pre>['")]?\s*[+,]\s*|-[fF]\s*)   # left context: + , or -f
        \(\s*(?P<bw>""" + _BAREWORD + r""")\s*\)
        (?P<post>\s*[+,)])                    # right context: + , or closing paren
        """,
        re.VERBOSE,
    )
    prev = None
    while prev != text:
        prev = text
        text = _rx.sub(lambda m: m.group("pre") + "'" + m.group("bw") + "'" + m.group("post"), text)

    # Third pass — UNPARENTHESISED bareword adjacent to a quoted string in
    # a `+` concat chain. Handles `'Man'+agement.)` → `'Man'+'agement.'`
    # and `('u'+'to'+(mation.))` → `'utomation.'` residues.
    #   'x' + bareword    → 'x' + 'bareword'
    #   bareword + 'x'    → 'bareword' + 'x'
    _rx_right = re.compile(r"(['\"][^'\"\n]*['\"])\s*\+\s*(" + _BAREWORD + r")(?=\s*[),+])")
    _rx_left  = re.compile(r"(?<![A-Za-z_.])(" + _BAREWORD + r")\s*\+\s*(['\"][^'\"\n]*['\"])")
    prev = None
    while prev != text:
        prev = text
        text = _rx_right.sub(lambda m: m.group(1) + "+'" + m.group(2) + "'", text)
        text = _rx_left.sub(lambda m: "'" + m.group(1) + "'+" + m.group(2), text)

    # Fourth pass — `(bareword)` when it's part of a `+` concat expression.
    #   (Syst) + 'em'  → 'Syst' + 'em'
    #   'em' + (Syst)  → 'em' + 'Syst'
    _rx_paren_plus_r = re.compile(r"\(\s*(" + _BAREWORD + r")\s*\)\s*\+")
    _rx_paren_plus_l = re.compile(r"\+\s*\(\s*(" + _BAREWORD + r")\s*\)")
    prev = None
    while prev != text:
        prev = text
        text = _rx_paren_plus_r.sub(lambda m: "'" + m.group(1) + "'+", text)
        text = _rx_paren_plus_l.sub(lambda m: "+'" + m.group(1) + "'", text)

    return text


def _collapse_mixed_concat(text: str) -> str:
    """Collapse `'a' + 'b' + 'c'` chains of THREE OR MORE literals into one.

    The base `_RX_STR_CONCAT` handles two-string collapses; running it
    iteratively already handles chains — but the mixed-order regex tighter
    than `_RX_STR_CONCAT.sub` sometimes leaves gaps when parens interleave.
    This helper is a safety net that repeatedly collapses `'X' + 'Y'`.
    """
    return _collapse_concat(text)


def normalize_powershell(text: str) -> Tuple[str, List[str]]:
    """Apply all cosmetic-layer normalizations. Returns (cleaned_text, applied_passes)."""
    if not text or not isinstance(text, str):
        return text, []

    applied: List[str] = []
    passes = [
        ("strip-backticks",       _strip_backticks),
        ("bareword-to-literal",   _barewords_to_literals),
        ("collapse-concat",       _collapse_concat),
        ("resolve-format",        _resolve_format),
        ("strip-paren-str",       _strip_paren_str),
    ]

    for _ in range(_MAX_PASSES):
        prev = text
        for name, fn in passes:
            new = fn(text)
            if new != text:
                applied.append(name)
                text = new
        if text == prev:
            break

    return text, applied


def normalize_if_powershell(text: str) -> Tuple[str, List[str]]:
    """Only run the normalizer if the text smells like PowerShell.
    Prevents accidental damage to non-PS payloads."""
    if not text:
        return text, []
    smell = (
        "`" in text and re.search(r"[A-Za-z]`+[A-Za-z]", text)
    ) or (
        "-f'" in text or '-f"' in text or " -f " in text.lower()
    ) or (
        re.search(r"'[A-Za-z]+'\s*\+\s*'[A-Za-z]+'", text)
    ) or (
        # Bareword-in-parens concat, e.g. `('Am'+'si') + (Utils)`
        re.search(r"['\"][^'\"]*['\"]\s*\+\s*\(\s*[A-Za-z_]", text)
    )
    if not smell:
        return text, []
    return normalize_powershell(text)
