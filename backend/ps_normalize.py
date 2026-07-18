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


def normalize_powershell(text: str) -> Tuple[str, List[str]]:
    """Apply all cosmetic-layer normalizations. Returns (cleaned_text, applied_passes)."""
    if not text or not isinstance(text, str):
        return text, []

    applied: List[str] = []
    passes = [
        ("strip-backticks",  _strip_backticks),
        ("collapse-concat",  _collapse_concat),
        ("resolve-format",   _resolve_format),
        ("strip-paren-str",  _strip_paren_str),
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
    )
    if not smell:
        return text, []
    return normalize_powershell(text)
