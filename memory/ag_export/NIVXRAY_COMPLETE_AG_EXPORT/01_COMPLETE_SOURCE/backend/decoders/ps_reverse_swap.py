"""PowerShell reverse + regex-swap decoders (RC4.0 Pattern 5 · Feb 2026).

Two related PowerShell string-obfuscation tricks:

  1. Reverse-string with negative-index slicing:
        $s = 'exe.clac'; $s[-1..-8] -join ''      →   'calc.exe'
        [string]::Concat($s[-1..-($s.Length)])    →   full reverse

  2. Regex-based token swap:
        'calc.exe' -replace '(\\w+)\\.(\\w+)','$2.$1'   →  'exe.calc'
     Combined with the reverse above this produces a familiar `calc.exe` again,
     but the intermediate obfuscated form (`exe.calc` inside single quotes) is
     what static scanners actually see.

Deterministic peel — regex-match the literal, apply the swap / reverse, and
return the plaintext.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from operations import op


# ── Pattern 5a · Reverse-string via [-1..-N] index slice ────────────────────
#
# Matches:
#   $var[-1..-8] -join ''
#   $var[-1..-$var.Length] -join ''
#   [string]::Concat($var[-1..-8])
_STRING_ASSIGN_RE = re.compile(r"""\$(\w+)\s*=\s*['"]([^'"\r\n]{2,256})['"]""")
_REVERSE_SLICE_RE = re.compile(
    r"""\$(\w+)\s*\[\s*-1\s*\.\.\s*-(?:\$\w+\.Length|\d+)\s*\]""",
    re.IGNORECASE,
)


@op("powershell-reverse-string",
    "PowerShell reverse-string via negative slice",
    "Malware Loaders",
    "Decodes `$s='exe.clac'; $s[-1..-8] -join ''` → 'calc.exe'. Extracts the "
    "string-var assignment, resolves the [-1..-N] slice, joins in reverse "
    "order, and returns the reconstructed command line.")
def op_powershell_reverse_string(data: str, args: Dict[str, Any] | None = None) -> str:
    src = data or ""
    assign = {m.group(1): m.group(2) for m in _STRING_ASSIGN_RE.finditer(src)}
    if not assign:
        return "(powershell-reverse-string · no $var='...' assignment)"

    m_slice = _REVERSE_SLICE_RE.search(src)
    if not m_slice:
        return "(powershell-reverse-string · no [-1..-N] slice)"

    var = m_slice.group(1)
    val = assign.get(var)
    if val is None:
        return f"(powershell-reverse-string · var ${var} not assigned)"

    # Rewrite the src replacing the slice expression with the reversed literal.
    reversed_val = val[::-1]
    out = src[:m_slice.start()] + repr(reversed_val) + src[m_slice.end():]
    # Strip the -join '' immediately after slice if present.
    out = re.sub(r"""'\s*-join\s*['"]{2}""", "'", out)
    return out


# ── Pattern 5b · Regex swap `(\\w+)\\.(\\w+)` → `$2.$1` ────────────────────
_REGEX_SWAP_RE = re.compile(
    r"""['"]([^'"\r\n]{2,256})['"]"""            # literal string
    r"""\s*-replace\s*"""                          # -replace
    r"""['"]"""
    r"""\(([^)]+)\)\\\.\(([^)]+)\)"""            # (grp1)\.(grp2)
    r"""['"]"""
    r"""\s*,\s*['"]\$2\.\$1['"]""",              # → '$2.$1'
    re.IGNORECASE,
)


@op("powershell-reverse-regex-swap",
    "PowerShell regex swap `(\\w+)\\.(\\w+)` → `$2.$1`",
    "Malware Loaders",
    "Decodes the `-replace '(\\w+)\\.(\\w+)','$2.$1'` obfuscation. Swaps the "
    "two token groups deterministically so `'exe.calc' -replace ...` → "
    "'calc.exe'. Handles the common variant chained with [-1..-N] reverse.")
def op_powershell_reverse_regex_swap(data: str, args: Dict[str, Any] | None = None) -> str:
    src = data or ""
    m = _REGEX_SWAP_RE.search(src)
    if not m:
        return "(powershell-reverse-regex-swap · no -replace '(\\w+)\\.(\\w+)','$2.$1' pattern)"

    literal = m.group(1)
    parts = literal.split(".")
    if len(parts) < 2:
        return f"(powershell-reverse-regex-swap · literal '{literal}' has no dot to swap)"
    # Swap FIRST two dot-separated tokens (PS $2.$1 semantics — the group is greedy \w+).
    swapped = ".".join([parts[1], parts[0]] + parts[2:])
    out = src[:m.start()] + f"'{swapped}'" + src[m.end():]
    return out
