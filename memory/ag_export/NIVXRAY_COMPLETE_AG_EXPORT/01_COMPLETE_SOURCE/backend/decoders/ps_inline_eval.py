"""PowerShell inline-eval decoders (RC4.0 · Feb 2026 · v2).

Two deterministic decoders that eliminate common PowerShell obfuscation
patterns that Google AI can handle but earlier NivXRay versions couldn't:

  1. `powershell-hex-csv-inline` — `$h='43,61,6c,63,2e,65,78,65'; $c = $h -split
     ',' | ForEach-Object {[char][int]('0x'+$_)}; Invoke-Expression ($c -join '')`
     → executes each comma-separated hex byte as an ASCII char.

  2. `powershell-xor-inline-key` — `[byte[]](N,N,N,...); -bxor key[...]` inline
     XOR loop with a hardcoded key extracted from any of:
        * `[System.Text.Encoding]::ASCII.GetBytes('KEY')`
        * `[Text.Encoding]::ASCII.GetBytes('KEY')`
        * `[System.Text.Encoding]::UTF8.GetBytes('KEY')`
        * `$key = (65,66,67,...)`   (integer literal array)
        * `[byte[]](65,66,67,...)` second array in same payload treated as key
                                    when a longer byte-array exists

Both plugins are recipe-only — the orchestrator adds them as candidates when
the input has the PowerShell wrapper + the matching structural markers.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from operations import op


# ── Pattern 1 · comma-separated hex → char → -join ─────────────────────────
_HEX_CSV_RE = re.compile(
    r"""\$\w+\s*=\s*['"]((?:[0-9a-fA-F]{1,2}\s*,\s*){4,}[0-9a-fA-F]{1,2})['"]""",
    re.VERBOSE,
)


@op("powershell-hex-csv-inline",
    "PowerShell inline hex-CSV → char → join",
    "Malware Loaders",
    "Decodes the common `$h='43,61,6c,63,...'; $c = $h -split ',' | ForEach-Object "
    "{[char][int]('0x'+$_)}; iex ($c -join '')` obfuscation. Extracts the hex CSV "
    "literal, converts each byte to ASCII, returns the plaintext command.")
def op_powershell_hex_csv_inline(data: str, args: Dict[str, Any] | None = None) -> str:
    m = _HEX_CSV_RE.search(data or "")
    if not m:
        return "(powershell-hex-csv-inline · no hex-CSV literal found)"
    hex_csv = m.group(1)
    try:
        toks = [t.strip() for t in hex_csv.split(",") if t.strip()]
        out = bytes(int(t, 16) for t in toks).decode("latin-1", errors="replace")
        return out
    except Exception as e:
        return f"(powershell-hex-csv-inline · decode error: {e})"


# ── Pattern 2 · inline byte-array XOR — flexible key + index patterns ──────
#
# Regex explanations:
#   _BYTE_ARRAY_RE  : `[byte[]](N,N,...)` with 3+ ints — the *ciphertext*.
#   _INT_ARRAY_RE   : bare parens `(65,66,67)` (integer array key literal).
#   _BXOR_LOOP_RE   : ANY `-bxor <var>[<idx> % <var>[.Length]]` construct
#                     using any variable names (`$_`, `$i`, `$idx`, `$j`).
#   _ASCII_KEY_RE   : `[[System.]Text.Encoding]::(ASCII|UTF8|Unicode|UTF7)
#                     .GetBytes('KEY')`  — flexible on the class path.
_BYTE_ARRAY_RE = re.compile(
    r"""\[byte\[\]\]\s*\(\s*((?:\d{1,3}\s*,\s*){2,}\d{1,3})\s*\)""",
    re.IGNORECASE,
)
_INT_ARRAY_RE = re.compile(
    r"""\(\s*((?:\d{1,3}\s*,\s*){2,}\d{1,3})\s*\)""",
    re.IGNORECASE,
)
_ASCII_KEY_RE = re.compile(
    r"""\[(?:System\.)?Text\.Encoding\]::(?:ASCII|UTF8|Unicode|UTF7)"""
    r"""\.GetBytes\s*\(\s*['"]([^'"]+)['"]\s*\)""",
    re.IGNORECASE,
)
# Shortcut when analysts type `[Encoding]::ASCII.GetBytes('KEY')`
_ASCII_KEY_SHORT_RE = re.compile(
    r"""\[Encoding\]::(?:ASCII|UTF8|Unicode|UTF7)"""
    r"""\.GetBytes\s*\(\s*['"]([^'"]+)['"]\s*\)""",
    re.IGNORECASE,
)
# `$k = 'PASSWORD'` — simple string-var key assignment (used with .ToCharArray)
_STRING_KEY_ASSIGN_RE = re.compile(
    r"""\$\w+\s*=\s*['"]([A-Za-z0-9_\-!@#$%^&*+=\.]{2,64})['"]""",
    re.IGNORECASE,
)
# `-bxor <var>[<idx> % <var>.Length]`  — any variable names allowed.
# Also accepts `-bxor <var>[<idx>]` with modulo omitted (unrolled loop).
_BXOR_LOOP_RE = re.compile(
    r"-bxor\s+\$?\w+\s*(?:\[\s*\$?\w+\s*(?:%\s*\$?\w+(?:\.Length)?)?\s*\])?",
    re.IGNORECASE,
)


def _extract_int_array(text: str, exclude_span: Optional[Tuple[int, int]] = None) -> Optional[List[int]]:
    """Find the *second* integer-array literal in the payload (the key).

    The FIRST `[byte[]](...)` is the ciphertext; a second bare `(N,N,...)` or
    `[byte[]](...)` in the same script is very frequently the XOR key when
    `[Encoding]::…GetBytes` isn't used.
    """
    for m in _INT_ARRAY_RE.finditer(text):
        if exclude_span and (m.start() >= exclude_span[0] and m.end() <= exclude_span[1]):
            continue
        try:
            toks = [int(t.strip()) for t in m.group(1).split(",") if t.strip()]
            if len(toks) >= 1 and all(0 <= v <= 255 for v in toks):
                return toks
        except Exception:
            continue
    return None


@op("powershell-xor-inline-key",
    "PowerShell inline byte-array XOR with hardcoded key",
    "Malware Loaders",
    "Decodes `[byte[]](N,N,...) -bxor key[i % key.Length]` inline PowerShell "
    "XOR loops where the key comes from `[[System.]Text.Encoding]::(ASCII|UTF8)"
    ".GetBytes('KEY')`, `[Encoding]::ASCII.GetBytes('KEY')`, a bare "
    "`(N,N,N,...)` integer array, or a `$k = 'STRING'` assignment. Recovers "
    "the plaintext command deterministically without executing PowerShell.")
def op_powershell_xor_inline_key(data: str, args: Dict[str, Any] | None = None) -> str:
    src = data or ""

    # Ciphertext bytes — the longest `[byte[]](...)` array wins.
    byte_matches = list(_BYTE_ARRAY_RE.finditer(src))
    if not byte_matches:
        return "(powershell-xor-inline-key · no [byte[]] cipher array found)"
    m_bytes = max(byte_matches, key=lambda m: len(m.group(1)))

    if not _BXOR_LOOP_RE.search(src):
        return "(powershell-xor-inline-key · no -bxor loop found)"

    # Key resolution — try each strategy in order of specificity.
    key_bytes: Optional[bytes] = None
    key_source = ""

    m_ascii = _ASCII_KEY_RE.search(src) or _ASCII_KEY_SHORT_RE.search(src)
    if m_ascii:
        key_bytes = m_ascii.group(1).encode("ascii", errors="replace")
        key_source = "encoding-getbytes"
    else:
        # Look for a *second* integer array in the payload (bare `(N,N,...)`)
        # excluding the ciphertext span.
        alt_key = _extract_int_array(src, exclude_span=(m_bytes.start(), m_bytes.end()))
        if alt_key:
            key_bytes = bytes(alt_key)
            key_source = "integer-array"
        else:
            # Fallback — a `$k = 'STRING'` assignment. Take the FIRST match whose
            # value isn't obviously a URL / long path.
            for m_str in _STRING_KEY_ASSIGN_RE.finditer(src):
                val = m_str.group(1)
                if len(val) <= 64 and not val.startswith(("http", "//", "\\\\", "C:")):
                    key_bytes = val.encode("ascii", errors="replace")
                    key_source = "string-var"
                    break

    if not key_bytes:
        return "(powershell-xor-inline-key · required tokens not found · key resolution failed)"

    try:
        cipher = [int(t.strip()) for t in m_bytes.group(1).split(",") if t.strip()]
        decoded = bytes(
            cipher[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(cipher))
        )
        return decoded.decode("latin-1", errors="replace")
    except Exception as e:
        return f"(powershell-xor-inline-key · decode error: {e})"
