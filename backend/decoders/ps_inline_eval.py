"""PowerShell inline-eval decoders (RC4.0 · Feb 2026).

Two new deterministic decoders that eliminate common PowerShell obfuscation
patterns Google AI can handle but we couldn't:

  1. `powershell-hex-csv-inline` — `$h='43,61,6c,63,2e,65,78,65'; $c = $h -split
     ',' | ForEach-Object {[char][int]('0x'+$_)}; Invoke-Expression ($c -join '')`
     → executes each comma-separated hex byte as an ASCII char.

  2. `powershell-xor-inline-key` — `[byte[]](N,N,N,...); -bxor key[i%len]` inline
     XOR loop with a hardcoded key extracted from `[Encoding]::ASCII.GetBytes('KEY')`.

Both plugins are recipe-only — the orchestrator adds them as candidates when the
input has the PowerShell wrapper + the matching structural markers.
"""
from __future__ import annotations

import re
from typing import Any, Dict

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


# ── Pattern 2 · inline byte-array XOR with `KEY` ────────────────────────────
_BYTE_ARRAY_RE = re.compile(
    r"""\[byte\[\]\]\s*\(\s*((?:\d{1,3}\s*,\s*)+\d{1,3})\s*\)""",
    re.IGNORECASE,
)
_ASCII_KEY_RE = re.compile(
    r"""\[System\.Text\.Encoding\]::ASCII\.GetBytes\(\s*['"]([^'"]+)['"]\s*\)""",
    re.IGNORECASE,
)
_BXOR_LOOP_RE = re.compile(
    r"-bxor\s+\$?\w+\[\$?i\s*%\s*\$?\w+\.Length\]", re.IGNORECASE,
)


@op("powershell-xor-inline-key",
    "PowerShell inline byte-array XOR with hardcoded key",
    "Malware Loaders",
    "Decodes `[byte[]](N,N,...) -bxor key[i % key.Length]` inline PowerShell "
    "XOR loops where the key is extracted from "
    "`[Encoding]::ASCII.GetBytes('KEY')` — recovers the plaintext command "
    "deterministically without executing PowerShell.")
def op_powershell_xor_inline_key(data: str, args: Dict[str, Any] | None = None) -> str:
    src = data or ""
    m_bytes = _BYTE_ARRAY_RE.search(src)
    m_key   = _ASCII_KEY_RE.search(src)
    if not (m_bytes and m_key and _BXOR_LOOP_RE.search(src)):
        return "(powershell-xor-inline-key · required tokens not found)"
    try:
        bytes_arr = [int(t.strip()) for t in m_bytes.group(1).split(",") if t.strip()]
        key = m_key.group(1).encode("ascii", errors="replace")
        if not key:
            return "(powershell-xor-inline-key · empty key)"
        decoded = bytes(bytes_arr[i] ^ key[i % len(key)] for i in range(len(bytes_arr)))
        return decoded.decode("latin-1", errors="replace")
    except Exception as e:
        return f"(powershell-xor-inline-key · decode error: {e})"
