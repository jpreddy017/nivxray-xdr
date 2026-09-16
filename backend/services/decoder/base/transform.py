"""Plane-A codec · Byte-array XOR loop (single-byte XOR fold).

Migrated from `services/die/preprocessor/recursive_decoder.py`
under Gate 2D-B3.1 · Family 3.  Byte-for-byte behavioural parity
with the legacy implementation is REQUIRED.

Pattern (canonical Empire / Nishang / Cobalt Strike stager):

    [Byte[]]$var_code = [System.Convert]::FromBase64String('<b64>')
    for ($x = 0; $x -lt $var_code.Count; $x++) {
        $var_code[$x] = $var_code[$x] -bxor <KEY>
    }

The loop syntax is matched loosely to handle whitespace, alternate
variable names, and hex/decimal key notations.

Contract:
    fn(text: str) -> Optional[Tuple[str, Dict[str, Any]]]

Static-only.  No execution.  No network.
"""
from __future__ import annotations

import base64
import binascii
import re
from typing import Any, Dict, List, Optional, Tuple

from ._shared import _shellcode_string_scan


_BYTE_ARRAY_XOR_LOOP_RE = re.compile(
    r"""
    \[\s*Byte\s*\[\s*\]\s*\]\s*
    \$(?P<var>[A-Za-z_][A-Za-z0-9_]*)
    \s*=\s*
    \[\s*(?:System\.)?Convert\s*\]\s*::\s*FromBase64String\s*\(
        \s*['"](?P<b64>[A-Za-z0-9+/=\s]{40,})['"]\s*
    \)\s*;?\s*
    for\s*\(
        \s*\$\w+\s*=\s*0\s*;\s*
        \$\w+\s*-lt\s*\$(?P=var)\.(?:Count|Length)\s*;\s*
        \$\w+\s*\+\+\s*
    \)\s*\{\s*
        \$(?P=var)\s*\[\s*\$\w+\s*\]\s*=\s*
        \$(?P=var)\s*\[\s*\$\w+\s*\]\s*
        -b?xor\s*(?P<key>0[xX][0-9a-fA-F]+|\d{1,3})
    \s*\}?
    """,
    re.IGNORECASE | re.DOTALL | re.VERBOSE,
)


def _shellcode_ascii_strings(buf: bytes, *, min_len: int = 5,
                              max_out: int = 32) -> List[str]:
    """Extract short printable ASCII strings from a byte blob.

    Analysts see the shellcode's textual fabric (User-Agents,
    file paths, function names)."""
    if not buf:
        return []
    out: List[str] = []
    cur: List[str] = []
    for b in buf:
        if 32 <= b < 127:
            cur.append(chr(b))
        else:
            if len(cur) >= min_len:
                out.append("".join(cur))
                if len(out) >= max_out:
                    break
            cur = []
    if cur and len(cur) >= min_len and len(out) < max_out:
        out.append("".join(cur))
    return out


def decode_byte_array_xor_loop(text: str) -> Optional[Tuple[str, Dict[str, Any]]]:
    """Deterministically fold the ``FromBase64String(...) + for(...)-bxor <K>``
    idiom into its recovered bytes.  Terminal Cobalt Strike / Empire /
    Nishang shellcode-stager layer.

    Emits either recovered plaintext (rare — usually not printable)
    or a synthetic printable block that surfaces ASCII-embedded
    IOCs (C2 IPs / URLs / domains / User-Agents / raw strings)
    hidden in the shellcode.  Same ``embedded_iocs`` extraction
    contract as ``decode_gzip_bytes``.
    """
    m = _BYTE_ARRAY_XOR_LOOP_RE.search(text or "")
    if not m:
        return None
    b64 = re.sub(r"\s+", "", m.group("b64"))
    if len(b64) < 40:
        return None
    key_tok = m.group("key")
    try:
        key = int(key_tok, 16) if key_tok.lower().startswith("0x") else int(key_tok)
    except ValueError:
        return None
    if not (0 <= key <= 0xFF):
        return None
    padded = b64 + "=" * (-len(b64) % 4)
    try:
        raw = base64.b64decode(padded, validate=False)
    except (binascii.Error, ValueError):
        return None
    if not raw:
        return None
    decoded = bytes(b ^ key for b in raw)
    iocs = _shellcode_string_scan(decoded)
    strings = _shellcode_ascii_strings(decoded)
    tag_lines: List[str] = [
        f"[byte-array XOR loop decoded · key=0x{key:02X} · "
        f"{len(decoded)} bytes]"
    ]
    if iocs:
        tag_lines.append("  embedded_iocs: " + ", ".join(iocs))
    if strings:
        tag_lines.append("  extracted_strings:")
        for s in strings[:16]:
            tag_lines.append(f"    · {s}")
    tag = "\n".join(tag_lines)
    new_text = text[:m.start()] + tag + text[m.end():]
    return new_text, {
        "encoding":         "byte_array_xor_loop",
        "bytes_in":         len(raw),
        "bytes_out":        len(decoded),
        "xor_key":          key,
        "xor_key_hex":      f"0x{key:02X}",
        "shellcode":        True,
        "embedded_iocs":    iocs,
        "extracted_strings": strings[:16],
    }


__all__ = [
    "decode_byte_array_xor_loop",
    "_BYTE_ARRAY_XOR_LOOP_RE",
    "_shellcode_ascii_strings",
]
