"""NivXRay — Known base64/binary signatures for auto-chain detection.

Curated from Sophos, Mandiant, and CISA malicious-PowerShell teardowns.
Given a base64 prefix (or a decoded byte-header), returns the OPTIMAL
follow-up chain so magic-decode / smart-decode can auto-apply it.

Reference:
- https://community.sophos.com/sophos-labs/b/blog/posts/decoding-malicious-powershell
- MITRE ATT&CK T1027 (Obfuscated Files or Information)
"""
from __future__ import annotations
import re
from typing import Dict, List, Optional, Tuple

# --- Known base64 prefixes → recommended follow-on op chain ------------------
# Each entry: prefix_regex, chain (list of op ids), description, MITRE
B64_PREFIX_SIGNATURES: List[Dict] = [
    {
        "prefix": r"^H4sI",
        "chain":  ["base64-decode", "gzip-decompress"],
        "desc":   "gzip magic (0x1f8b) — base64→gzip",
        "mitre":  ["T1027.010"],
    },
    {
        "prefix": r"^e[AFJN]",
        "chain":  ["zlib-decompress"],
        "desc":   "zlib deflate stream (0x78 xx) — base64-wrapped zlib",
        "mitre":  ["T1027.010"],
    },
    {
        "prefix": r"^/Td6WFo",
        "chain":  ["lzma-decompress"],
        "desc":   "LZMA/XZ magic (0xfd 7z XZ 0x00) — base64-wrapped LZMA",
        "mitre":  ["T1027.010"],
    },
    {
        "prefix": r"^QlpoO",
        "chain":  ["bzip2-decompress"],
        "desc":   "bzip2 magic (BZh) — base64-wrapped bzip2",
        "mitre":  ["T1027.010"],
    },
    {
        "prefix": r"^JAB",
        "chain":  ["base64-decode", "utf16le-decode"],
        "desc":   "PowerShell `$` variable declaration (UTF-16LE) — base64→utf16le",
        "mitre":  ["T1059.001"],
    },
    {
        "prefix": r"^SQBFAF",
        "chain":  ["base64-decode", "utf16le-decode"],
        "desc":   "PowerShell 'IEX' (Invoke-Expression, UTF-16LE) — base64→utf16le",
        "mitre":  ["T1059.001"],
    },
    {
        "prefix": r"^SQBuAH",
        "chain":  ["base64-decode", "utf16le-decode"],
        "desc":   "PowerShell 'In' (Invoke-*, UTF-16LE) — base64→utf16le",
        "mitre":  ["T1059.001"],
    },
    {
        "prefix": r"^SUVY",
        "chain":  ["base64-decode"],
        "desc":   "PowerShell 'IEX' (ASCII) — base64",
        "mitre":  ["T1059.001"],
    },
    {
        "prefix": r"^aWV4",
        "chain":  ["base64-decode"],
        "desc":   "PowerShell 'iex' (ASCII) — base64",
        "mitre":  ["T1059.001"],
    },
    {
        "prefix": r"^TVq",
        "chain":  ["base64-decode"],
        "desc":   "PE header 'MZ' (Windows EXE/DLL) — base64",
        "mitre":  ["T1027.002"],
    },
    {
        "prefix": r"^UEsD",
        "chain":  ["base64-decode"],
        "desc":   "ZIP archive 'PK\\x03\\x04' — base64",
        "mitre":  ["T1027.010"],
    },
    {
        "prefix": r"^PA[BA]",
        "chain":  ["base64-decode", "utf16le-decode"],
        "desc":   "HTML/XML '<' (UTF-16LE, common in Emotet stagers) — base64→utf16le",
        "mitre":  ["T1027", "T1059.001"],
    },
    {
        "prefix": r"^dmFy",
        "chain":  ["base64-decode"],
        "desc":   "JavaScript 'var' — base64",
        "mitre":  ["T1059.007"],
    },
    {
        "prefix": r"^dgBhA",
        "chain":  ["base64-decode", "utf16le-decode"],
        "desc":   "JavaScript 'va' (UTF-16LE) — base64→utf16le",
        "mitre":  ["T1059.007"],
    },
    {
        "prefix": r"^JVBER",
        "chain":  ["base64-decode"],
        "desc":   "PDF header '%PDF-' — base64",
        "mitre":  ["T1027.002"],
    },
    {
        "prefix": r"^f0VMRg",
        "chain":  ["base64-decode"],
        "desc":   "ELF header '\\x7fELF' — base64",
        "mitre":  ["T1027.002"],
    },
    {
        "prefix": r"^iVBOR",
        "chain":  ["base64-decode"],
        "desc":   "PNG image header — base64",
        "mitre":  ["T1027"],
    },
]


def match_b64_signature(b64_payload: str) -> Optional[Dict]:
    """Return the first matching signature for a base64 payload, or None."""
    s = b64_payload.strip()
    if not s or len(s) < 4:
        return None
    for sig in B64_PREFIX_SIGNATURES:
        if re.match(sig["prefix"], s):
            return sig
    return None


# --- XOR loop detection in PowerShell / Bash / C ---------------------------
# Common obfuscation pattern from Sophos article:
#   for ($x=0; $x-lt$var_code.Count; $x++) { $var_code[$x] = $var_code[$x] -bxor 35 }
_XOR_LOOP_PATTERNS = [
    # PowerShell -bxor with a literal integer key
    re.compile(r"-bxor\s+(\d{1,3})\b", re.IGNORECASE),
    # C/C++/JS bitwise xor with literal
    re.compile(r"\^\s*(0x[0-9a-fA-F]{1,2}|\d{1,3})\b"),
    # Bash printf | xxd | xor style — very rare, harder to pin down
]


def detect_xor_key(text: str) -> Optional[int]:
    """Sniff a single-byte XOR key from a text-form deobfuscator loop.

    Returns the integer key (0-255) or None if no clear match.
    """
    for pat in _XOR_LOOP_PATTERNS:
        m = pat.search(text)
        if not m:
            continue
        raw = m.group(1)
        try:
            n = int(raw, 16) if raw.lower().startswith("0x") else int(raw)
        except ValueError:
            continue
        if 0 <= n <= 255:
            return n
    return None
