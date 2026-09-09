"""RC4.1 · Deterministic RC4 inline decryptor (Feb 2026).

Detects the classic PowerShell RC4 loader pattern:

    $k = [Text.Encoding]::UTF8.GetBytes('KEY')
    $c = [Convert]::FromBase64String('CIPHER_B64')
    $S = (0..255)
    for ($i=0; $i -lt 256; $i++) { $j = ... }
    for (byte in c) { ... $S[$i] $S[$j] -bxor ... }

When BOTH the key literal and the base64 ciphertext are inline, we can
execute the RC4 KSA/PRGA in Python and emit the recovered plaintext. This
is the ONLY correct behaviour for a deterministic decoder — a runtime
primitive is required in .NET, but the RC4 stream cipher is pure math and
we own the math here.
"""
from __future__ import annotations

import base64
import re
from typing import Any, Dict, Optional

from operations import op


_KEY_UTF8_RE = re.compile(
    r"""\[(?:System\.)?Text\.Encoding\]::(?:UTF8|ASCII|Unicode)\.GetBytes"""
    r"""\s*\(\s*['"]([^'"]+)['"]\s*\)""",
    re.IGNORECASE,
)
_KEY_SHORT_RE = re.compile(
    r"""\[Encoding\]::(?:UTF8|ASCII|Unicode)\.GetBytes\s*\(\s*['"]([^'"]+)['"]\s*\)""",
    re.IGNORECASE,
)
_KEY_STRING_ASSIGN = re.compile(
    r"""\$\w+\s*=\s*['"]([A-Za-z0-9_@!#\$%&*+\-=./:; ]{2,64})['"]""",
    re.IGNORECASE,
)
_B64_CIPHER_RE = re.compile(
    r"""\[Convert\]::FromBase64String\s*\(\s*['"]([A-Za-z0-9+/=]{16,})['"]\s*\)""",
    re.IGNORECASE,
)
# The RC4 signature — KSA (0..255 loop) + PRGA (for loop with -bxor $S[])
_RC4_KSA_SIG   = re.compile(r"""0\s*\.\.\s*255""")
_RC4_PRGA_SIG  = re.compile(r"""-bxor\s+\$S\[\s*\(?\s*\$S\[""", re.IGNORECASE)
_RC4_SIMPLE    = re.compile(r"""(?:rc4|prga|ksa)""", re.IGNORECASE)


def _rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for ch in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) & 0xFF]
        out.append(ch ^ K)
    return bytes(out)


@op("rc4-inline-decrypt",
    "RC4 inline decryption with hardcoded key",
    "Cryptography",
    "Deterministically decrypts a PowerShell RC4 loader when BOTH the key "
    "and base64 ciphertext are inline. Runs the standard RC4 KSA + PRGA in "
    "Python without executing PowerShell — recovers the plaintext command "
    "line for tools like Empire, Nishang, and Metasploit PS payloads.")
def op_rc4_inline_decrypt(data: str, args: Dict[str, Any] | None = None) -> str:
    src = data or ""
    if not (_RC4_KSA_SIG.search(src) and (_RC4_PRGA_SIG.search(src) or "-bxor" in src.lower())):
        return "(rc4-inline-decrypt · no RC4 KSA/PRGA signature)"

    # Locate the ciphertext — base64 literal wrapped in FromBase64String.
    m_c = _B64_CIPHER_RE.search(src)
    if not m_c:
        return "(rc4-inline-decrypt · no [Convert]::FromBase64String literal)"
    try:
        cipher = base64.b64decode(m_c.group(1))
    except Exception as e:
        return f"(rc4-inline-decrypt · base64 decode error: {e})"

    # Locate the key. Preference order:
    #   1. [Encoding]::UTF8.GetBytes('literal')
    #   2. [Text.Encoding]::UTF8.GetBytes('literal')
    #   3. $k = 'literal' assignment (first plausible short literal)
    key_bytes: Optional[bytes] = None
    for regex in (_KEY_UTF8_RE, _KEY_SHORT_RE):
        m = regex.search(src)
        if m:
            key_bytes = m.group(1).encode("utf-8")
            break
    if key_bytes is None:
        for m in _KEY_STRING_ASSIGN.finditer(src):
            val = m.group(1)
            # Skip URLs, base64 literals, obviously-cipher literals.
            if len(val) <= 64 and not val.startswith(("http", "//", "\\\\", "C:")):
                key_bytes = val.encode("utf-8")
                break
    if key_bytes is None:
        return "(rc4-inline-decrypt · no key literal found)"

    try:
        plain = _rc4(key_bytes, cipher)
        # UTF-8 first, fall back to Latin-1 for shellcode-ish content.
        try:
            return plain.decode("utf-8")
        except UnicodeDecodeError:
            return plain.decode("latin-1", errors="replace")
    except Exception as e:
        return f"(rc4-inline-decrypt · rc4 error: {e})"
