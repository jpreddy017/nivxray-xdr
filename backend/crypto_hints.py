"""crypto_hints — deterministic key / IV recovery from a single artifact.

Contract
--------
* SCAN A SINGLE STRING ONLY. Never cross-request, never brute-force, never
  guess. If the analyst didn't put the key next to the ciphertext, we
  return an empty list.
* Precision-first: regexes only accept structurally-plausible key literals
  (quoted string, hex/base64 blob, byte array), and we still validate the
  produced plaintext downstream via a ≥ 70 %-printable check.

Public entrypoints
------------------
`extract_key_candidates(text)`  → list[bytes]        · ordered by regex priority
`extract_iv_candidates(text)`   → list[bytes]        · 16-byte IVs only
`extract_ciphertext_blob(text)` → bytes | None       · longest b64/hex substring
`detect_encryption_shape(text)` → dict | None
    Structural detector — returns {"algorithms": …, "byte_len": …,
    "why": …} when the payload's raw byte shape matches an AES / RC4
    ciphertext, even if we can't decrypt it.
"""
from __future__ import annotations

import base64
import binascii
import re
from typing import List, Optional, Dict, Tuple


# ── Key literal patterns (scan a SINGLE artifact only) ───────────────────
_KEY_RX: Tuple[re.Pattern, ...] = tuple(
    re.compile(p, re.IGNORECASE) for p in (
        # $key = "literal" / $k='literal' / password="…" / rc4Key="…" etc.
        r"""(?:\$?(?:key|k|passphrase|secret|password|passwd|rc4[-_]?key|"""
        r"""aes[-_]?key))\s*[:=]\s*['"]([^'"]{6,128})['"]""",
        # key: BASE64BLOB   (no quotes — long-form comment/docs)
        r"""(?:key|passphrase|secret)\s*[:=]\s*([A-Za-z0-9+/=]{16,88})\b""",
        # PowerShell byte array: [byte[]]$k = 0x41,0x42,…
        r"""(?:\$?key|\$?k)\s*[:=]\s*@?\(?\s*"""
        r"""((?:0x[0-9a-fA-F]{2}\s*,?\s*){8,64})""",
    )
)

_IV_RX = re.compile(
    r"""(?:\$?iv|initialization[-_ ]?vector)\s*[:=]\s*['"]([^'"]{6,64})['"]""",
    re.IGNORECASE,
)


def _decode_maybe(s: str) -> List[bytes]:
    """Return every plausible byte interpretation of `s`:
    * as UTF-8 bytes,
    * as hex-decoded bytes (if hex-shaped),
    * as base64-decoded bytes (if b64-shaped).
    """
    out: List[bytes] = []
    seen: set = set()

    def _push(b):
        if b and b not in seen:
            seen.add(b)
            out.append(b)

    _push(s.encode())
    stripped = re.sub(r"\s+", "", s)
    if stripped and all(c in "0123456789abcdefABCDEF" for c in stripped) \
            and len(stripped) % 2 == 0:
        try:
            _push(bytes.fromhex(stripped))
        except ValueError:
            pass
    if stripped:
        try:
            pad = "=" * (-len(stripped) % 4)
            _push(base64.b64decode(stripped + pad, validate=False))
        except (binascii.Error, ValueError):
            pass
    return out


def extract_key_candidates(text: str) -> List[bytes]:
    """Return key candidates in regex-priority order. NEVER brute-force."""
    if not text:
        return []
    out: List[bytes] = []
    seen: set = set()

    def _push(k: bytes) -> None:
        if k and k not in seen:
            seen.add(k)
            out.append(k)

    for rx in _KEY_RX:
        for m in rx.finditer(text):
            cand = m.group(1)
            for b in _decode_maybe(cand):
                _push(b)
            # Byte-array style
            if "0x" in cand:
                hexbytes = re.findall(r"0x([0-9a-fA-F]{2})", cand)
                if hexbytes:
                    try:
                        _push(bytes.fromhex("".join(hexbytes)))
                    except ValueError:
                        pass
    return out


def extract_iv_candidates(text: str) -> List[bytes]:
    """Return 16-byte IV candidates from a single artifact."""
    if not text:
        return []
    out: List[bytes] = []
    seen: set = set()
    for m in _IV_RX.finditer(text):
        cand = m.group(1)
        for b in _decode_maybe(cand):
            if len(b) == 16 and b not in seen:
                seen.add(b)
                out.append(b)
    return out


# ── Shape-only structural detector (no key required) ─────────────────────
def _b64_or_hex_to_bytes(s: str) -> Optional[bytes]:
    stripped = re.sub(r"\s+", "", s or "")
    if not stripped:
        return None
    try:
        pad = "=" * (-len(stripped) % 4)
        b = base64.b64decode(stripped + pad, validate=False)
        if b:
            return b
    except (binascii.Error, ValueError):
        pass
    if all(c in "0123456789abcdefABCDEF" for c in stripped) and len(stripped) % 2 == 0:
        try:
            return bytes.fromhex(stripped)
        except ValueError:
            return None
    return None


# ── Ciphertext blob extractor ────────────────────────────────────────────
_B64_BLOB_RX = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_HEX_BLOB_RX = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{48,}(?![0-9a-fA-F])")


def extract_ciphertext_blob(text: str) -> Optional[bytes]:
    """Find the longest b64/hex substring in `text` and return its bytes.

    Rationale: payloads carry the ciphertext INSIDE a wrapper that also
    contains the key literal (e.g. `$key="…"; $ct="AAAA…"`). Treating the
    whole wrapper as base64 obviously fails; we scan for the longest
    plausible blob and decode that.

    Key literals (quoted strings ≤ 64 chars) are excluded by requiring a
    minimum length that far exceeds any human-picked passphrase.
    """
    if not text:
        return None
    best: Optional[bytes] = None
    # 1. Prefer the longest base64 blob (≥ 24 chars ~ 16 bytes)
    for m in _B64_BLOB_RX.finditer(text):
        cand = m.group(0)
        try:
            pad = "=" * (-len(cand) % 4)
            b = base64.b64decode(cand + pad, validate=False)
        except (binascii.Error, ValueError):
            continue
        if b and (best is None or len(b) > len(best)):
            best = b
    if best is not None and len(best) >= 8:
        return best
    # 2. Fall back to the longest hex blob (≥ 48 chars = 24 bytes)
    for m in _HEX_BLOB_RX.finditer(text):
        cand = m.group(0)
        if len(cand) % 2 != 0:
            cand = cand[:-1]
        try:
            b = bytes.fromhex(cand)
        except ValueError:
            continue
        if b and (best is None or len(b) > len(best)):
            best = b
    return best


def _entropy(b: bytes) -> float:
    if not b:
        return 0.0
    from collections import Counter
    import math
    counts = Counter(b)
    total = len(b)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def detect_encryption_shape(text: str) -> Optional[Dict[str, object]]:
    """Return a structural signature when `text` (or the largest b64/hex
    blob inside it) byte-decodes into a ciphertext-shaped blob.
    Does NOT attempt decryption.

    * AES : ≥ 32 raw bytes, aligned to 16, entropy ≥ 6.0
    * RC4 : ≥ 16 raw bytes, ANY alignment, entropy ≥ 5.5
    """
    # First try the whole string; if not decodable, extract the longest
    # embedded ciphertext blob.
    raw = _b64_or_hex_to_bytes(text)
    if raw is None or len(raw) < 16:
        raw = extract_ciphertext_blob(text)
    if raw is None or len(raw) < 16:
        return None
    ent = _entropy(raw)
    algos: List[str] = []
    if len(raw) >= 32 and len(raw) % 16 == 0 and ent >= 6.0:
        algos.append("AES-CBC/ECB")
    if len(raw) >= 16 and ent >= 5.5:
        algos.append("RC4")
    if not algos:
        return None
    return {
        "algorithms":  algos,
        "byte_len":    len(raw),
        "entropy":     round(ent, 3),
        "why": (f"{len(raw)}B raw, entropy {ent:.2f}, "
                f"alignment {'16-block' if len(raw) % 16 == 0 else 'stream'}"),
    }
