"""Base58 decoder (Bitcoin / Solana / IPFS alphabet).

Base58 avoids characters 0/O/I/l to be visually unambiguous. Used by
Bitcoin wallet addresses, Solana keys, IPFS multihashes and some
malware C2 configuration blobs.

Alphabet: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
"""
from __future__ import annotations

import re
from typing import Any, Dict

from engine.decoder_base import BaseDecoder
from engine.models import AnalysisContext, DetectResult, Fingerprint, PluginResult
from engine.registry import DecoderRegistry


_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_ALPHABET_MAP = {c: i for i, c in enumerate(_ALPHABET)}
_RX_B58 = re.compile(r"^[" + re.escape(_ALPHABET) + r"]+$")


def _b58decode(s: str) -> bytes:
    """Reference implementation — not perf-critical."""
    n = 0
    for c in s:
        n = n * 58 + _ALPHABET_MAP[c]
    # Leading '1's are leading zero bytes
    pad = len(s) - len(s.lstrip("1"))
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * pad + raw


class Base58Decoder(BaseDecoder):
    id = "base58-decode"
    name = "Base58 Decode"
    category = "encoding"
    cost = 2                                    # slower than base64 due to big-int math
    tags = ("base58", "bitcoin", "solana", "ipfs")
    schema_version = "1.0"

    def detect(self, payload: str, fp: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        if not payload:
            return DetectResult(confidence=0.0, why="Empty payload")
        s = payload.strip()
        # Base58 blobs are single contiguous alphabet runs — reject prose.
        if not s or any(ch.isspace() for ch in s):
            return DetectResult(confidence=0.0, why="Contains whitespace — not Base58")
        if len(s) < 8:
            return DetectResult(confidence=0.0, why="Too short (< 8 chars)")
        if not _RX_B58.match(s):
            return DetectResult(confidence=0.0, why="Non-Base58 characters present")
        # Confidence stays modest because Base58 shape overlaps Base62 heavily.
        # Boost when the payload matches wallet-address prefixes (1/3/bc1).
        conf = 0.35
        if s[0] in ("1", "3") and 25 <= len(s) <= 35:
            conf = 0.7
        return DetectResult(
            confidence=conf,
            why=f"Base58 alphabet fit, len={len(s)}",
        )

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        s = payload.strip()
        try:
            raw = _b58decode(s)
        except Exception as exc:                       # pragma: no cover
            return PluginResult(output="", notes=[f"base58 decode failed: {exc}"])
        printable = sum(1 for b in raw if 32 <= b < 127 or b in (9, 10, 13))
        is_binary = printable / max(1, len(raw)) < 0.85
        out = raw.decode("latin-1") if is_binary else raw.decode("utf-8", errors="replace")
        return PluginResult(
            output=out,
            output_is_binary=is_binary,
            notes=[f"Decoded {len(raw)} byte(s) from Base58"],
        )


DecoderRegistry.register(Base58Decoder())
