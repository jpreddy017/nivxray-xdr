"""Base64 decoder plugin (standard + url-safe).

Detection strategy
------------------
1. Strip whitespace.
2. Must be ≥ 8 chars and match the base64 alphabet (standard OR url-safe).
3. Length mod 4 gates confidence:
      0 or 2 or 3  → full confidence
      1            → invalid; low confidence
4. Bonus for the payload NOT being all-digits (which is usually decimal).
"""
from __future__ import annotations

import base64 as _b64
import re
from typing import Any, Dict

from engine.decoder_base import BaseDecoder
from engine.models import AnalysisContext, DecodeResult, DetectResult, Fingerprint
from engine.registry import DecoderRegistry

_WS = re.compile(r"\s+")
_STD = re.compile(r"^[A-Za-z0-9+/=]+$")
_URLSAFE = re.compile(r"^[A-Za-z0-9\-_=]+$")
_ANY = re.compile(r"^[A-Za-z0-9+/=\-_]+$")


class Base64Decoder(BaseDecoder):
    id = "base64-decode"
    name = "Base64 Decode"
    category = "encoding"
    cost = 1
    tags = ("base64", "text-to-bytes")
    schema_version = "1.0"

    def detect(self, payload: str, fingerprint: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        s = _WS.sub("", payload or "")
        if len(s) < 8:
            return DetectResult(confidence=0.0, why="Too short for base64")
        if not _ANY.match(s):
            return DetectResult(confidence=0.0, why="Non-base64 characters present")
        mod = len(s) % 4
        if mod == 1:
            return DetectResult(confidence=0.15, why="Length mod 4 == 1 (invalid pad)")
        if not re.search(r"[A-Za-z]", s):
            return DetectResult(confidence=0.30, why="All-digit — could be decimal")
        conf = 0.85
        urlsafe = bool(_URLSAFE.match(s) and not _STD.match(s))
        return DetectResult(
            confidence=conf,
            why=f"Base64 alphabet fit, length mod 4 == {mod}",
            args={"urlsafe": urlsafe},
        )

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> DecodeResult:
        s = _WS.sub("", payload or "")
        pad = (-len(s)) % 4
        notes = []
        if pad:
            notes.append(f"Auto-padded with {pad} '='")
        try:
            if args.get("urlsafe"):
                raw = _b64.urlsafe_b64decode(s + "=" * pad)
            else:
                raw = _b64.b64decode(s + "=" * pad, validate=False)
        except Exception as exc:
            # Recovery: try trimming 1–3 trailing chars (garbled paste)
            for trim in (1, 2, 3):
                try:
                    trimmed = s[:-trim]
                    tpad = (-len(trimmed)) % 4
                    raw = _b64.b64decode(trimmed + "=" * tpad, validate=False)
                    notes.append(f"Recovered by trimming {trim} trailing char(s)")
                    break
                except Exception:
                    continue
            else:
                return DecodeResult(
                    output="",
                    output_is_binary=False,
                    notes=[f"base64 decode failed: {exc}"],
                )
        # Decide binary vs text
        printable = sum(1 for b in raw if 32 <= b < 127 or b in (9, 10, 13))
        is_binary = printable / max(1, len(raw)) < 0.85
        out = raw.decode("latin-1") if is_binary else raw.decode("utf-8", errors="replace")
        return DecodeResult(
            output=out,
            output_is_binary=is_binary,
            notes=notes,
        )


DecoderRegistry.register(Base64Decoder())
