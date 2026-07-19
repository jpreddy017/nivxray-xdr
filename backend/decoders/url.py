"""URL / percent-encoding decoder plugin.

Handles both `%xx` sequences and `+`→space (application/x-www-form-urlencoded).
Only fires when the payload actually contains percent-encoded triplets.
"""
from __future__ import annotations

import re
from typing import Any, Dict
from urllib.parse import unquote_plus

from engine.decoder_base import BaseDecoder
from engine.models import AnalysisContext, DecodeResult, DetectResult, Fingerprint
from engine.registry import DecoderRegistry

_PCT = re.compile(r"%[0-9A-Fa-f]{2}")


class UrlDecoder(BaseDecoder):
    id = "url-decode"
    name = "URL / Percent-Decode"
    category = "encoding"
    cost = 1
    tags = ("url", "percent")
    schema_version = "1.0"

    def detect(self, payload: str, fingerprint: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        if not payload:
            return DetectResult(confidence=0.0, why="Empty payload")
        matches = _PCT.findall(payload)
        if not matches:
            return DetectResult(confidence=0.0, why="No %xx sequences found")
        density = len(matches) / max(1, len(payload) / 3)
        conf = min(0.9, 0.4 + density * 0.5)
        return DetectResult(
            confidence=conf,
            why=f"{len(matches)} percent-encoded triplet(s)",
        )

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> DecodeResult:
        try:
            out = unquote_plus(payload)
        except Exception as exc:
            return DecodeResult(output=payload, notes=[f"url decode failed: {exc}"])
        return DecodeResult(output=out)


DecoderRegistry.register(UrlDecoder())
