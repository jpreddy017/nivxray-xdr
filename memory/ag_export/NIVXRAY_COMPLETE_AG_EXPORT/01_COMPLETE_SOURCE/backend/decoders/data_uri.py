"""RFC 2397 `data:` URI unwrapper.

Extracts the payload from strings like:

    data:text/html;base64,PGh0bWw+PHNjcmlwdD4uLi4=
    data:application/octet-stream;base64,<b64>
    data:text/plain,Hello%20World          (percent-encoded body)

If the URI declares `;base64`, we return the Base64 body so the base64
decoder fires next. If it's a plain body, we percent-decode inline.
"""
from __future__ import annotations

import re
from typing import Any, Dict
from urllib.parse import unquote

from engine.decoder_base import BaseDecoder
from engine.models import (
    AnalysisContext,
    DetectResult,
    Fingerprint,
    MitreHint,
    PluginResult,
)
from engine.registry import DecoderRegistry


_RX_DATA_URI = re.compile(
    r"""data:(?P<mime>[a-zA-Z0-9.+/\-]+)?(?:;(?P<charset>charset=[^;,]+))?(?P<b64>;base64)?,(?P<body>[^"'\s<>]+)""",
    re.IGNORECASE,
)


class DataUriDecoder(BaseDecoder):
    id = "data-uri-extract"
    name = "Data URI Extract"
    category = "reconstruct"
    cost = 1
    tags = ("data-uri", "rfc-2397", "wrapper")
    schema_version = "1.0"

    def detect(self, payload: str, fp: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        if not payload or "data:" not in payload:
            return DetectResult(confidence=0.0, why="No data: URI prefix")
        m = _RX_DATA_URI.search(payload)
        if not m:
            return DetectResult(confidence=0.0, why="No RFC-2397 data: URI matched")
        return DetectResult(
            confidence=0.9,
            why=f"data: URI matched (mime={m.group('mime') or '?'}, "
                f"base64={bool(m.group('b64'))})",
            args={"is_base64": bool(m.group("b64")), "mime": m.group("mime") or ""},
        )

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        m = _RX_DATA_URI.search(payload)
        if not m:
            return PluginResult(output=payload, notes=["data-uri: no match at decode"])
        body = m.group("body")
        mime = m.group("mime") or "text/plain"
        if m.group("b64"):
            return PluginResult(
                output=body,
                notes=[f"Extracted Base64 body from data:{mime};base64, URI"],
                mitre_hints=[
                    MitreHint(
                        id="T1027", technique="Obfuscated Files or Information",
                        tactic="Defense Evasion",
                        evidence="RFC-2397 data: URI carrying Base64 payload",
                        source="archetype",
                    ),
                ],
                explanation=f"Peeled `data:{mime};base64,` wrapper; inner is Base64.",
            )
        try:
            decoded = unquote(body)
        except Exception:
            decoded = body
        return PluginResult(
            output=decoded,
            notes=[f"Percent-decoded body from data:{mime}, URI"],
            explanation=f"Peeled `data:{mime},` wrapper; body was percent-encoded plaintext.",
        )


DecoderRegistry.register(DataUriDecoder())
