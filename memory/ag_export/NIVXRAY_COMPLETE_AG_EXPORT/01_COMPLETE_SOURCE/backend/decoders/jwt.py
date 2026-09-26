"""JWT (JSON Web Token) decoder.

JWT format: `<header>.<payload>.<signature>` where each part is URL-safe
Base64 without padding. Header + payload are JSON; signature is raw bytes.

We surface the JSON header + payload as decoded output so downstream IOC
and family plugins can scan claim values (issuer, subject, custom claims
often carry C2 URLs / tokens in supply-chain malware).
"""
from __future__ import annotations

import base64 as _b64
import json
import re
from typing import Any, Dict

from engine.decoder_base import BaseDecoder
from engine.models import (
    AnalysisContext,
    DetectResult,
    Fingerprint,
    MitreHint,
    PluginResult,
)
from engine.registry import DecoderRegistry


_RX_JWT = re.compile(
    r"""^[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*$"""
)


def _b64url_decode(s: str) -> bytes:
    s = s + "=" * ((-len(s)) % 4)
    return _b64.urlsafe_b64decode(s)


class JwtDecoder(BaseDecoder):
    id = "jwt-decode"
    name = "JWT Decode"
    category = "encoding"
    cost = 1
    tags = ("jwt", "json", "token", "auth")
    schema_version = "1.0"

    def detect(self, payload: str, fp: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        if not payload:
            return DetectResult(confidence=0.0, why="Empty payload")
        s = payload.strip()
        if not _RX_JWT.match(s):
            return DetectResult(confidence=0.0, why="Not a JWT shape")
        try:
            head_raw = _b64url_decode(s.split(".", 1)[0])
            head = json.loads(head_raw)
        except Exception:
            return DetectResult(confidence=0.1, why="JWT shape but header not JSON")
        if not isinstance(head, dict) or "alg" not in head:
            return DetectResult(confidence=0.1, why="JWT shape but no 'alg' in header")
        return DetectResult(
            confidence=0.95,
            why=f"JWT header decoded, alg={head.get('alg')}",
            args={"alg": head.get("alg", "?"), "typ": head.get("typ", "?")},
        )

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        s = payload.strip()
        parts = s.split(".")
        if len(parts) != 3:
            return PluginResult(output=payload, notes=["jwt: not 3 parts at decode"])
        try:
            head = json.loads(_b64url_decode(parts[0]))
            body = json.loads(_b64url_decode(parts[1]))
        except Exception as exc:
            return PluginResult(output="", notes=[f"jwt decode failed: {exc}"])
        alg = str(head.get("alg", "unknown"))
        pretty = (
            f"# JWT decoded\nheader = {json.dumps(head, indent=2, ensure_ascii=False)}\n"
            f"payload = {json.dumps(body, indent=2, ensure_ascii=False)}\n"
        )
        mitre = []
        if alg.lower() in ("none", ""):
            mitre.append(MitreHint(
                id="T1550.001",
                technique="Application Access Token",
                tactic="Defense Evasion",
                evidence="JWT with alg=none — signature bypass",
                source="heuristic",
            ))
        return PluginResult(
            output=pretty,
            notes=[f"Decoded JWT (alg={alg})"],
            mitre_hints=mitre,
            explanation=(
                f"Decoded JWT with alg={alg}; header and payload printed as JSON."
            ),
        )


DecoderRegistry.register(JwtDecoder())
