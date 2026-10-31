"""Stage 6 · Recursive Decoder.

Consumes the `DiscoveredArtifactRef` list from Stage 5 and recursively
decodes those artefacts that require decoding
(`encoded_command`, `base64_blob`, `pe_header`). Every layer produces
`DecodedLayer` records so provenance chains survive into the graph.

Deterministic. Bounded (max 8 layers, max 128 artefacts) to prevent
adversarial payload attacks.
"""
from __future__ import annotations

import base64
import re
import zlib
from dataclasses import dataclass, field
from typing import List, Optional

from .artifact_discovery import DiscoveredArtifactRef


@dataclass(frozen=True)
class DecodedLayer:
    """Result of one decoding step."""
    parent_event_id: str
    parent_value: str        # what was decoded
    layer_index: int
    scheme: str              # base64 | b64_utf16le | b64_gzip | raw
    output: str              # decoded string
    confidence: float


DECODE_LAYERS_MAX = 8
DECODE_ARTIFACTS_MAX = 128


def decode(artifacts: List[DiscoveredArtifactRef]) -> List[DecodedLayer]:
    """Decode every artefact that requires decoding, recursively."""
    out: List[DecodedLayer] = []
    queue: List[tuple] = []  # (event_id, value, depth)
    seen: set = set()
    count = 0
    for art in artifacts:
        if art.kind in ("encoded_command", "base64_blob", "pe_header"):
            queue.append((art.event_id, art.value, 0))
        elif art.kind == "command_line" and _looks_encoded(art.value):
            b64 = _extract_b64(art.value)
            if b64:
                queue.append((art.event_id, b64, 0))

    while queue and count < DECODE_ARTIFACTS_MAX:
        event_id, value, depth = queue.pop(0)
        key = (event_id, value[:120])
        if key in seen:
            continue
        seen.add(key)
        count += 1
        decoded = _try_decode(value)
        if not decoded:
            continue
        scheme, text = decoded
        out.append(DecodedLayer(
            parent_event_id=event_id,
            parent_value=value[:200],
            layer_index=depth,
            scheme=scheme,
            output=text[:8000],
            confidence=0.85,
        ))
        if depth + 1 >= DECODE_LAYERS_MAX:
            continue
        # If the decoded output still contains base64, recurse.
        nested = _extract_b64(text)
        if nested and nested != value:
            queue.append((event_id, nested, depth + 1))

    return out


_B64_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")


def _looks_encoded(cmd: str) -> bool:
    if not cmd:
        return False
    return bool(re.search(r"-e(?:nc(?:od(?:ed(?:command)?)?)?)?", cmd,
                          re.IGNORECASE))


def _extract_b64(s: str) -> Optional[str]:
    m = _B64_RE.search(s or "")
    return m.group(0) if m else None


def _try_decode(v: str) -> Optional[tuple]:
    if not v:
        return None
    try:
        raw = base64.b64decode(v, validate=False)
    except (base64.binascii.Error, ValueError):
        return None
    if not raw:
        return None
    # Try gzip / zlib first
    if len(raw) > 2 and raw[:2] in (b"\x1f\x8b", b"\x78\x9c", b"\x78\xda"):
        try:
            inflated = zlib.decompress(raw, 47 if raw[:2] == b"\x1f\x8b" else 15)
            text = _decode_text(inflated)
            if text:
                return ("b64_gzip", text)
        except zlib.error:
            pass
    # UTF-16LE (PowerShell -EncodedCommand default)
    try:
        text = raw.decode("utf-16le", errors="ignore")
        if _is_printable(text):
            return ("b64_utf16le", text)
    except UnicodeDecodeError:
        pass
    # UTF-8
    text = _decode_text(raw)
    if text:
        return ("base64", text)
    return None


def _decode_text(raw: bytes) -> Optional[str]:
    for enc in ("utf-8", "utf-16le", "latin-1"):
        try:
            text = raw.decode(enc)
            if _is_printable(text):
                return text
        except UnicodeDecodeError:
            continue
    return None


def _is_printable(text: str, threshold: float = 0.85) -> bool:
    if not text:
        return False
    ok = sum(1 for c in text[:256] if c.isprintable() or c in "\n\r\t")
    return ok / max(1, min(256, len(text))) >= threshold


__all__ = ["DecodedLayer", "decode",
           "DECODE_LAYERS_MAX", "DECODE_ARTIFACTS_MAX"]
