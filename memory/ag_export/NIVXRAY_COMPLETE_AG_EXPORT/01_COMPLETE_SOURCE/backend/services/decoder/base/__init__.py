"""Plane-A codec sub-engine architecture · Gate 2D-B1 scaffolding.

Sub-modules:
  · encoding   — text/character encodings   (delivered · Gate 2D-B1)
  · compression — GZIP/Zlib/Deflate         (Gate 2D-B2)
  · transform  — reverse / hex-strings      (Gate 2D-B2)
  · crypto     — XOR / RC4 / AES / DES      (Gate 2D-B2)

Every codec MUST:
  · be deterministic (same input → same output)
  · declare kind=CapabilityKind.DECODER (structural allow-list)
  · fold ONLY on a valid signature (no speculative decoding)
  · reject non-printable / high-entropy garbage output
"""
from . import encoding as _encoding
from .encoding import (
    register_all as _register_encoding,
    decode_url, decode_unicode_escape, decode_html_entities,
    decode_base32, decode_base85, decode_octal_ascii,
    decode_decimal_ascii,
)
from .base64_codec import (
    decode_base64, decode_base64_as_string, is_valid_base64,
    register_all as _register_base64,
)

from ..registry import CapabilityRegistry


def register_all(registry: CapabilityRegistry) -> None:
    """Register every base sub-module's capabilities. Idempotent."""
    _register_encoding(registry)
    _register_base64(registry)


__all__ = [
    "_encoding", "register_all",
    "decode_base64", "decode_base64_as_string", "is_valid_base64",
    "decode_url", "decode_unicode_escape", "decode_html_entities",
    "decode_base32", "decode_base85",
    "decode_octal_ascii", "decode_decimal_ascii",
]
