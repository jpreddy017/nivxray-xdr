"""DDO adapter for the migrated Plane-A codecs.

Gate 2D-B3.2 — the codecs migrated in B3.1 have implementations
in `services/decoder/base/*` but their invocation contract is
    fn(text: str) -> Optional[Tuple[str, Dict[str, Any]]]
which differs from the DDO's simple text-in / text-in signature
    fn(text: str) -> Optional[str]

This module wraps each migrated codec with a lightweight
`decoder_only_text(text) -> Optional[str]` adapter that:
    · returns None on no-match (unchanged semantics)
    · returns the reconstructed text otherwise
    · drops the meta dict (DDO reads observability from provenance)

The wrapper adds NO behavioural logic — it exists solely to bridge
signatures so the DDO can signature-dispatch the migrated codecs
alongside the existing text-encoding codecs from B1.

Static-only.  Deterministic.  Bounded.
"""
from __future__ import annotations

from typing import Optional

from .compression import decode_gzip_bytes, decode_zlib_bytes
from .transform import decode_byte_array_xor_loop
from .powershell_encoded_command import decode_ps_encoded_command


def _text_or_none(res):
    """Return only the reconstructed text; drop the meta dict."""
    if res is None:
        return None
    if isinstance(res, tuple) and len(res) >= 1:
        return res[0]
    return res


def ddo_gzip(text: str) -> Optional[str]:
    return _text_or_none(decode_gzip_bytes(text))


def ddo_zlib(text: str) -> Optional[str]:
    return _text_or_none(decode_zlib_bytes(text))


def ddo_byte_array_xor_loop(text: str) -> Optional[str]:
    return _text_or_none(decode_byte_array_xor_loop(text))


def ddo_ps_encoded_command(text: str) -> Optional[str]:
    return _text_or_none(decode_ps_encoded_command(text))


__all__ = [
    "ddo_gzip",
    "ddo_zlib",
    "ddo_byte_array_xor_loop",
    "ddo_ps_encoded_command",
]
