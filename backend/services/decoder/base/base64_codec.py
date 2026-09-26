"""Plane-A codec sub-engine · P0-1B Gate 2D ·

Scope of Gate 2D-A (this file):
  · base64_decode_literal   — deterministic Base64 string decoder
                              for use by higher-level fold callers.

Scope of Gate 2D-B (later this gate — or a follow-up):
  · migration of existing codec logic from
    `services/die/preprocessor/recursive_decoder` INTO this module
    (URL-decode · Unicode escapes · HTML entities · Base32 · Base85
    · Octal/Decimal ASCII · Hex · UTF-16 · GZIP · Zlib · XOR · RC4
    · AES · PE · shellcode)
  · deterministic bounded classifier (`.classifier.Classifier`) that
    orchestrates candidate transforms per input signature.

Owner-locked rule (P0_1B_SCOPE.md): the classifier must be
DETERMINISTIC, BOUNDED and PROVENANCE-BEARING. It MUST NOT emit
speculative attempts the way CyberChef's "Magic" would.

Static invariants (verified structurally by Provenance):
  · static_only=True
  · execution=False
  · attck_promotion=False
  · DECODED ≠ EXECUTED
  · no network access
  · no external runtime
"""
from __future__ import annotations

import base64
import binascii
import re
from typing import Optional

from ..types import (
    Capability, CapabilityKind, DecodedLayer, Provenance,
    ReconstructionResult, now_iso,
)
from ..registry import CapabilityRegistry


ENGINE_VERSION = "0.4.0-gate2d"


# ══════════════════════════════════════════════════════════════════
# Deterministic Base64 codec
# ══════════════════════════════════════════════════════════════════
_B64_STRICT_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


def is_valid_base64(text: str, min_len: int = 8) -> bool:
    """Deterministic strict Base64 check.  Rejects short strings
    (may collide with English words), URL-safe variants (handled
    elsewhere), and non-length-of-4 strings."""
    text = text.strip()
    if len(text) < min_len or (len(text) % 4) != 0:
        return False
    if not _B64_STRICT_RE.match(text):
        return False
    try:
        base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return False
    return True


def decode_base64(text: str) -> Optional[bytes]:
    """Strict Base64 decode. Returns raw bytes or None."""
    if not is_valid_base64(text):
        return None
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None


def decode_base64_as_string(text: str,
                            encodings: tuple = ("utf-8", "utf-16-le", "latin-1")
                           ) -> Optional[str]:
    """Try to decode Base64 to a printable string. Deterministic
    encoding order — never guesses via heuristic scores."""
    raw = decode_base64(text)
    if raw is None:
        return None
    for enc in encodings:
        try:
            out = raw.decode(enc)
        except UnicodeDecodeError:
            continue
        # Reject if the decoded string is mostly non-printable — the
        # source may have been ciphertext / shellcode / random.
        printable = sum(1 for ch in out
                       if ch.isprintable() or ch in ("\n", "\r", "\t"))
        if len(out) > 0 and (printable / len(out)) > 0.85:
            return out
    return None


# ══════════════════════════════════════════════════════════════════
# Capabilities & registration
# ══════════════════════════════════════════════════════════════════
_CAPS: dict[str, Capability] = {
    "base.b64_literal_decode": Capability(
        name        = "base.b64_literal_decode",
        kind        = CapabilityKind.DECODER,
        language    = "generic",
        version     = "0.1.0",
        description = "Deterministic Base64 string decoder. Rejects "
                      "non-length-of-4 / non-printable / short strings. "
                      "Static-only.",
    ),
}


def _run_base_b64_literal(raw: str,
                         parent_id: str,
                         layer_index: int) -> Optional[DecodedLayer]:
    """Wraps `decode_base64_as_string` with a DecodedLayer envelope."""
    decoded = decode_base64_as_string(raw)
    if decoded is None or decoded == raw:
        return None
    cap = _CAPS["base.b64_literal_decode"]
    return DecodedLayer(
        layer_index    = layer_index,
        stage          = "base.b64_literal_decode",
        language       = "generic",
        bytes_in       = len(raw),
        bytes_out      = len(decoded),
        input_preview  = raw[:64],
        output         = decoded,
        capability     = cap,
        provenance     = Provenance(
            decoded_from    = parent_id,
            capability_name = cap.name,
            engine_version  = ENGINE_VERSION,
            recorded_at     = now_iso(),
        ),
        confidence     = "HIGH",
        notes          = f"base64 → {len(decoded)}-byte string",
    )


def register_all(registry: CapabilityRegistry) -> None:
    if registry.get("base.b64_literal_decode") is not None:
        return
    registry.register(_CAPS["base.b64_literal_decode"], _run_base_b64_literal)


__all__ = [
    "is_valid_base64", "decode_base64", "decode_base64_as_string",
    "register_all", "_run_base_b64_literal",
]
