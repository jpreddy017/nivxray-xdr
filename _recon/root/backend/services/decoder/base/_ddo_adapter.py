"""DDO adapter for the migrated Plane-A codecs.

Gate 2D-B3.2 (+ B3.2-A completion correction) — the codecs
migrated in B3.1 have implementations in `services/decoder/base/*`
but their invocation contract differs from the DDO's simple
text-in / text-out signature.  This module wraps each migrated
codec with a lightweight `Optional[str]` adapter.

Adapters cover ALL 7 migrated Plane-A codec families:

    ddo_gzip                    → services.decoder.base.compression
    ddo_zlib                    → services.decoder.base.compression
    ddo_byte_array_xor_loop     → services.decoder.base.transform
    ddo_ps_encoded_command      → services.decoder.base.powershell_encoded_command
    ddo_xor_brute               → services.decoder.base.xor_brute        (B3.2-A)
    ddo_rc4                     → services.decoder.base.crypto           (B3.2-A)
    ddo_aes_cbc                 → services.decoder.base.crypto           (B3.2-A)

Wrappers add NO behavioural logic — they exist solely to bridge
signatures so the DDO can signature-dispatch the migrated codecs
alongside the existing text-encoding codecs from B1.  They call
ONLY the already-migrated authoritative implementations under
`services.decoder.base.*` — never the legacy paths.

Static-only.  Deterministic.  Bounded.
"""
from __future__ import annotations

from typing import Optional

from .compression import decode_gzip_bytes, decode_zlib_bytes
from .transform import decode_byte_array_xor_loop
from .powershell_encoded_command import decode_ps_encoded_command
# B3.2-A: repeating-XOR + RC4 + AES-CBC — authoritative impls at
# services.decoder.base.{xor_brute,crypto} (migrated in B3.1).
from .xor_brute import XorBruteDecoder as _XorBruteDecoder
from .crypto import Rc4Decoder as _Rc4Decoder, AesCbcDecoder as _AesCbcDecoder


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


# ── B3.2-A · plugin-shape → DDO invocation bridge ─────────────────
# These three plugins carry a heavier invocation shape
#     .detect(payload, Fingerprint, AnalysisContext) → DetectResult
#     .decode(payload, args_dict,   AnalysisContext) → PluginResult
# The adapters below construct a minimal deterministic Fingerprint
# + AnalysisContext, call the same authoritative implementations,
# then return ONLY the reconstructed text — matching the DDO's
# text-in/text-out contract.  Zero new capability, zero new
# heuristics; the plugin's own .detect() gates the actual decode
# (same acceptance floor as the legacy invocation path).
#
# The Fingerprint and AnalysisContext are instantiated ONCE at
# module load so per-call cost stays negligible and behaviour
# stays deterministic.
def _lazy_ctx_fp():
    """Lazy-instantiate the plugin invocation shims (module-level
    singletons).  Isolated in a callable so DDO import cost stays
    minimal when the plugins are never invoked."""
    from engine.models import AnalysisContext, Fingerprint
    return AnalysisContext(), Fingerprint(input_len=0)


_CTX = None
_FP = None
_XOR_INST = None
_RC4_INST = None
_AES_INST = None


def _ensure_shims():
    global _CTX, _FP, _XOR_INST, _RC4_INST, _AES_INST
    if _CTX is None:
        _CTX, _FP = _lazy_ctx_fp()
        _XOR_INST = _XorBruteDecoder()
        _RC4_INST = _Rc4Decoder()
        _AES_INST = _AesCbcDecoder()


def _fp_for(text: str):
    """Cheap deterministic Fingerprint for the current input.

    The plugins read `input_len`, `entropy`, `printable_ratio`.
    Compute exactly what they need — nothing more."""
    from engine.models import Fingerprint
    b = text.encode("utf-8", errors="replace")
    n = len(b)
    entropy = 0.0
    if n:
        from collections import Counter
        import math
        counts = Counter(b)
        entropy = -sum((c / n) * math.log2(c / n) for c in counts.values())
    printable = sum(1 for x in b if 32 <= x < 127 or x in (9, 10, 13))
    return Fingerprint(
        input_len=n,
        entropy=entropy,
        printable_ratio=(printable / n) if n else 0.0,
        english_density=0.0,
        is_binary=False,
    )


# Acceptance floor mirrors the plugins' own detect() confidence
# gate at 0.30 (the same threshold the legacy plugin-registry
# invocation uses to accept a decode).  This preserves the
# existing behavioural semantics — the DDO adapter is
# invocation-shape only.
_DETECT_FLOOR = 0.30


def _invoke_plugin(inst, text: str) -> Optional[str]:
    _ensure_shims()
    fp = _fp_for(text)
    try:
        det = inst.detect(text, fp, _CTX)
    except Exception:
        return None
    if float(det.confidence or 0.0) < _DETECT_FLOOR:
        return None
    try:
        res = inst.decode(text, det.args or {}, _CTX)
    except Exception:
        return None
    if res is None:
        return None
    out = getattr(res, "output", None) or ""
    # Only report an actual peel — DDO's cycle detector requires
    # that a codec's output NEVER equals its input.
    if not out or out == text:
        return None
    return out


def ddo_xor_brute(text: str) -> Optional[str]:
    _ensure_shims()
    return _invoke_plugin(_XOR_INST, text)


def ddo_rc4(text: str) -> Optional[str]:
    _ensure_shims()
    return _invoke_plugin(_RC4_INST, text)


def ddo_aes_cbc(text: str) -> Optional[str]:
    _ensure_shims()
    return _invoke_plugin(_AES_INST, text)


__all__ = [
    "ddo_gzip",
    "ddo_zlib",
    "ddo_byte_array_xor_loop",
    "ddo_ps_encoded_command",
    "ddo_xor_brute",
    "ddo_rc4",
    "ddo_aes_cbc",
]
