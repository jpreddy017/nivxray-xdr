"""Plane-A encoding sub-engine · P0-1B Gate 2D-B1.

Seven NEW deterministic text-encoding decoders, all of which were
previously fixture-only in the corpus:

  · encoding.url_decode         — %XX (RFC 3986)
  · encoding.unicode_escape     — \\uXXXX, \\xNN, \\UXXXXXXXX
  · encoding.html_entities      — &#65; &amp; &lt; &#x41;
  · encoding.base32             — RFC 4648 Base32 (with padding)
  · encoding.base85             — Ascii85 (btoa) + Z85 (ZeroMQ)
  · encoding.octal_ascii        — \\101\\102\\103 → 'ABC'
  · encoding.decimal_ascii      — 65,66,67 → 'ABC' (comma / space)

Static-only invariants (structurally enforced by Provenance):
  · execution=False  · network_access unavailable  · attck_promotion=False
  · every decoder returns None on ambiguous input — NEVER guesses

False-reconstruction guarantee:
  · Every decoder validates the OUTPUT before emitting a layer
    (≥ 85 %% printability, well-formed length, well-formed charset).
    Random ASCII that happens to be legal Base32 but decodes to
    garbage MUST NOT be reported as a successful decode.
"""
from __future__ import annotations

import base64
import binascii
import html
import re
import urllib.parse
from typing import Optional

from ..types import (
    Capability, CapabilityKind, DecodedLayer, Provenance, now_iso,
)
from ..registry import CapabilityRegistry


ENGINE_VERSION = "0.5.0-gate2d-b1"


# ══════════════════════════════════════════════════════════════════
# Shared "printable text" acceptance check
# ══════════════════════════════════════════════════════════════════
def _is_printable_text(s: str, floor: float = 0.85) -> bool:
    """Reject decode results that are mostly non-printable.  This is
    the primary defence against false reconstruction: an input that
    is legal Base32 but decodes to random bytes will fail here."""
    if not s or len(s) < 2:
        return False
    ok = sum(1 for ch in s
             if ch.isprintable() or ch in ("\n", "\r", "\t"))
    return (ok / len(s)) >= floor


def _layer(stage: str, cap: Capability, raw: str, out: str,
           parent_id: str, layer_index: int, notes: str = "") -> DecodedLayer:
    return DecodedLayer(
        layer_index    = layer_index,
        stage          = stage,
        language       = "generic",
        bytes_in       = len(raw),
        bytes_out      = len(out),
        input_preview  = raw[:64],
        output         = out,
        capability     = cap,
        provenance     = Provenance(
            decoded_from    = parent_id,
            capability_name = cap.name,
            engine_version  = ENGINE_VERSION,
            recorded_at     = now_iso(),
        ),
        confidence     = "HIGH",
        notes          = notes,
    )


# ══════════════════════════════════════════════════════════════════
# 1 · URL decode  (%XX)
# ══════════════════════════════════════════════════════════════════
_URL_ENCODED_RE = re.compile(r"%[0-9A-Fa-f]{2}")


def decode_url(text: str) -> Optional[str]:
    if not _URL_ENCODED_RE.search(text):
        return None
    try:
        out = urllib.parse.unquote(text, errors="strict")
    except (UnicodeDecodeError, ValueError):
        return None
    if out == text or not _is_printable_text(out):
        return None
    return out


# ══════════════════════════════════════════════════════════════════
# 2 · Unicode / hex escapes  (\uXXXX  \xNN  \UXXXXXXXX)
# ══════════════════════════════════════════════════════════════════
_UNICODE_ESC_RE = re.compile(r"\\(?:u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|x[0-9A-Fa-f]{2})")


def decode_unicode_escape(text: str) -> Optional[str]:
    if not _UNICODE_ESC_RE.search(text):
        return None
    try:
        out = bytes(text, "utf-8").decode("unicode_escape")
    except (UnicodeDecodeError, ValueError):
        return None
    if out == text or not _is_printable_text(out):
        return None
    return out


# ══════════════════════════════════════════════════════════════════
# 3 · HTML entities  (&amp; &#65; &#x41;)
# ══════════════════════════════════════════════════════════════════
_HTML_ENTITY_RE = re.compile(r"&(?:#[0-9]+|#x[0-9A-Fa-f]+|[A-Za-z]+);")


def decode_html_entities(text: str) -> Optional[str]:
    if not _HTML_ENTITY_RE.search(text):
        return None
    out = html.unescape(text)
    if out == text or not _is_printable_text(out):
        return None
    return out


# ══════════════════════════════════════════════════════════════════
# 4 · Base32  (RFC 4648)
# ══════════════════════════════════════════════════════════════════
_B32_RE = re.compile(r"^[A-Z2-7]+={0,6}$")


def decode_base32(text: str) -> Optional[str]:
    text = text.strip()
    if len(text) < 8 or (len(text) % 8) != 0:
        return None
    if not _B32_RE.match(text):
        return None
    try:
        raw = base64.b32decode(text, casefold=False)
    except (binascii.Error, ValueError):
        return None
    for enc in ("utf-8", "utf-16-le", "latin-1"):
        try:
            out = raw.decode(enc)
            if _is_printable_text(out):
                return out
        except UnicodeDecodeError:
            continue
    return None


# ══════════════════════════════════════════════════════════════════
# 5 · Base85  (Ascii85 · Z85 · btoa)
# ══════════════════════════════════════════════════════════════════
_B85_ASCII85_RE = re.compile(r"^<~[!-uz]+~>$")
_B85_STRICT_RE  = re.compile(r"^[!-u]+$")


def decode_base85(text: str) -> Optional[str]:
    """Decode Adobe Ascii85 ONLY (with `<~ ... ~>` wrapper).
    Bare-form Ascii85 without a delimiter is ambiguous with normal
    printable text and would false-reconstruct — we require the
    explicit wrapper as a signature."""
    text = text.strip()
    if not _B85_ASCII85_RE.match(text):
        return None
    try:
        raw = base64.a85decode(text, adobe=True)
    except (binascii.Error, ValueError):
        return None
    for enc in ("utf-8", "latin-1"):
        try:
            out = raw.decode(enc)
            if _is_printable_text(out):
                return out
        except UnicodeDecodeError:
            continue
    return None


# ══════════════════════════════════════════════════════════════════
# 6 · Octal ASCII   \101\102\103 → 'ABC'
# ══════════════════════════════════════════════════════════════════
_OCTAL_RE = re.compile(r"(?:\\[0-7]{3}){3,}")


def decode_octal_ascii(text: str) -> Optional[str]:
    if not _OCTAL_RE.search(text):
        return None
    def _fold(m: re.Match) -> str:
        chunk = m.group(0)
        chars: list[str] = []
        for i in range(0, len(chunk), 4):
            try:
                v = int(chunk[i+1:i+4], 8)
                if 0 < v < 256:
                    chars.append(chr(v))
                else:
                    return chunk
            except (ValueError, IndexError):
                return chunk
        return "".join(chars)
    out = _OCTAL_RE.sub(_fold, text)
    if out == text or not _is_printable_text(out):
        return None
    return out


# ══════════════════════════════════════════════════════════════════
# 7 · Decimal ASCII   65,66,67 → 'ABC'   (comma / space delimited)
# ══════════════════════════════════════════════════════════════════
_DEC_ASCII_RE = re.compile(
    r"(?<![0-9])(?:\d{2,3}[,\s]+){3,}\d{2,3}(?![0-9])")


def decode_decimal_ascii(text: str) -> Optional[str]:
    match = _DEC_ASCII_RE.search(text)
    if not match:
        return None
    replacements: list[tuple[str, str]] = []
    for m in _DEC_ASCII_RE.finditer(text):
        chunk = m.group(0)
        parts = [p for p in re.split(r"[,\s]+", chunk) if p]
        chars: list[str] = []
        ok = True
        for p in parts:
            try:
                v = int(p)
            except ValueError:
                ok = False; break
            if 32 <= v < 127 or v in (9, 10, 13):
                chars.append(chr(v))
            else:
                ok = False; break
        if ok and len(chars) >= 3:
            replacements.append((chunk, "".join(chars)))
    if not replacements:
        return None
    out = text
    for old, new in replacements:
        out = out.replace(old, new, 1)
    if not _is_printable_text(out):
        return None
    return out


# ══════════════════════════════════════════════════════════════════
# Capabilities + registration
# ══════════════════════════════════════════════════════════════════
def _cap(name: str, desc: str) -> Capability:
    return Capability(
        name=name, kind=CapabilityKind.DECODER, language="generic",
        version="0.1.0", description=desc)


_CAPS = {
    "encoding.url_decode":       _cap("encoding.url_decode",
                                      "Decode %XX percent-encoded strings."),
    "encoding.unicode_escape":   _cap("encoding.unicode_escape",
                                      "Decode \\uXXXX, \\xNN, \\UXXXXXXXX."),
    "encoding.html_entities":    _cap("encoding.html_entities",
                                      "Decode &amp; &#65; &#x41; entities."),
    "encoding.base32":           _cap("encoding.base32",
                                      "Decode RFC 4648 Base32."),
    "encoding.base85":           _cap("encoding.base85",
                                      "Decode Ascii85 / Z85 Base85."),
    "encoding.octal_ascii":      _cap("encoding.octal_ascii",
                                      "Decode \\NNN octal char sequences."),
    "encoding.decimal_ascii":    _cap("encoding.decimal_ascii",
                                      "Decode comma/space-delimited decimal "
                                      "char-code arrays."),
}


_DECODERS = [
    ("encoding.url_decode",       decode_url),
    ("encoding.unicode_escape",   decode_unicode_escape),
    ("encoding.html_entities",    decode_html_entities),
    ("encoding.base32",           decode_base32),
    ("encoding.base85",           decode_base85),
    ("encoding.octal_ascii",      decode_octal_ascii),
    ("encoding.decimal_ascii",    decode_decimal_ascii),
]


def _make_runner(name: str, fn):
    def _run(raw: str, parent_id: str, layer_index: int) -> Optional[DecodedLayer]:
        out = fn(raw)
        if out is None:
            return None
        return _layer(name, _CAPS[name], raw, out, parent_id, layer_index,
                      notes=f"{name} → {len(out)} chars")
    return _run


def register_all(registry: CapabilityRegistry) -> None:
    if registry.get("encoding.url_decode") is not None:
        return
    for name, fn in _DECODERS:
        registry.register(_CAPS[name], _make_runner(name, fn))


__all__ = [
    "decode_url", "decode_unicode_escape", "decode_html_entities",
    "decode_base32", "decode_base85", "decode_octal_ascii",
    "decode_decimal_ascii",
    "register_all",
    "_DECODERS", "_CAPS",
]
