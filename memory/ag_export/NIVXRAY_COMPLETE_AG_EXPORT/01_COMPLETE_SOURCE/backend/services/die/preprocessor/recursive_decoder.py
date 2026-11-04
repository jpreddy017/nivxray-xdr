"""
DIE · Preprocessor · Recursive Multi-Layer Decoder (R23/R24 core fix)
─────────────────────────────────────────────────────────────────────
Peels every recognisable encoding layer until nothing decodable
remains, or a safety cap (default 8 layers) is hit.  Handles the
canonical multi-stage PowerShell loader:

    Layer 0 · CMD launcher                       (%COMSPEC% /c powershell …)
    Layer 1 · PowerShell -EncodedCommand         (UTF-16LE base64)
    Layer 2 · Decoded PowerShell                 (contains inner loader)
    Layer 3 · [Convert]::FromBase64String("…")   (extract inner b64)
    Layer 4 · Base64 decode                      (yields gzip bytes)
    Layer 5 · GZipStream / [IO.Compression]      (inflate to plaintext)
    Layer 6 · Recovered PowerShell payload
    …recursion continues if new patterns appear…

Deterministic.  No LLM.  Same input → same layer trace.  Every layer
records:
    stage      ("ps_encodedcommand", "utf16le", "base64", "gzip", …)
    bytes_in / bytes_out / ratio
    elapsed_ms
    meta       (index / offset / notes)

Design principles (Rule R23/R24):
    · Never crash — every decoder wrapped in try/except.
    · Never infinite-loop — bounded MAX_LAYERS + no-progress detector.
    · Never masquerade failure — output equals input ⇒ nothing peeled.
    · Emits per-layer telemetry via `decode_telemetry.record_layer()`.
"""
from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import re
import zlib
from time    import perf_counter
from typing  import Any, Dict, List, Optional, Tuple

from .decode_telemetry import record_layer


# ══════════════════════════════════════════════════════════════════
# Decoder helpers
# ══════════════════════════════════════════════════════════════════
# ══════════════════════════════════════════════════════════════════
# Gate 2D-B3.1 · Family 7 (UTF-16LE via PS -EncodedCommand) MIGRATED
# ══════════════════════════════════════════════════════════════════
# Authoritative UTF-16LE + PS-EncodedCommand runtime now lives at
#     services.decoder.base.powershell_encoded_command
# All symbols re-exported here for backward compatibility (existing
# UAIE plugin adapter `powershell_encoded_command/__init__.py`
# imports `_decode_ps_encoded_command` from this module).
from services.decoder.base.powershell_encoded_command import (   # noqa: F401
    _ENC_CMD_RE                as _ENC_CMD_RE,
    _looks_like_powershell     as _looks_like_powershell,
    _utf16le_realign           as _utf16le_realign,
    decode_ps_encoded_command  as _decode_ps_encoded_command,
)


# --- 2. FromBase64String("…") / [Convert]::FromBase64String("…") ──
_FROM_B64_RE = re.compile(
    r"""(?ix)
    (?:\[\s*Convert\s*\]\s*::)?FromBase64String\s*\(
      \s*(?P<q>['"])(?P<b64>[A-Za-z0-9+/=\s]{16,})(?P=q)\s*
    \)
    """,
    re.VERBOSE,
)


def _decode_frombase64string(text: str) -> Optional[Tuple[str, Dict[str, Any]]]:
    """Find the first FromBase64String("…") in the script, decode
    it, and if the result looks like GZip-compressed data, inflate
    it too — that's the canonical loader shape.  Otherwise return
    the raw base64-decoded string."""
    m = _FROM_B64_RE.search(text or "")
    if not m:
        return None
    b64 = re.sub(r"\s+", "", m.group("b64"))
    padded = b64 + "=" * (-len(b64) % 4)
    try:
        raw = base64.b64decode(padded, validate=False)
    except (binascii.Error, ValueError):
        return None
    if not raw or len(raw) < 4:
        return None
    # Common wrapper: raw bytes are GZip.  We DO NOT auto-inflate
    # here — the recursion driver will detect the gzip magic on the
    # next pass and route through _decode_gzip_bytes.  That keeps
    # the decode_layers[] trace faithful to what actually happened.
    # Try UTF-8 / UTF-16LE plaintext first; if not printable, return
    # a printable base16 representation so subsequent passes can
    # still detect gzip magic (0x1F 0x8B).
    for enc in ("utf-8", "utf-16-le", "latin-1"):
        try:
            decoded = raw.decode(enc)
            if _mostly_printable(decoded):
                return decoded, {"encoding": enc, "b64_len": len(padded)}
        except UnicodeDecodeError:
            continue
    # Non-printable — return an ASCII-safe representation carrying
    # the raw bytes so the gzip / zlib detector can see the magic
    # header.  We prefix the hex with a sentinel so the recursion
    # driver can find + peel it deterministically.
    # Non-printable — surface as raw bytes for the gzip / zlib
    # detector on the next pass.  If neither compression signature
    # matches (rare — happens when the inner blob is raw shellcode
    # with no compression), we STILL scan the bytes for ASCII IOCs
    # so the C2 IP / URL / domain surfaces regardless.
    embedded = _shellcode_string_scan(raw)
    if embedded and not (raw[0:2] == b"\x1F\x8B" or (raw[0] == 0x78 and raw[1] in (0x01, 0x5E, 0x9C, 0xDA))):
        # Pure raw shellcode from FromBase64String — no compression.
        tag = f"[shellcode-payload: {len(raw)} bytes · embedded_iocs=" + ", ".join(embedded) + "]"
        return tag, {"encoding": "shellcode",
                        "b64_len": len(padded),
                        "raw_len": len(raw),
                        "embedded_iocs": embedded,
                        "shellcode": True}
    return "@@RAWBYTES@@" + raw.hex(), {"encoding": "raw", "b64_len": len(padded), "raw_len": len(raw)}


_RAWBYTES_RE = re.compile(r"@@RAWBYTES@@([0-9a-fA-F]+)")


def _extract_rawbytes(text: str) -> Optional[Tuple[bytes, int, int]]:
    m = _RAWBYTES_RE.search(text or "")
    if not m:
        return None
    hex_str = m.group(1)
    try:
        raw = bytes.fromhex(hex_str)
    except ValueError:
        return None
    return raw, m.start(), m.end()


# --- 3. GZip inflate ─────────────────────────────────────────────
_IP_RE  = re.compile(rb"(?<![0-9])(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?![0-9])")
_URL_RE = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,}")
_DOM_RE = re.compile(rb"(?<![A-Za-z0-9])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){1,}[A-Za-z]{2,24}(?![A-Za-z0-9])")


# ══════════════════════════════════════════════════════════════════
# Gate 2D-B3.1 · Family 1 (GZIP) MIGRATED to services/decoder/base/
# ══════════════════════════════════════════════════════════════════
# The GZIP codec implementation now lives at
#     services.decoder.base.compression.decode_gzip_bytes
# `_decode_gzip_bytes` is retained here purely as a name-preserving
# delegate so legacy callers (UAIE plugin wrappers, pipeline.py, etc.)
# continue to import the exact same symbol.  New callers MUST import
# from services.decoder.base.compression.
#
# The shellcode string scanner + printability helper also moved to
# services.decoder.base._shared and are re-exported here as aliases
# so existing callers (cs_beacon_config_parser plugin, shellcode
# plugins) keep working without a coordinated change.
from services.decoder.base._shared import (
    _shellcode_string_scan as _shellcode_string_scan,   # noqa: F401 (re-export)
)
from services.decoder.base.compression import (
    decode_gzip_bytes as _decode_gzip_bytes,           # noqa: F401 (re-export)
)


# --- 4. zlib / deflate (rarer, but seen in some loaders) ─────────
# Gate 2D-B3.1 · Family 2 (Zlib/Deflate) MIGRATED to
#     services.decoder.base.compression.decode_zlib_bytes
# `_decode_zlib_bytes` remains here as a re-export shim.
from services.decoder.base.compression import (
    decode_zlib_bytes as _decode_zlib_bytes,           # noqa: F401 (re-export)
)


# --- 5. Standalone base64 blob (bare paste of a long b64 string) ─
_BARE_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{80,}={0,2}(?![A-Za-z0-9+/=])")


def _decode_bare_base64(text: str, *, min_len: int = 120) -> Optional[Tuple[str, Dict[str, Any]]]:
    """If the input is (or contains) a very long bare base64 blob
    that isn't inside a FromBase64String() call, try to decode it
    once.  We only fire when there's exactly one candidate and it's
    long enough — otherwise we could false-positive on IOC-style
    hashes.

    2026-02-04 · R28.7.5 · Sentinel guard.  Previously the regex
    matched the hex characters INSIDE ``@@RAWBYTES@@<hex>`` sentinels
    emitted by ``_decode_frombase64string``, causing a runaway
    ``bare_base64`` loop that never let ``_decode_gzip_bytes`` fire on
    the underlying gzip magic (Sophos-shape 3-layer stagers stall at
    the wrapper layer).  We now strip every sentinel span from the
    scan text before searching — the hex string is not base64.
    """
    if not text:
        return None
    # ── Sentinel guard — remove @@RAWBYTES@@<hex> spans before scan ─
    scan = _RAWBYTES_RE.sub("", text).strip()
    b64 = None
    # If the input itself is a standalone base64 payload
    if len(scan) >= 16 and len(scan) % 4 == 0 and re.match(r"^[A-Za-z0-9+/]+={0,2}$", scan):
        b64 = scan
    else:
        matches = _BARE_B64_RE.findall(scan)
        if len(matches) == 1 and len(matches[0]) >= min_len:
            b64 = matches[0]
    if not b64:
        return None
    padded = b64 + "=" * (-len(b64) % 4)
    try:
        raw = base64.b64decode(padded, validate=False)
    except (binascii.Error, ValueError):
        return None
    if not raw:
        return None
    for enc in ("utf-8", "utf-16-le", "latin-1"):
        try:
            decoded = raw.decode(enc)
            if _mostly_printable(decoded) and decoded.strip() != text.strip():
                return decoded, {"encoding": enc, "b64_len": len(padded)}
        except UnicodeDecodeError:
            continue
    # Non-printable — surface as raw bytes for the gzip/zlib pass if it looks like gzip/zlib or shellcode.
    if raw[0:2] == b"\x1F\x8B" or (raw[0] == 0x78 and raw[1] in (0x01, 0x5E, 0x9C, 0xDA)):
        return "@@RAWBYTES@@" + raw.hex(), {"encoding": "raw", "b64_len": len(padded)}
    embedded = _shellcode_string_scan(raw)
    if embedded:
        tag = f"[shellcode-payload: {len(raw)} bytes · embedded_iocs=" + ", ".join(embedded) + "]"
        return tag, {"encoding": "shellcode",
                     "b64_len": len(padded),
                     "raw_len": len(raw),
                     "embedded_iocs": embedded,
                     "shellcode": True}
    return None


# ══════════════════════════════════════════════════════════════════
# Utility
# ══════════════════════════════════════════════════════════════════
def _mostly_printable(s: str, threshold: float = 0.85) -> bool:
    if not s:
        return False
    total = len(s)
    ok = sum(1 for c in s
              if (32 <= ord(c) < 127) or ord(c) in (9, 10, 13))
    return (ok / total) >= threshold


# ══════════════════════════════════════════════════════════════════
# 6.  Byte-array XOR loop  (R28.7.6 · Cobalt Strike stager terminal)
# ══════════════════════════════════════════════════════════════════
# Gate 2D-B3.1 · Family 3 (byte-array XOR loop) MIGRATED to
#     services.decoder.base.transform.decode_byte_array_xor_loop
# `_decode_byte_array_xor_loop`, `_BYTE_ARRAY_XOR_LOOP_RE`, and
# `_shellcode_ascii_strings` are re-exported here as legacy aliases.
from services.decoder.base.transform import (
    _BYTE_ARRAY_XOR_LOOP_RE as _BYTE_ARRAY_XOR_LOOP_RE,          # noqa: F401 (re-export)
    decode_byte_array_xor_loop as _decode_byte_array_xor_loop,   # noqa: F401 (re-export)
    _shellcode_ascii_strings as _shellcode_ascii_strings,        # noqa: F401 (re-export)
)


def _decode_hex(text: str) -> Optional[Tuple[str, Dict[str, Any]]]:
    s = text.strip()
    if len(s) < 8 or len(s) % 2 != 0:
        return None
    if not re.match(r"^[0-9a-fA-F]+$", s):
        return None
    try:
        raw = bytes.fromhex(s)
    except ValueError:
        return None
    if not raw:
        return None
    for enc in ("utf-8", "latin-1"):
        try:
            decoded = raw.decode(enc)
            if _mostly_printable(decoded) and decoded.strip() != text.strip():
                return decoded, {"encoding": enc, "bytes_in": len(s), "bytes_out": len(decoded)}
        except UnicodeDecodeError:
            continue
    return "@@RAWBYTES@@" + raw.hex(), {"encoding": "raw", "bytes_in": len(s), "bytes_out": len(raw)}


class PeelResult(tuple):
    """Dual-contract result object.
    
    Unpacks as (text, layers) for all existing legacy/production callers,
    while exposing .text, .layers, .success, and .stop_reason for analyst contracts.
    """
    def __new__(cls, text: str, layers: list, stop_reason: str = ""):
        return super().__new__(cls, (text, layers))

    def __init__(self, text: str, layers: list, stop_reason: str = ""):
        self._stop_reason = stop_reason

    @property
    def text(self) -> str:
        return self[0]

    @property
    def layers(self) -> list:
        return self[1]

    @property
    def success(self) -> bool:
        return bool(self[1]) and any(l.get("status") == "success" for l in self[1])

    @property
    def stop_reason(self) -> str:
        if self[1]:
            r = self[1][-1].get("stop_reason")
            if r:
                return r
        return self._stop_reason


# ══════════════════════════════════════════════════════════════════
# Recursive driver
# ══════════════════════════════════════════════════════════════════
# Ordered list of (stage_name, function).  Deterministic order —
# earliest match wins.  We try the wrappers first (they're cheap and
# unambiguous), then falling back to bare base64.
_DECODERS: List[Tuple[str, Any]] = [
    ("ps_encodedcommand",       _decode_ps_encoded_command),
    # ── Byte-array XOR loop  BEFORE  from_base64_string  ──
    # The XOR-loop pattern is MORE SPECIFIC (requires both b64 blob
    # AND ``-bxor <K>`` loop referencing the same variable) than the
    # bare ``FromBase64String(...)`` matcher.  If it matches we must
    # fold both ops in one deterministic step; otherwise
    # ``from_base64_string`` would burn the b64 blob first and the
    # XOR-loop trace would be lost (Sophos-shape Layer-2 terminal
    # regression — user reported ``no_transformation`` at this
    # exact layer).
    ("byte_array_xor_loop",     _decode_byte_array_xor_loop),
    ("from_base64_string",      _decode_frombase64string),
    ("gzip",                    _decode_gzip_bytes),
    ("zlib",                    _decode_zlib_bytes),
    ("hex",                     _decode_hex),
    ("bare_base64",             _decode_bare_base64),
]


def peel_recursively(text: str,
                       *,
                       max_layers: int = 8,
                       max_bytes:  int = 512 * 1024) -> Tuple[str, List[Dict[str, Any]]]:
    """Iteratively peel decode layers until nothing further can be
    peeled OR safety caps are hit.

    Returns ``(final_text, layers[])`` where ``layers[]`` is the
    per-layer telemetry (also emitted via ``record_layer`` so the
    SSOT's ``metadata.performance.decode_layers`` reflects it).

    Bounded by:
      · ``max_layers``  — hard cap (default 8)
      · ``max_bytes``   — reject expansions past ~512 KB
      · no-progress detector — same output twice in a row exits
    """
    if not text:
        return PeelResult(text, [], "already_plaintext")
    layers_meta: List[Dict[str, Any]] = []
    current  = text
    previous = None

    stop_reason = "No further deterministic decoder matched or made progress"
    for layer_idx in range(1, max_layers + 1):
        if current == previous:
            stop_reason = "Output stabilized (idempotent stop)"
            break
        if len(current) > max_bytes:
            stop_reason = f"Output exceeded safety threshold ({max_bytes} bytes)"
            layers_meta.append({
                "stage": "abort_size",
                "layer": layer_idx,
                "sequence": layer_idx,
                "decoder": "abort_size",
                "bytes_in": len(current),
                "bytes_out": 0,
                "status": "aborted",
                "why_selected": "Safety guard: output size cap reached",
                "stop_reason": stop_reason,
                "meta": {"reason": f"output exceeded {max_bytes} bytes"},
            })
            break
        previous = current
        peeled = False
        for stage_name, fn in _DECODERS:
            t0 = perf_counter()
            try:
                res = fn(current)
            except Exception as e:  # pragma: no cover — never crash
                record_layer(f"{stage_name}_error",
                              bytes_in=len(current), bytes_out=0,
                              elapsed_ms=(perf_counter() - t0) * 1000.0,
                              meta={"error": type(e).__name__})
                continue
            if res is None:
                continue
            new_text, meta = res
            if not new_text or new_text == current:
                continue
            elapsed_ms = (perf_counter() - t0) * 1000.0
            record_layer(stage_name,
                          bytes_in=len(current),
                          bytes_out=len(new_text),
                          elapsed_ms=elapsed_ms,
                          meta=meta)

            in_hash = hashlib.sha256(current.encode("utf-8", errors="replace")).hexdigest()
            out_hash = hashlib.sha256(new_text.encode("utf-8", errors="replace")).hexdigest()

            why_map = {
                "ps_encodedcommand": "Matched PowerShell -EncodedCommand / -e (base64 UTF-16LE payload)",
                "byte_array_xor_loop": "Matched PowerShell byte-array XOR loop with embedded Base64 blob",
                "from_base64_string": "Matched FromBase64String() method call with embedded Base64 payload",
                "gzip": "Detected GZip compressed stream magic bytes (0x1F 0x8B)",
                "zlib": "Detected Zlib / Deflate compressed stream magic bytes (0x78)",
                "bare_base64": "Matched valid standalone Base64 encoded payload",
            }
            why_selected = why_map.get(stage_name, f"Matched {stage_name} heuristic signature")

            layers_meta.append({
                "layer":           layer_idx,
                "sequence":        layer_idx,
                "stage":           stage_name,
                "decoder":         stage_name,
                "bytes_in":        len(current),
                "bytes_out":       len(new_text),
                "elapsed_ms":      round(elapsed_ms, 3),
                "input_hash":      in_hash,
                "output_hash":     out_hash,
                "input_preview":   current[:200],
                "output_preview":  new_text[:200],
                "output_text":     new_text[:64 * 1024],
                "text":            new_text[:64 * 1024],
                "status":          "success",
                "why_selected":    why_selected,
                "confidence":      0.95,
                "meta":            meta,
            })
            current = new_text
            peeled = True
            break
        if not peeled:
            break
        if layer_idx >= max_layers:
            stop_reason = "max_depth_reached"

    if not layers_meta:
        stop_reason = "no_transformation_identified"
    else:
        if current != text and _mostly_printable(current):
            stop_reason = "terminal_plaintext_reached"
        elif stop_reason not in ("max_depth_reached", "size_limit_exceeded"):
            stop_reason = "no_further_transformation"

    # Stamp stop_reason on all layer metadata
    for lyr in layers_meta:
        lyr["stop_reason"] = stop_reason

    # Final cleanup — replace any lingering @@RAWBYTES@@ sentinel
    # with a printable placeholder so downstream consumers never
    # see the internal representation.
    if "@@RAWBYTES@@" in current:
        current = _RAWBYTES_RE.sub(lambda m: f"[raw:{len(m.group(1))//2}b]", current)

    return PeelResult(current, layers_meta, stop_reason)
