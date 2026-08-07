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
import re
import zlib
from time    import perf_counter
from typing  import Any, Dict, List, Optional, Tuple

from .decode_telemetry import record_layer


# ══════════════════════════════════════════════════════════════════
# Decoder helpers
# ══════════════════════════════════════════════════════════════════
# --- 1. PowerShell -EncodedCommand (base64 → UTF-16LE) ────────────
_ENC_CMD_RE = re.compile(
    r"""
    (?ix)
    (?:^|\s|['"`])
    (?:powershell(?:_ise)?(?:\.exe)?|pwsh(?:\.exe)?)
    # Allow ANY intervening tokens — flags (``-nop``, ``-w hidden``,
    # ``-executionpolicy bypass``) as well as non-flag args — before the
    # ``-encodedcommand`` flag.  Lazy ``*?`` so we never accidentally
    # swallow the ``-encodedcommand`` flag itself as an intervening
    # argument.  This is the fix for the real-world
    # ``powershell -nop -w hidden -encodedcommand …`` chain the
    # legacy regex was silently missing.
    (?:\s+\S+)*?
    (?:\s+-(?:e|en|enc|encode|encoded|encodedcommand|ec))\b
    \s*(?P<b64>[A-Za-z0-9+/]{16,}={0,2})
    """,
    re.VERBOSE,
)


def _decode_ps_encoded_command(text: str) -> Optional[Tuple[str, Dict[str, Any]]]:
    m = _ENC_CMD_RE.search(text or "")
    if not m:
        return None
    b64 = m.group("b64")
    padded = b64 + "=" * (-len(b64) % 4)
    try:
        raw = base64.b64decode(padded, validate=False)
    except (binascii.Error, ValueError):
        return None
    if not raw:
        return None
    # UTF-16LE first (PowerShell wire format), then UTF-8, then latin-1.
    for enc in ("utf-16-le", "utf-8", "latin-1"):
        try:
            decoded = raw.decode(enc)
            if _mostly_printable(decoded):
                return decoded, {"encoding": enc, "b64_len": len(padded)}
        except UnicodeDecodeError:
            continue
    return None


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


def _shellcode_string_scan(raw: bytes) -> List[str]:
    """Extract ASCII-embedded C2 indicators from raw byte payloads
    (shellcode / packed configs).  Returns a human-readable list
    like ``["ip:149.28.81.19", "url:http://…", "domain:evil.com"]``
    suitable for surfacing on the decoded output block.

    This is the terminal-layer bug fix for Sophos / Cobalt-Strike
    style loaders where the innermost payload is raw shellcode
    (non-printable bytes) that carries the beacon C2 config as
    ASCII substrings.  Without this, the pipeline peels through
    every text layer but never surfaces the actual IOC.
    """
    if not raw:
        return []
    findings: List[str] = []
    for ip in _IP_RE.findall(raw):
        try:
            s = ip.decode("ascii")
            # skip obvious non-IPs like version strings 0.0.0.0 / 127.0.0.1 loopbacks
            parts = s.split(".")
            if all(0 <= int(p) <= 255 for p in parts) and s not in ("0.0.0.0", "127.0.0.1"):
                findings.append(f"ip:{s}")
        except (UnicodeDecodeError, ValueError):
            continue
    for u in _URL_RE.findall(raw):
        try:
            findings.append(f"url:{u.decode('ascii', 'ignore')}")
        except Exception:  # pragma: no cover
            pass
    for d in _DOM_RE.findall(raw):
        try:
            s = d.decode("ascii", "ignore").rstrip(".")
            if "." in s and len(s) >= 4 and not s.replace(".", "").isdigit():
                findings.append(f"domain:{s}")
        except Exception:  # pragma: no cover
            pass
    # Dedupe while preserving order — deterministic.
    seen, out = set(), []
    for x in findings:
        if x not in seen:
            seen.add(x); out.append(x)
    return out


def _decode_gzip_bytes(text: str) -> Optional[Tuple[str, Dict[str, Any]]]:
    """Look for a @@RAWBYTES@@ sentinel; if the payload starts with
    GZip magic bytes (0x1F 0x8B), inflate it in place.

    When the inflated payload is NOT printable text (i.e. raw
    shellcode), we still emit a synthetic printable block that
    surfaces the ASCII-embedded IOCs (C2 IPs / URLs / domains)
    living inside the shellcode.  That closes the Sophos/Cobalt
    Strike terminal-layer gap where the innermost artifact is a
    byte blob rather than another PS layer.
    """
    hit = _extract_rawbytes(text)
    if not hit:
        return None
    raw, start, end = hit
    if len(raw) < 4 or raw[0] != 0x1F or raw[1] != 0x8B:
        return None
    try:
        inflated = gzip.decompress(raw)
    except (OSError, EOFError, zlib.error):
        return None
    for enc in ("utf-8", "utf-16-le", "latin-1"):
        try:
            plaintext = inflated.decode(enc)
            if _mostly_printable(plaintext):
                new_text = text[:start] + plaintext + text[end:]
                return new_text, {"encoding": enc,
                                    "bytes_in": len(raw),
                                    "bytes_out": len(inflated)}
        except UnicodeDecodeError:
            continue
    # ── Terminal shellcode layer — extract embedded IOCs ─────────
    iocs = _shellcode_string_scan(inflated)
    tag = (
        f"[shellcode-payload: {len(inflated)} bytes"
        + (f" · embedded_iocs=" + ", ".join(iocs) if iocs else "")
        + "]"
    )
    new_text = text[:start] + tag + text[end:]
    return new_text, {
        "encoding":         "shellcode",
        "bytes_in":         len(raw),
        "bytes_out":        len(inflated),
        "shellcode":        True,
        "embedded_iocs":    iocs,
    }
    return None


# --- 4. zlib / deflate (rarer, but seen in some loaders) ─────────
def _decode_zlib_bytes(text: str) -> Optional[Tuple[str, Dict[str, Any]]]:
    hit = _extract_rawbytes(text)
    if not hit:
        return None
    raw, start, end = hit
    # zlib magic: 0x78 followed by 0x01/0x5E/0x9C/0xDA
    if len(raw) < 2 or raw[0] != 0x78 or raw[1] not in (0x01, 0x5E, 0x9C, 0xDA):
        return None
    try:
        inflated = zlib.decompress(raw)
    except zlib.error:
        return None
    for enc in ("utf-8", "utf-16-le", "latin-1"):
        try:
            plaintext = inflated.decode(enc)
            if _mostly_printable(plaintext):
                new_text = text[:start] + plaintext + text[end:]
                return new_text, {"encoding": enc,
                                    "bytes_in": len(raw),
                                    "bytes_out": len(inflated)}
        except UnicodeDecodeError:
            continue
    return None


# --- 5. Standalone base64 blob (bare paste of a long b64 string) ─
_BARE_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{80,}={0,2}(?![A-Za-z0-9+/=])")


def _decode_bare_base64(text: str, *, min_len: int = 120) -> Optional[Tuple[str, Dict[str, Any]]]:
    """If the input is (or contains) a very long bare base64 blob
    that isn't inside a FromBase64String() call, try to decode it
    once.  We only fire when there's exactly one candidate and it's
    long enough — otherwise we could false-positive on IOC-style
    hashes."""
    matches = _BARE_B64_RE.findall(text or "")
    if len(matches) != 1:
        return None
    b64 = matches[0]
    if len(b64) < min_len:
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
    # Non-printable — surface as raw bytes for the gzip/zlib pass.
    return "@@RAWBYTES@@" + raw.hex(), {"encoding": "raw", "b64_len": len(padded)}


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
# Recursive driver
# ══════════════════════════════════════════════════════════════════
# Ordered list of (stage_name, function).  Deterministic order —
# earliest match wins.  We try the wrappers first (they're cheap and
# unambiguous), then falling back to bare base64.
_DECODERS: List[Tuple[str, Any]] = [
    ("ps_encodedcommand",   _decode_ps_encoded_command),
    ("from_base64_string",  _decode_frombase64string),
    ("gzip",                _decode_gzip_bytes),
    ("zlib",                _decode_zlib_bytes),
    ("bare_base64",         _decode_bare_base64),
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
        return text, []
    layers_meta: List[Dict[str, Any]] = []
    current  = text
    previous = None

    for layer_idx in range(1, max_layers + 1):
        if current == previous:
            break
        if len(current) > max_bytes:
            layers_meta.append({
                "stage": "abort_size",
                "layer": layer_idx,
                "bytes_in": len(current),
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
            layers_meta.append({
                "layer":      layer_idx,
                "stage":      stage_name,
                "bytes_in":   len(current),
                "bytes_out":  len(new_text),
                "elapsed_ms": round(elapsed_ms, 3),
                "meta":       meta,
            })
            current = new_text
            peeled = True
            break
        if not peeled:
            # No decoder made progress this iteration → we're done.
            break

    # Final cleanup — replace any lingering @@RAWBYTES@@ sentinel
    # with a printable placeholder so downstream consumers never
    # see the internal representation.
    if "@@RAWBYTES@@" in current:
        current = _RAWBYTES_RE.sub(lambda m: f"[raw:{len(m.group(1))//2}b]", current)

    return current, layers_meta
