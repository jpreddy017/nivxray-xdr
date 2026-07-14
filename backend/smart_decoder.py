"""NivXRay — deterministic smart auto-decoder (no AI required).

Given any payload — a raw PowerShell command line, a CMD one-liner, a nested
base64/gzip blob, a URL-encoded XSS string, JS charcode, defanged IOCs, etc. —
this module inspects the input and recursively chains the appropriate
operations until a "clean" result is produced or no further progress is made.
"""
from __future__ import annotations
import base64
import binascii
import bz2
import gzip
import lzma
import re
import zlib
from typing import Any, Dict, List, Tuple

from operations import run_operation


# ---------------------------------------------------------------------------
# Detectors  --  return (op_id, args) to apply, or None if not applicable
# ---------------------------------------------------------------------------

_PS_ENCODED_RE = re.compile(
    r"(?:^|\s|;|&|\|)pwsh(?:\.exe)?|powershell(?:\.exe)?"
    r"[\s\S]*?"
    r"(?:-e(?:c|n|nc|ncoded(?:command)?)?)\s+([A-Za-z0-9+/=\s]{16,})",
    re.IGNORECASE,
)

_JS_CHARCODE_RE = re.compile(r"String\.fromCharCode\s*\(", re.IGNORECASE)
_JS_HEX_ESC_RE = re.compile(r"\\x[0-9a-fA-F]{2}")
_UNICODE_ESC_RE = re.compile(r"\\u[0-9a-fA-F]{4}")
_URL_ENC_RE = re.compile(r"%[0-9A-Fa-f]{2}")
_DEFANGED_RE = re.compile(r"hxxp[s]?://|\[\.\]|\[@\]|\[://\]", re.IGNORECASE)
_HTML_ENT_RE = re.compile(r"&(?:#x?[0-9a-fA-F]+|[a-zA-Z]+);")
_CMD_CARET_RE = re.compile(r"\^[a-zA-Z]")
_CMD_QUOTED_RE = re.compile(r'[a-zA-Z]"[a-zA-Z]|"[a-zA-Z]"')
_PS_TICK_RE = re.compile(r"[a-zA-Z]`[a-zA-Z]")
_PS_CHAR_ARR_RE = re.compile(r"\[char\[\]\]|\[char\]", re.IGNORECASE)


def _looks_like_base64(s: str) -> bool:
    s2 = re.sub(r"\s+", "", s)
    if len(s2) < 16:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", s2):
        return False
    # avoid decoding plain english words that happen to be base64-shaped
    if len(s2) < 24 and s2.isalpha():
        return False
    return True


def _looks_like_hex(s: str) -> bool:
    s2 = re.sub(r"[\s,\-]", "", s)
    if len(s2) < 16 or len(s2) % 2:
        return False
    return bool(re.fullmatch(r"[0-9a-fA-F]+", s2))


def _try_base64(s: str) -> bytes | None:
    s2 = re.sub(r"\s+", "", s)
    try:
        raw = base64.b64decode(s2 + "=" * (-len(s2) % 4), validate=False)
        if len(raw) == 0:
            return None
        return raw
    except (binascii.Error, ValueError):
        return None


def _is_printable_text(raw: bytes, threshold: float = 0.85) -> bool:
    if not raw:
        return False
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            s = raw.decode("utf-16-le")
        except UnicodeDecodeError:
            return False
    if not s:
        return False
    printable = sum(1 for c in s if c.isprintable() or c in "\n\r\t")
    return printable / max(1, len(s)) >= threshold


def _decode_bytes(raw: bytes) -> str:
    """Decode bytes with best-effort: UTF-16LE if likely, else UTF-8."""
    if len(raw) >= 4 and raw[1] == 0 and raw[3] == 0:
        try:
            return raw.decode("utf-16-le")
        except UnicodeDecodeError:
            pass
    if raw.startswith(b"\xff\xfe"):
        try:
            return raw.decode("utf-16-le")
        except UnicodeDecodeError:
            pass
    return raw.decode("utf-8", errors="replace")


def _bin_magic_op(raw: bytes):
    """If `raw` begins with a compression magic-byte sequence, decompress it
    and return (op_id, decoded_string). Otherwise return None."""
    if raw[:2] == b"\x1f\x8b":
        try:
            return ("base64-gzip", gzip.decompress(raw).decode("utf-8", errors="replace"))
        except Exception:
            pass
    if raw[:2] in (b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda"):
        try:
            return ("base64-zlib", zlib.decompress(raw).decode("utf-8", errors="replace"))
        except Exception:
            pass
    if raw[:6] == b"\xfd7zXZ\x00":
        try:
            return ("lzma-decompress", lzma.decompress(raw).decode("utf-8", errors="replace"))
        except Exception:
            pass
    if raw[:3] == b"BZh":
        try:
            return ("bzip2-decompress", bz2.decompress(raw).decode("utf-8", errors="replace"))
        except Exception:
            pass
    return None


# ---------------------------------------------------------------------------
# Chain runner
# ---------------------------------------------------------------------------

MAX_STEPS = 12
MAX_LENGTH = 2_000_000


def smart_decode(payload: str) -> Dict[str, Any]:
    """Deterministically chain decoders until no further transformation applies.

    Returns dict with: steps [{op, args, reason}], output, notes.
    """
    from payload_sanitizer import sanitize_encapsulated_payload

    steps: List[Dict[str, Any]] = []
    notes: List[str] = []
    current = payload

    # THUMB RULE: ISOLATE THE PAYLOAD STRING FIRST.
    # If the input is a full script wrapper (variable assignment, cmdlet call,
    # bash pipeline), extract the enclosed base64 payload before running any
    # decoder recipe on it.
    isolated = sanitize_encapsulated_payload(payload)
    isolated_flag = False
    if isolated and isolated != payload.strip():
        steps.append({
            "op": "extract-payload",
            "args": {},
            "reason": f"Isolated base64 payload from script wrapper ({len(isolated)} chars)",
        })
        notes.append("Payload isolated from script/command wrapper (thumb rule)")
        current = isolated
        isolated_flag = True

    # If the isolated payload is a *clean* base64 string, decode it eagerly —
    # short pure-alpha payloads (e.g. `YWxlcnQoIlhTUyIp`) would otherwise be
    # rejected by the length/alpha heuristics in `_apply_next`.
    if isolated_flag:
        b64_only = re.sub(r"\s+", "", current)
        if b64_only and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", b64_only) and len(b64_only) >= 8:
            raw = _try_base64(b64_only)
            if raw is not None:
                # gzip / zlib / lzma / bzip2 magic byte fast-paths
                bin_op = _bin_magic_op(raw)
                if bin_op:
                    op_id, decoded = bin_op
                    steps.append({"op": op_id, "args": {},
                                  "reason": f"Isolated payload → {op_id}"})
                    current = decoded
                else:
                    dec_str = _decode_bytes(raw)
                    if _is_printable_text(dec_str.encode("utf-8", errors="replace"), 0.85):
                        steps.append({"op": "base64-decode", "args": {},
                                      "reason": "Isolated payload → base64 decode"})
                        current = dec_str

    for _ in range(MAX_STEPS):
        if len(current) > MAX_LENGTH:
            notes.append(f"Aborting: output exceeded {MAX_LENGTH} chars")
            break

        applied = _apply_next(current, steps, notes)
        if not applied:
            break
        op_id, args, reason, new_val = applied
        steps.append({"op": op_id, "args": args, "reason": reason})
        current = new_val

    # If nothing chained (or ended on a non-base64 wrapper) — try to extract
    # embedded base64 blobs and produce an annotated multi-part output.
    if not steps or (len(current) == len(payload) and current == payload):
        embedded = _extract_embedded_b64_blocks(current)
        if embedded:
            steps.append({
                "op": "extract-base64",
                "args": {},
                "reason": f"Extracted {len(embedded)} embedded base64 blob(s) from wrapper",
            })
            parts = []
            for i, e in enumerate(embedded, 1):
                parts.append(f"────── EMBEDDED BLOB #{i} ({e['method']}) ──────")
                parts.append(f"blob: {e['blob']}")
                parts.append("decoded:")
                parts.append(e["decoded"])
                parts.append("")
            current = "\n".join(parts).rstrip()

    # Post-decoding polish: expand %TEMP% / $env:APPDATA / ${HOME} / ~/ into
    # canonical placeholder paths so obfuscated IOC paths render as readable
    # strings analysts can pivot on.
    if current and re.search(r"%[A-Za-z_]|\$env:|\$\{?[A-Za-z_]|~/", current):
        try:
            expanded = run_operation("env-expand", current, {})
            if expanded and expanded != current:
                steps.append({
                    "op": "env-expand", "args": {},
                    "reason": "Resolved %TEMP% / $env:* / ${HOME} into canonical paths",
                })
                current = expanded
        except Exception:
            pass

    return {"steps": steps, "output": current, "notes": notes}


def _extract_embedded_b64_blocks(text: str) -> List[Dict[str, str]]:
    """Find long base64 blobs (>= 40 chars) embedded inside text and decode them.
    Uses gzip → zlib → utf-16-le → utf-8 fallback chain.
    """
    hits: List[Dict[str, str]] = []
    seen = set()
    for m in re.finditer(r"[A-Za-z0-9+/]{40,}={0,2}", text):
        blob = m.group(0)
        if blob in seen:
            continue
        seen.add(blob)
        raw = _try_base64(blob)
        if not raw:
            continue
        decoded_str = None
        method = None
        if raw[:2] == b"\x1f\x8b":
            try: decoded_str = gzip.decompress(raw).decode("utf-8", errors="replace"); method = "base64→gzip"
            except Exception: pass
        if decoded_str is None and raw[:2] in (b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda"):
            try: decoded_str = zlib.decompress(raw).decode("utf-8", errors="replace"); method = "base64→zlib"
            except Exception: pass
        if decoded_str is None and len(raw) >= 4 and raw[1] == 0:
            try:
                s = raw.decode("utf-16-le")
                if _is_printable_text(s.encode("utf-8", errors="replace"), 0.85):
                    decoded_str = s; method = "base64→utf-16-le"
            except UnicodeDecodeError: pass
        if decoded_str is None and _is_printable_text(raw, 0.85):
            decoded_str = raw.decode("utf-8", errors="replace"); method = "base64→utf-8"
        if decoded_str is None:
            continue
        hits.append({
            "blob": blob[:64] + ("…" if len(blob) > 64 else ""),
            "method": method,
            "decoded": decoded_str,
        })
    return hits


def _apply_next(current: str, steps_so_far: List[Dict[str, Any]], notes: List[str]) -> Tuple[str, Dict, str, str] | None:
    """Pick the single most appropriate op to apply next. Return (op_id, args, reason, new_value) or None."""

    # 1. PowerShell -EncodedCommand   (highest priority — very specific pattern)
    m = _PS_ENCODED_RE.search(current)
    if m:
        # Join lines & strip whitespace/non-base64 chars from the payload
        payload_b64 = re.sub(r"[^A-Za-z0-9+/=]", "", m.group(1))
        raw = _try_base64(payload_b64)
        if raw is not None:
            # PowerShell -EncodedCommand is ALWAYS UTF-16LE
            decoded = raw.decode("utf-16-le", errors="ignore")
            return ("powershell-encoded", {}, "Detected PowerShell -EncodedCommand base64 payload (UTF-16LE)", decoded)

    # 2. PowerShell char-array / tick obfuscation
    if _PS_CHAR_ARR_RE.search(current) or (_PS_TICK_RE.search(current) and re.search(r"\bpowershell|iex|invoke-expression|new-object\b", current, re.IGNORECASE)):
        new_val = run_operation("powershell-deobfuscate", current)
        if new_val != current:
            return ("powershell-deobfuscate", {}, "Detected PowerShell obfuscation (tick / [char[]] / [char]NN)", new_val)

    # 3. CMD.exe obfuscation (carets, quoted-string breaks)
    if _CMD_CARET_RE.search(current) and re.search(r"cmd(\.exe)?|/c\s|/k\s", current, re.IGNORECASE):
        new_val = run_operation("cmd-deobfuscate", current)
        if new_val != current:
            return ("cmd-deobfuscate", {}, "Detected CMD.exe caret obfuscation", new_val)

    # 4. Defanged IOCs → refang
    if _DEFANGED_RE.search(current):
        new_val = run_operation("refang-iocs", current)
        if new_val != current:
            return ("refang-iocs", {}, "Defanged IOCs detected (hxxp / [.] / [@])", new_val)

    # 5. URL encoding
    if _URL_ENC_RE.search(current) and len(_URL_ENC_RE.findall(current)) >= 2:
        new_val = run_operation("url-decode", current)
        if new_val != current:
            return ("url-decode", {}, "URL percent-encoded characters detected", new_val)

    # 6. HTML entities
    if _HTML_ENT_RE.search(current):
        new_val = run_operation("html-decode", current)
        if new_val != current:
            return ("html-decode", {}, "HTML entities detected", new_val)

    # 7. JavaScript charcode
    if _JS_CHARCODE_RE.search(current):
        new_val = run_operation("js-charcode", current)
        if new_val != current:
            return ("js-charcode", {}, "JavaScript String.fromCharCode() detected", new_val)

    # 8. \xNN / \uNNNN escapes
    if _JS_HEX_ESC_RE.search(current):
        new_val = run_operation("js-unescape", current)
        if new_val != current:
            return ("js-unescape", {}, "\\xNN hex escapes detected", new_val)
    if _UNICODE_ESC_RE.search(current):
        try:
            new_val = run_operation("unicode-escape", current)
            if new_val != current:
                return ("unicode-escape", {}, "\\uNNNN unicode escapes detected", new_val)
        except Exception:
            pass

    # 9. Whole-input Base64 candidates (with intelligent gzip/zlib/utf16 chaining)
    if _looks_like_base64(current):
        raw = _try_base64(current)
        if raw is not None:
            # Compression magics — gzip / zlib / lzma / bzip2
            bin_op = _bin_magic_op(raw)
            if bin_op:
                op_id, decoded = bin_op
                return (op_id, {}, f"Base64 → {op_id} magic detected", decoded)
            # UTF-16LE readable text
            if len(raw) >= 4 and raw[1] == 0:
                try:
                    dec = raw.decode("utf-16-le")
                    if _is_printable_text(dec.encode("utf-8", errors="replace"), 0.9):
                        return ("base64-decode", {}, "Base64 payload with UTF-16LE text", dec)
                except UnicodeDecodeError:
                    pass
            # plain UTF-8 text
            if _is_printable_text(raw, 0.9):
                dec = raw.decode("utf-8", errors="replace")
                # avoid identity ops (already ascii and matches trivially)
                if dec != current:
                    return ("base64-decode", {}, "Base64-encoded printable text detected", dec)

    # 10. Hex-only blob → decode
    if _looks_like_hex(current):
        try:
            new_val = run_operation("hex-decode", current)
            if _is_printable_text(new_val.encode("utf-8", errors="replace"), 0.85):
                return ("hex-decode", {}, "Hex-encoded printable payload detected", new_val)
        except Exception:
            pass

    # 11. Gzip magic in raw hex-ish form
    if current.strip().lower().startswith("1f8b"):
        try:
            new_val = run_operation("gzip-decompress", current)
            return ("gzip-decompress", {}, "Gzip magic bytes detected", new_val)
        except Exception:
            pass

    return None


# ---------------------------------------------------------------------------
# Extract embedded base64 blobs   (fallback if whole-input isn't base64)
# ---------------------------------------------------------------------------
def extract_and_decode_embedded_b64(text: str) -> List[Dict[str, str]]:
    """Find long base64 blobs embedded inside text and try to decode them."""
    hits = []
    for m in re.finditer(r"[A-Za-z0-9+/]{40,}={0,2}", text):
        blob = m.group(0)
        raw = _try_base64(blob)
        if not raw:
            continue
        # try gzip → zlib → utf16le → utf8
        for name, fn in [
            ("gzip", lambda r: gzip.decompress(r)),
            ("zlib", lambda r: zlib.decompress(r)),
            ("utf-16-le", lambda r: r.decode("utf-16-le").encode("utf-8", "replace")),
            ("utf-8", lambda r: r if _is_printable_text(r) else None),
        ]:
            try:
                out = fn(raw)
                if not out:
                    continue
                s = out.decode("utf-8", errors="replace") if isinstance(out, (bytes, bytearray)) else str(out)
                if _is_printable_text(s.encode("utf-8", "replace"), 0.85):
                    hits.append({"blob": blob[:80] + ("..." if len(blob) > 80 else ""), "method": f"base64→{name}", "decoded": s})
                    break
            except Exception:
                continue
    return hits
