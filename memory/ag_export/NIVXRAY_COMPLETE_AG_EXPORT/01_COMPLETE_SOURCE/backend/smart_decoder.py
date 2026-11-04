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

    # ── v1.3.3 · Concatenated base64 payload reconstruction ─────────────
    # Emotet / IcedID / Cobalt Strike downloaders split their base64 blob
    # across `'chunk1'+'chunk2'+...` (each chunk may embed `{0}` / `{1}`
    # format placeholders that get resolved by a `-f` operator elsewhere in
    # the script). We concatenate every quoted b64-shape chunk along a `+`
    # chain, run ps_normalize to resolve any format placeholders, then
    # decode the resulting joined blob. Almost always a gzip / PE payload.
    def _find_concat_chain(text: str, qc: str) -> str:
        # Allow base64 chars + `{d}` format placeholders + `/`+`-`+`_` for
        # URL-safe base64 variants inside chunks. Upper bound is generous
        # (up to 500 chars per chunk) so bulk-chunk splits don't break the
        # chain mid-run.
        chunk = qc + r"[A-Za-z0-9+/=_\-{}]{4,500}" + qc
        chain_pat = r"(?:" + chunk + r"\s*\+\s*){4,}" + chunk
        best = ""
        for m in re.finditer(chain_pat, text):
            joined = "".join(re.findall(qc + r"([A-Za-z0-9+/=_\-{}]{4,500})" + qc, m.group(0)))
            if len(joined) > len(best):
                best = joined
        return best

    _best_chain = ""
    for qc in ("'", '"'):
        cand = _find_concat_chain(payload, qc)
        if len(cand) > len(_best_chain):
            _best_chain = cand
    if _best_chain and len(_best_chain) >= 60:
        # Resolve `{0}` / `{1}` placeholders via ps_normalize if the input
        # has a `-f` format-operator argument list nearby.
        resolved = _best_chain
        if "{" in resolved:
            try:
                from ps_normalize import normalize_if_powershell
                # Feed the FULL input through normalize so `-f` args are visible;
                # then extract the same chain from the normalised text.
                norm_text, _ = normalize_if_powershell(payload)
                for qc in ("'", '"'):
                    cand = _find_concat_chain(norm_text, qc)
                    if len(cand) > len(resolved):
                        resolved = cand
            except Exception:
                pass
        # If placeholders remain, strip them so base64 decode can proceed.
        cleaned_blob = re.sub(r"\{[0-9]+\}", "", resolved)
        _raw = _try_base64(cleaned_blob) if len(cleaned_blob) >= 60 else None
        if _raw is not None:
            _n_chunks = payload.count("'+'") + payload.count('"+"') + 1
            steps.append({
                "op": "extract-b64-concat", "args": {},
                "reason": f"Reconstructed split base64 payload from ~{_n_chunks} concatenated chunks ({len(cleaned_blob)} chars total)",
            })
            current = cleaned_blob
            notes.append("Concatenated-base64 payload reconstructed before decode chain")
            bin_op = _bin_magic_op(_raw)
            if bin_op:
                op_id, decoded = bin_op
                steps.append({"op": op_id, "args": {}, "reason": f"Concat payload → {op_id}"})
                current = decoded

    # THUMB RULE: ISOLATE THE PAYLOAD STRING FIRST.
    # If the input is a full script wrapper (variable assignment, cmdlet call,
    # bash pipeline), extract the enclosed base64 payload before running any
    # decoder recipe on it.
    isolated_flag = False
    if not steps:  # Skip isolation if concat-reconstruct already fired.
        isolated = sanitize_encapsulated_payload(payload)
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
    #    Primary trigger: ≥2 percent-escapes (avoids false-positives on prose
    #    containing a single stray `%`).
    #    v1.5.6: also fire on a SINGLE percent-escape when the encoded byte
    #    sits at position 0 or in the final 3 chars AND the rest of the
    #    string is pure base64/hex charset — this is the fingerprint of
    #    `URL(rev(b64(P)))` and `URL(b64(P))` tradecraft where the reversed
    #    b64 padding (`=` → `%3D`) is the only surviving %-escape.
    _url_hits = _URL_ENC_RE.findall(current)
    _fire_url = False
    if len(_url_hits) >= 2:
        _fire_url = True
    elif len(_url_hits) == 1:
        m = _URL_ENC_RE.search(current)
        pos = m.start() if m else -1
        edge = pos == 0 or pos >= len(current) - 3
        remainder = _URL_ENC_RE.sub("", current)
        # remainder must be non-empty AND look like a codec-charset blob
        if edge and len(remainder) >= 16 and (
            re.fullmatch(r"[A-Za-z0-9+/=_\-]+", remainder) or
            re.fullmatch(r"[0-9a-fA-F]+", remainder)
        ):
            _fire_url = True
    if _fire_url:
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

    # 8.5. Reverse-string heuristic (Feb 2026 v1.3.1, expanded v1.4.1) ————
    # `echo … | rev | base64` and `xxd -p | rev` tradecraft. We attempt a
    # reversal ONLY IF: (a) we haven't just reversed on the previous step
    # (prevents ping-pong on symmetric charsets like pure hex), AND (b) the
    # reversed text decodes to something with a KNOWN binary magic OR non-
    # ambiguous plaintext (contains characters outside the current charset),
    # OR (c) the reversed text is a b64 blob whose decode is ITSELF another
    # b64/hex chain that eventually terminates in a magic byte (deep multi-
    # layer real-world tradecraft — Sophos / TrendMicro corpus).
    _last_op = steps_so_far[-1]["op"] if steps_so_far else None
    _rev = current[::-1]
    # ── Explicit tell: text STARTS with `=` = base64 padding was at END
    # before reversal. This is a near-certain reversed-b64 signature; we
    # loosen the strong-signal requirement in that case.
    _starts_with_pad = bool(current) and current[0] == "="
    if _last_op != "reverse" and _rev != current and len(_rev) >= 16:

        def _has_strong_signal(_raw: bytes, _depth: int = 0) -> bool:
            """A signal is 'strong' if the raw bytes contain a magic prefix
            OR decode to text that has whitespace / non-alphanumeric structure
            (i.e., real words, not just charset-shaped noise).

            v1.4.1: also allow charset-shape noise (pure b64 / pure hex) IF
            that noise ITSELF decodes to a magic byte / real text within
            <=2 recursive steps. This catches deep multi-layer reversed
            chains where the intermediate layers are pure charset."""
            if _bin_magic_op(_raw) is not None:
                return True
            if _raw[:2] == b"MZ" or _raw[:4] == b"\x7fELF":
                return True
            try:
                s = _raw.decode("utf-8")
            except UnicodeDecodeError:
                return False
            if not _is_printable_text(_raw, 0.9):
                return False
            # Real-words test — has whitespace or non-alphanumeric punctuation.
            if re.fullmatch(r"[0-9a-fA-F]+", s) or re.fullmatch(r"[A-Za-z0-9+/=]+", s):
                # v1.4.1: recurse ONE more level. If this charset-shape blob
                # decodes to a magic byte or true plaintext underneath, ACCEPT.
                if _depth >= 2:
                    return False
                # Try b64 first if it fits the charset
                if re.fullmatch(r"[A-Za-z0-9+/=]+", s):
                    _inner = _try_base64(s)
                    if _inner is not None and _has_strong_signal(_inner, _depth + 1):
                        return True
                # Try hex
                if re.fullmatch(r"[0-9a-fA-F]+", s) and len(s) % 2 == 0:
                    try:
                        _hex_inner = bytes.fromhex(s)
                        if _has_strong_signal(_hex_inner, _depth + 1):
                            return True
                    except (ValueError, binascii.Error):
                        pass
                return False
            return True

        # Case A — reversed is valid base64 that decodes with a strong signal.
        # If the original text starts with `=`, we KNOW this is reversed b64
        # (`=` is only ever base64 padding, and it's always at the tail); we
        # skip the strong-signal gate in that case.
        if _looks_like_base64(_rev):
            _raw = _try_base64(_rev)
            if _raw is not None and (_starts_with_pad or _has_strong_signal(_raw)):
                reason = (
                    "Reversed text is a base64 blob (input started with `=` padding, near-certain reversed-b64)"
                    if _starts_with_pad
                    else "Reversed text is a base64 blob with a real payload underneath"
                )
                return ("reverse", {}, reason, _rev)
        # Case B — reversed is valid hex that decodes with a strong signal
        if _looks_like_hex(_rev):
            try:
                _hex_raw = bytes.fromhex(re.sub(r"[\s,\-]", "", _rev))
                if _has_strong_signal(_hex_raw):
                    return ("reverse", {},
                            "Reversed text is hex-encoded with a real payload underneath",
                            _rev)
                # Special case: reversed hex decodes to something that's
                # itself the base64 charset (i.e., after unhex we get a b64
                # string). This is the `xxd -p | rev | base64` middle layer.
                try:
                    _hex_str = _hex_raw.decode("latin1")
                    if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", _hex_str) and len(_hex_str) >= 24:
                        # Confirm the b64 decodes to a magic or printable text
                        _inner = _try_base64(_hex_str)
                        if _inner is not None and (_bin_magic_op(_inner) or _is_printable_text(_inner, 0.85)):
                            return ("reverse", {},
                                    "Reversed hex unpacks to a base64 blob of real payload",
                                    _rev)
                except (UnicodeDecodeError, ValueError):
                    pass
            except (ValueError, binascii.Error):
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
