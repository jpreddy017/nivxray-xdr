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
    """base64 → gzip decompress, resilient to padding/length corruption
    AND to truncated gzip streams (partial decompression recovers whatever
    bytes were successfully emitted before the truncation).
    """
    raw = robust_b64decode(blob)
    try:
        return gzip.decompress(raw).decode("utf-8", errors="replace")
    except (EOFError, OSError, zlib.error):
        # Truncated stream — recover whatever we can via a streaming decompressor.
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
    r"\[(?:System\.)?Text\.Encoding\][^\n]{0,80}\.GetString\s*\("
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
    # PowerShell -EncodedCommand payloads are always UTF-16LE
    return raw.decode("utf-16le", errors="replace")


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


ARCHETYPES: List[Dict[str, Any]] = [
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
        "id": "PS_FromBase64String_UTF16LE",
        "description": "PowerShell FromBase64String + Encoding.Unicode.GetString (UTF-16LE)",
        "chain": ["extract-b64", "utf16le-decode"],
        "handler": _handle_ps_fb64_utf16,
        "match":   lambda t: bool(_PS_FB64_UTF16_RX.search(t)),
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
]


def try_archetypes(text: str) -> Optional[Dict[str, Any]]:
    """Try every archetype in registry order; return the FIRST successful decode.

    Return shape (matches deterministic_best_decode's return contract):
        {
          "output": "<decoded>",
          "engine": "archetype:<id>",
          "steps":  [{"op": step, "args": {}}, ...],
          "score":  1.0,
          "reached_shellcode": False,
          "notes":  ["matched archetype ..."],
          "archetype_id": "<id>",
          "archetype_desc": "<desc>",
        }
    Returns None if no archetype matched.
    """
    for arch in ARCHETYPES:
        try:
            if not arch["match"](text):
                continue
            out = arch["handler"](text)
            if isinstance(out, str) and out.strip():
                return {
                    "output": out,
                    "engine": f"archetype:{arch['id']}",
                    "steps":  [{"op": s, "args": {}} for s in arch["chain"]],
                    "score":  1.0,
                    "reached_shellcode": False,
                    "notes":  [f"Matched named wrapper archetype: {arch['description']}"],
                    "archetype_id":   arch["id"],
                    "archetype_desc": arch["description"],
                }
        except Exception:
            # Archetype's regex matched but its handler failed — try the next one
            continue
    return None
