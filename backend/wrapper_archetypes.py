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
#    The whole point of this archetype is to STOP the current pipeline from
#    stripping the wrapper down to a bare digit run (which is what
#    `extract-payload` currently does — the `-bxor` metadata is lost). This
#    handler recovers the ORIGINAL PowerShell script (`Write-Host 'Hello…'`
#    or a malicious payload) in a single pass, no LLM required.
_PS_ASCII_XOR_IEX_INTS_RX = re.compile(
    r"\(\s*(?P<ints>(?:\d{1,3}\s*,\s*){3,}\d{1,3})\s*\)",
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
    # Extract only 1-3 digit tokens between 0 and 255. Anything else is noise.
    tokens = re.findall(r"\d{1,3}", ints_raw)
    nums = [int(t) for t in tokens if 0 <= int(t) <= 255]
    if len(nums) < 4:
        raise ValueError("integer list too short")
    decoded = "".join(chr(n ^ key) for n in nums)
    # Sanity: decoded must be predominantly printable ASCII/UTF-8.
    printable = sum(1 for c in decoded if 32 <= ord(c) < 127 or c in "\r\n\t")
    if printable / max(1, len(decoded)) < 0.80:
        raise ValueError("xor result not printable — key mismatch")
    return decoded


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
    for _ in range(max_depth):
        matched = False
        for arch in ARCHETYPES:
            try:
                if not arch["match"](current):
                    continue
                out = arch["handler"](current)
                if isinstance(out, str) and out.strip() and out != current:
                    fired.append({"id": arch["id"], "desc": arch["description"],
                                  "chain": arch["chain"], "output": out})
                    current = out
                    matched = True
                    break
            except Exception:
                continue
        if not matched:
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
    }
