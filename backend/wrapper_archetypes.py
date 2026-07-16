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
    # Try canonical UTF-16LE first — this is what PowerShell.exe -Enc requires
    try:
        candidate = raw.decode("utf-16le", errors="replace")
        if _looks_like_text(candidate):
            return candidate
    except Exception:
        pass
    # Fall back to UTF-8 (analyst pasted a malformed / hand-rolled -Enc)
    try:
        candidate = raw.decode("utf-8", errors="replace")
        if _looks_like_text(candidate):
            return candidate
    except Exception:
        pass
    # Last resort: latin-1 always succeeds
    return raw.decode("latin-1", errors="replace")


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


def _ps_reverse_string_matches(text: str) -> bool:
    if len(text) > 800:
        return False
    return _PS_REVERSE_STRING_RX.search(text) is not None


def _handle_ps_reverse_string(text: str) -> str:
    m = _PS_REVERSE_STRING_RX.search(text)
    if not m:
        raise ValueError("no ps-reverse-string span")
    reversed_str = m.group(1)
    plain = reversed_str[::-1]
    return text.replace(m.group(0), plain, 1)


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
    # Detect MZ (PE) header — always show the first 32 bytes hex-summary
    # so downstream sees "MZ..." for T1140 + PE-staging.
    head = raw[:32]
    hex_head = head.hex()
    is_pe = raw[:2] == b"MZ"
    try:
        readable = raw.decode("utf-8", errors="replace")
    except Exception:
        readable = raw.decode("latin-1", errors="replace")
    tag = "PE (MZ) image staged for execution" if is_pe else "opaque binary blob"
    return (
        text
        + "\n\n[CERTUTIL / PEM PAYLOAD DECODED]\n"
        + f"first_bytes_hex={hex_head}\n"
        + f"type={tag}\n"
        + f"decoded_text_preview={readable[:200]!r}"
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



ARCHETYPES: List[Dict[str, Any]] = [
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
        "match":   lambda t: bool(_PEM_BLOB_RX.search(t) or _CERTUTIL_STAGING_RX.search(t)),
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
