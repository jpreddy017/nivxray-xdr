"""NivXRay PowerShell Deterministic Deobfuscator (2026-07-25).

Recursive, deterministic transformation engine. Runs safe .NET-style
operations (String.Format, Join, Convert.ToInt16, Base64, char array
reconstruction, octal / hex / decimal decoders) until no further
reversible transformation remains OR a true execution boundary is hit.

Contract (locked with SOC user 2026-07-25):
    • Safe operations only — NEVER execute Invoke-Expression, ScriptBlocks,
      Reflection.Assembly.Load, Add-Type, COM, WMI, Win32 APIs.
    • Every transformation is logged as a stage: {technique, evidence,
      before_snippet, after_snippet, offset}.
    • Recursion capped at MAX_STAGES to prevent runaway loops on adversarial
      input.
    • Deterministic — same input → same output → same stage chain.
"""
from __future__ import annotations

import base64
import binascii
import gzip as _gzip_lib
import hashlib as _hashlib
import io as _io
import re
import time as _time
import zlib as _zlib_lib
from dataclasses import dataclass, field, asdict

try:
    import brotli as _brotli_lib          # type: ignore
except Exception:                          # pragma: no cover
    _brotli_lib = None                     # runtime-optional

try:
    from cryptography.hazmat.primitives.ciphers import (
        Cipher as _Cipher, algorithms as _algs, modes as _modes,
    )
    _AES_LIB_OK = True
except Exception:                          # pragma: no cover
    _AES_LIB_OK = False


MAX_STAGES = 32


# ── Alias table (safe deterministic renames) ─────────────────────
_ALIASES = {
    r"\biex\b":  "Invoke-Expression",
    r"\biwr\b":  "Invoke-WebRequest",
    r"\birm\b":  "Invoke-RestMethod",
    r"\bsaps\b": "Start-Process",
    r"\bgv\b":   "Get-Variable",
    r"\bgc\b":   "Get-Content",
    r"\bsv\b":   "Set-Variable",
    r"\bsal\b":  "Set-Alias",
    r"\bni\b":   "New-Item",
    r"\bgci\b":  "Get-ChildItem",
    r"\bgps\b":  "Get-Process",
    r"\bgsv\b":  "Get-Service",
}


@dataclass
class Stage:
    n: int
    technique: str          # analyst-facing label
    evidence: str           # what pattern was matched
    before: str             # snippet before transformation (≤ 200 chars)
    after: str              # snippet after transformation (≤ 200 chars)
    offset: int = 0         # position in the payload where the transform applied
    # ── Phase 2 · Crypto classification (2026-07-27) ────────────────
    status: str | None = None
    unsupported_reason: str | None = None
    # ── Phase 2 · Batch 2 · Evidence preservation (2026-07-27) ──────
    # These fields make the chain fully auditable — analyst can verify
    # input_hash → output_hash for every transformation, and see how
    # long each step took plus the deobfuscator's self-reported
    # confidence in the transform.
    input_hash:    str | None = None      # sha256[:16] of `before` (transformed slice)
    output_hash:   str | None = None      # sha256[:16] of `after`
    input_length:  int = 0
    output_length: int = 0
    elapsed_ms:    float = 0.0
    confidence:    int = 95               # deobfuscator's confidence 0-100

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DeobfuscationReport:
    original:       str
    final:          str
    stages:         list[Stage] = field(default_factory=list)
    stopped_reason: str = ""    # boundary hit | max_stages | fixed_point | recursion_limit_reached
    boundary_op:    str = ""    # e.g. "Invoke-Expression" | "" if none
    # Aggregated crypto verdict rolled up from stages (worst wins).
    crypto_status:  str = ""    # fully_decrypted | partially_decrypted | encryption_detected | ""
    # Structured reasons the decoder halted / could not proceed. These
    # are ALSO reused by non-crypto resolvers (see KnownUnsupportedReason).
    unsupported_reasons: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "original":            self.original[:2000],
            "final":               self.final,
            "stages":              [s.to_dict() for s in self.stages],
            "stopped_reason":      self.stopped_reason,
            "boundary_op":         self.boundary_op,
            "crypto_status":       self.crypto_status,
            "unsupported_reasons": self.unsupported_reasons,
        }


# ── Known Unsupported Reasons (Phase 2 · 2026-07-27) ─────────────
# General-purpose reason codes usable across the semantic engine.
# Locked with SOC user 2026-07-27 as the OFFICIAL taxonomy — new
# reasons may be added but existing codes MUST be stable so downstream
# dashboards and playbooks don't break.
class KnownUnsupportedReason:
    RUNTIME_GENERATED_KEY   = "runtime_generated_key"
    DYNAMIC_EXECUTION       = "dynamic_execution"
    REFLECTION              = "reflection"
    NATIVE_SHELLCODE        = "native_shellcode"
    MEMORY_ONLY_OBJECT      = "memory_only_object"
    EXTERNAL_DEPENDENCY     = "external_dependency"
    NETWORK_FETCH_REQUIRED  = "network_fetch_required"
    USER_INPUT_REQUIRED     = "user_input_required"
    ENVIRONMENT_DEPENDENT   = "environment_dependent"
    UNKNOWN_ALGORITHM       = "unknown_algorithm"
    UNSUPPORTED_ALGORITHM   = "unsupported_algorithm"

    @classmethod
    def all(cls) -> list[str]:
        return [v for k, v in vars(cls).items()
                if not k.startswith("_") and isinstance(v, str)]


# Crypto status roll-up ranking. Highest severity wins in the final report.
_CRYPTO_STATUS_RANK = {
    "":                    -1,
    "fully_decrypted":       0,
    "partially_decrypted":   1,
    "encryption_detected":   2,
}


# ── Format-string resolver ───────────────────────────────────────
# Match `'fmt' -f 'a','b','c'` — simpler regex, no catastrophic backtracking
_FORMAT_RE = re.compile(
    r"(['\"])([^'\"]*?\{\d+\}[^'\"]*?)\1"       # 'fmt with {N} placeholders'
    r"\s*-f\s*"
    r"((?:\s*(['\"])[^'\"]*?\4\s*,?\s*)+)",
    re.DOTALL,
)


def _resolve_format(txt: str, stages: list[Stage]) -> tuple[str, bool]:
    """Replace `'fmt' -f 'a','b','c'` occurrences with the folded string."""
    def _repl(m: re.Match) -> str:
        fmt = m.group(2)
        args_blob = m.group(3)
        # Extract each simple quoted arg
        strs = [g[1] for g in re.findall(r"(['\"])([^'\"]*?)\1", args_blob)]
        try:
            def _sub(mm):
                idx_s = mm.group(1)
                idx = int(idx_s.split(",")[0].split(":")[0])
                return strs[idx] if 0 <= idx < len(strs) else mm.group(0)
            folded = re.sub(r"\{(\d+(?:,[^{}]*)?(?::[^{}]*)?)\}", _sub, fmt)
        except Exception:
            return m.group(0)
        return f"'{folded}'"
    new_txt, count = _FORMAT_RE.subn(_repl, txt)
    if count and new_txt != txt:
        stages.append(Stage(
            n=len(stages) + 1,
            technique="Resolve .NET string format",
            evidence=f"Matched {count} `-f` format expression(s).",
            before=txt[:200], after=new_txt[:200],
        ))
        return new_txt, True
    return txt, False


# ── String concat `'a' + 'b'` ────────────────────────────────────
_CONCAT_RE = re.compile(r"(['\"])([^'\"]*?)\1\s*\+\s*(['\"])([^'\"]*?)\3")


def _resolve_concat(txt: str, stages: list[Stage]) -> tuple[str, bool]:
    changed = False
    for _ in range(10):
        new_txt, count = _CONCAT_RE.subn(
            lambda m: f"'{m.group(2)}{m.group(4)}'", txt)
        if not count:
            break
        txt = new_txt
        changed = True
    if changed:
        stages.append(Stage(
            n=len(stages) + 1,
            technique="Resolve string concatenation",
            evidence="Merged `'a' + 'b'` literals.",
            before="", after=txt[:200],
        ))
    return txt, changed


# ── Backtick escape strip ────────────────────────────────────────
def _resolve_backticks(txt: str, stages: list[Stage]) -> tuple[str, bool]:
    new_txt = re.sub(r"`([a-zA-Z_])", r"\1", txt)
    if new_txt != txt:
        stages.append(Stage(
            n=len(stages) + 1,
            technique="Resolve backtick escapes",
            evidence="Stripped PowerShell backtick escapes.",
            before=txt[:200], after=new_txt[:200],
        ))
        return new_txt, True
    return txt, False


# ── Alias expansion ──────────────────────────────────────────────
def _resolve_aliases(txt: str, stages: list[Stage]) -> tuple[str, bool]:
    changed = False
    for pat, full in _ALIASES.items():
        new_txt = re.sub(pat, full, txt, flags=re.IGNORECASE)
        if new_txt != txt:
            txt = new_txt
            changed = True
    if changed:
        stages.append(Stage(
            n=len(stages) + 1,
            technique="Resolve cmdlet aliases",
            evidence="Expanded PowerShell aliases (iex→Invoke-Expression, etc.).",
            before="", after=txt[:200],
        ))
    return txt, changed


# ── Numeric char-array reconstruction (octal/hex/decimal) ────────
# Matches things like:
#   (127,162,151,164,145) | %{ [char]([Convert]::ToInt16(([string]$_),8)) }
#   (0x57, 0x72, 0x69) | %{ [char]$_ }
#   [char[]](87,114,105,116,101)
_NUM_LIST_RE = re.compile(
    r"\(\s*((?:[0-9a-fA-Fx]+\s*,\s*){2,}[0-9a-fA-Fx]+)\s*\)"
)


def _parse_number(tok: str, base: int) -> int | None:
    tok = tok.strip()
    try:
        if tok.lower().startswith("0x"):
            return int(tok, 16)
        return int(tok, base)
    except Exception:
        return None


def _resolve_numeric_char_reconstruction(txt: str, stages: list[Stage]) -> tuple[str, bool]:
    """Detect (n1, n2, …) coupled with a `[char]([Convert]::ToInt16(…,BASE))`
    or `[char[]](…)` construction, fold the array into a literal string."""
    # Find all `(N1,N2,N3,…)` numeric lists and check their context for a
    # `[char]` / `Convert::ToInt16(...,BASE)` marker within 200 chars.
    changed = False
    for m in list(_NUM_LIST_RE.finditer(txt)):
        list_text = m.group(1)
        raw_tokens = [t.strip() for t in list_text.split(",") if t.strip()]
        # Peek ±200 chars for base indicator
        ctx = txt[max(0, m.start() - 300): m.end() + 300]
        base = None
        technique = None
        if re.search(r"convert\]::toint(?:16|32)\s*\(.*?,\s*8\s*\)", ctx, re.I | re.S):
            base = 8;  technique = "Octal ASCII reconstruction"
        elif re.search(r"convert\]::toint(?:16|32)\s*\(.*?,\s*16\s*\)", ctx, re.I | re.S):
            base = 16; technique = "Hex ASCII reconstruction"
        elif re.search(r"convert\]::toint(?:16|32)\s*\(.*?,\s*2\s*\)", ctx, re.I | re.S):
            base = 2;  technique = "Binary ASCII reconstruction"
        elif re.search(r"\[char\s*\[\s*\]\s*\]", ctx, re.I) or \
             re.search(r"\|\s*%\s*\{\s*\[char\]", ctx, re.I):
            base = 10; technique = "Decimal char[] reconstruction"
        if base is None:
            continue
        # Decode each token in the chosen base
        chars: list[str] = []
        for tok in raw_tokens:
            n = _parse_number(tok, base)
            if n is None or not (0 <= n < 0x110000):
                chars = []
                break
            try:
                chars.append(chr(n))
            except Exception:
                chars = []; break
        if not chars:
            continue
        recovered = "".join(chars)
        # Replace the WHOLE construction (list + surrounding pipeline) with the
        # recovered string literal wrapped in quotes.
        # We look for the enclosing `( … ) | %{ … } ` or `[char[]](…)` — take
        # the outermost of the two markers around the list.
        span_start, span_end = m.start(), m.end()
        # Extend to swallow the `| %{ ... }` tail if present
        tail = re.match(r"\s*\|\s*%\s*\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", txt[span_end:], re.S)
        if tail:
            span_end += tail.end()
        # Extend backward for `[char[]]` prefix
        head_prefix = re.search(r"\[char(?:\[\s*\])?\s*\]\s*$", txt[:span_start], re.I)
        if head_prefix:
            span_start = head_prefix.start()
        replacement = f"'{recovered}'"
        txt = txt[:span_start] + replacement + txt[span_end:]
        stages.append(Stage(
            n=len(stages) + 1,
            technique=technique,
            evidence=(f"Recovered {len(recovered)} chars from a "
                       f"{len(raw_tokens)}-element base-{base} integer array."),
            before=list_text[:200],
            after=recovered[:200],
            offset=span_start,
        ))
        changed = True
        break   # Restart from top of loop — text has shifted
    return txt, changed


# ── [Convert]::FromBase64String("...") ───────────────────────────
_B64_STATIC_RE = re.compile(
    r"\[?\s*(?:system\.)?convert\]?\s*::\s*frombase64string\s*\(\s*"
    r"(['\"])([A-Za-z0-9+/=]{8,})\1\s*\)",
    re.IGNORECASE,
)


def _resolve_static_base64(txt: str, stages: list[Stage]) -> tuple[str, bool]:
    changed = False
    for m in list(_B64_STATIC_RE.finditer(txt)):
        blob = m.group(2)
        try:
            raw = base64.b64decode(blob, validate=False)
        except binascii.Error:
            continue
        # Try to interpret as text — UTF-8 first (safest default for text
        # payloads wrapped in `[System.Text.Encoding]::UTF8.GetString(...)`),
        # then UTF-16LE (PowerShell canonical for -EncodedCommand), then ASCII.
        decoded = None
        for enc in ("utf-8", "utf-16-le", "ascii"):
            try:
                decoded = raw.decode(enc, errors="strict")
                break
            except Exception:
                continue
        if decoded is None:
            continue
        # Skip if replacement produces junk
        if len(decoded) < 3 or not any(c.isalpha() for c in decoded):
            continue
        replacement = f"'{decoded}'"
        txt = txt[:m.start()] + replacement + txt[m.end():]
        stages.append(Stage(
            n=len(stages) + 1,
            technique="Decode Base64 payload",
            evidence=(f"Statically evaluated `[Convert]::FromBase64String` on a "
                       f"{len(blob)}-char blob."),
            before=blob[:80], after=decoded[:200],
        ))
        changed = True
        break
    return txt, changed


# ── UTF-16LE Base64 via [Encoding]::Unicode.GetString([Convert]::FromBase64String(...)) ──
# 2026-07-27 · SOC user Phase 1 corpus expansion (naked-script encodings).
# Matches the common PowerShell idiom used by Empire / Invoke-Obfuscation
# to hide UTF-16LE-encoded scripts inside a Base64 blob.
_UTF16_B64_RE = re.compile(
    r"\[?\s*(?:system\.)?text\.encoding\]?\s*::\s*unicode\s*\.\s*getstring"
    r"\s*\(\s*"
    r"\[?\s*(?:system\.)?convert\]?\s*::\s*frombase64string\s*\(\s*"
    r"(['\"])([A-Za-z0-9+/=]{8,})\1\s*\)\s*\)",
    re.IGNORECASE | re.DOTALL,
)


def _resolve_utf16le_base64(txt: str, stages: list[Stage]) -> tuple[str, bool]:
    for m in list(_UTF16_B64_RE.finditer(txt)):
        blob = m.group(2)
        try:
            raw = base64.b64decode(blob, validate=False)
            decoded = raw.decode("utf-16-le", errors="strict")
        except Exception:
            continue
        if len(decoded) < 3 or not any(c.isalpha() for c in decoded):
            continue
        replacement = f"'{decoded}'"
        txt = txt[:m.start()] + replacement + txt[m.end():]
        stages.append(Stage(
            n=len(stages) + 1,
            technique="Decode UTF-16LE Base64",
            evidence=(f"Statically evaluated `[Encoding]::Unicode.GetString(FromBase64String(...))` "
                       f"on a {len(blob)}-char blob."),
            before=blob[:80], after=decoded[:200],
        ))
        return txt, True
    return txt, False


# ── Compression streams (GZip / Deflate / Brotli) over a Base64 blob ─
# Matches the common .NET pattern:
#   [IO.Compression.GzipStream]::new(
#       [IO.MemoryStream][Convert]::FromBase64String("..."),
#       [IO.Compression.CompressionMode]::Decompress)
# and its close relatives with `.Read` / `StreamReader` wrappers.
_COMPRESSION_RE = re.compile(
    r"(?ixs)"
    r"\[?\s*(?:system\.)?io\.compression\.(gzip|deflate|brotli)stream\]?"
    r".{0,500}?"
    r"\[?\s*(?:system\.)?convert\]?\s*::\s*frombase64string\s*\(\s*"
    r"(['\"])([A-Za-z0-9+/=]{8,})\2\s*\)"
    r".{0,200}?compressionmode\]?\s*::\s*decompress"
)

_COMPRESSION_TECHNIQUE = {
    "gzip":    ("Decompress GZip stream",    "gzip"),
    "deflate": ("Decompress Deflate stream", "deflate"),
    "brotli":  ("Decompress Brotli stream",  "brotli"),
}


def _decompress(kind: str, raw: bytes) -> bytes | None:
    try:
        if kind == "gzip":
            return _gzip_lib.decompress(raw)
        if kind == "deflate":
            # PowerShell's DeflateStream emits raw deflate (no zlib header)
            return _zlib_lib.decompress(raw, -_zlib_lib.MAX_WBITS)
        if kind == "brotli":
            if _brotli_lib is None:
                return None
            return _brotli_lib.decompress(raw)
    except Exception:
        return None
    return None


def _resolve_compression_stream(txt: str, stages: list[Stage]) -> tuple[str, bool]:
    for m in list(_COMPRESSION_RE.finditer(txt)):
        kind = m.group(1).lower()
        blob = m.group(3)
        try:
            raw = base64.b64decode(blob, validate=False)
        except binascii.Error:
            continue
        decompressed = _decompress(kind, raw)
        if decompressed is None:
            continue
        # Interpret as text. Prefer UTF-16LE when the decompressed data
        # shows the classic every-other-null pattern (>=25% null bytes
        # AND first byte not null) — otherwise UTF-8, then ASCII.
        decoded = None
        _has_null_pattern = (len(decompressed) >= 4
                              and decompressed.count(b"\x00") >= max(1, len(decompressed) // 4)
                              and decompressed[0:1] != b"\x00")
        _enc_order = (("utf-16-le", "utf-8", "ascii")
                       if _has_null_pattern
                       else ("utf-8", "utf-16-le", "ascii"))
        for enc in _enc_order:
            try:
                decoded = decompressed.decode(enc, errors="strict")
                break
            except Exception:
                continue
        if decoded is None or len(decoded) < 3 or not any(c.isalpha() for c in decoded):
            continue
        label, kind_str = _COMPRESSION_TECHNIQUE[kind]
        replacement = f"'{decoded}'"
        txt = txt[:m.start()] + replacement + txt[m.end():]
        stages.append(Stage(
            n=len(stages) + 1,
            technique=label,
            evidence=(f"Statically decompressed a {len(blob)}-char Base64 blob "
                       f"through `[IO.Compression.{kind_str.title()}Stream]` "
                       f"(recovered {len(decoded)} chars)."),
            before=blob[:80], after=decoded[:200],
        ))
        return txt, True
    return txt, False


# ── XOR loop over a byte array with a static key ──────────────────
# Matches the common Invoke-Obfuscation / Empire pattern:
#   $k=0x2A; $b=[Convert]::FromBase64String("..."); ($b|%{$_-bxor$k})
# Deterministic — decodes only when the key is a literal integer and the
# Base64 blob is a literal string.
_XOR_STATIC_RE = re.compile(
    r"(?ixs)"
    r"(?:\$\w+\s*=\s*(0x[0-9a-f]+|\d{1,4})\s*[;\r\n]+\s*)?"                   # optional $k=NN;
    r"(?:\$\w+\s*=\s*)?"                                                       # optional $b=
    r"\[?\s*(?:system\.)?convert\]?\s*::\s*frombase64string\s*\(\s*"
    r"(['\"])([A-Za-z0-9+/=]{8,})\2\s*\)"                                      # base64 literal
    r".{0,300}?"
    r"-\s*bxor\s*"
    r"(?:\$\w+|(0x[0-9a-f]+|\d{1,4}))"                                          # -bxor $k OR literal
)


def _resolve_static_xor(txt: str, stages: list[Stage]) -> tuple[str, bool]:
    for m in list(_XOR_STATIC_RE.finditer(txt)):
        key_str = m.group(1) or m.group(4)
        if not key_str:
            continue
        try:
            key = int(key_str, 0) & 0xFF
        except Exception:
            continue
        try:
            raw = base64.b64decode(m.group(3), validate=False)
        except binascii.Error:
            continue
        xored = bytes(b ^ key for b in raw)
        decoded = None
        for enc in ("utf-8", "utf-16-le", "ascii"):
            try:
                decoded = xored.decode(enc, errors="strict")
                break
            except Exception:
                continue
        if decoded is None or len(decoded) < 3 or not any(c.isalpha() for c in decoded):
            continue
        # Replace ONLY the `[Convert]::FromBase64String("...")` sub-expression
        # (found relative to the outer match) so the outer IEX / pipeline
        # wrapper stays visible for boundary detection.
        sub_start = m.start(2) - len("[Convert]::FromBase64String(")
        # Anchor precisely on the "[Convert]::FromBase64String(" prefix.
        inner_call_start = txt.rfind("FromBase64String", 0, m.start(2))
        if inner_call_start == -1:
            continue
        # Walk backwards to the `[` (optional) that starts the accessor.
        prefix_start = inner_call_start
        # Skip leading whitespace, optional `[system.]convert]::` prefix.
        # Find the '[' that opens the accessor if present.
        i = prefix_start
        while i > 0 and txt[i - 1] not in "\n;( \t":
            i -= 1
        replace_start = i
        replace_end = m.end(3) + 1  # include closing quote and ')'
        # Move end forward to include ")" after the base64 arg.
        while replace_end < len(txt) and txt[replace_end - 1] != ")":
            replace_end += 1
        replacement = f"'{decoded}'"
        txt = txt[:replace_start] + replacement + txt[replace_end:]
        stages.append(Stage(
            n=len(stages) + 1,
            technique="XOR single-byte decode",
            evidence=(f"Statically XORed a {len(m.group(3))}-char Base64 blob "
                       f"with key 0x{key:02x}; recovered {len(decoded)} chars."),
            before=m.group(3)[:80], after=decoded[:200],
            status="fully_decrypted",
        ))
        return txt, True
    return txt, False


# ── Multi-byte / repeating-key XOR ───────────────────────────────
# Matches the pattern where a repeating byte-array key is used:
#   $k = 0x2A,0x1B,0x77,0x03
#   $b = [Convert]::FromBase64String("...")
#   $out = for($i=0;$i -lt $b.Length;$i++) { $b[$i] -bxor $k[$i % $k.Length] }
# Deterministic — decodes only when both the key array literal and the
# base64 blob are statically present.
_XOR_MULTIBYTE_RE = re.compile(
    r"(?ixs)"
    r"\$\w+\s*=\s*"                                                              # $k =
    r"((?:\s*(?:0x[0-9a-f]+|\d{1,3})\s*,){1,63}\s*(?:0x[0-9a-f]+|\d{1,3}))"     # 2-64 byte array
    r".{0,400}?"
    r"\[?\s*(?:system\.)?convert\]?\s*::\s*frombase64string\s*\(\s*"
    r"(['\"])([A-Za-z0-9+/=]{8,})\2\s*\)"
    r".{0,600}?"
    r"-\s*bxor\s*\$\w+\s*\[\s*\$\w+\s*%\s*\$\w+\s*\.\s*length\s*\]"             # -bxor $k[$i % $k.Length]
)


def _resolve_multibyte_xor(txt: str, stages: list[Stage]) -> tuple[str, bool]:
    for m in list(_XOR_MULTIBYTE_RE.finditer(txt)):
        key_str = m.group(1)
        try:
            key = bytes(int(tok.strip(), 0) & 0xFF
                         for tok in key_str.split(",") if tok.strip())
        except Exception:
            continue
        if not key:
            continue
        try:
            raw = base64.b64decode(m.group(3), validate=False)
        except binascii.Error:
            continue
        xored = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))
        decoded = None
        for enc in ("utf-8", "utf-16-le", "ascii"):
            try:
                decoded = xored.decode(enc, errors="strict")
                break
            except Exception:
                continue
        if decoded is None or len(decoded) < 3 or not any(c.isalpha() for c in decoded):
            continue
        # Replace only the base64 sub-expression, preserve the outer
        # pipeline for boundary detection.
        b64_call_start = txt.rfind("FromBase64String", 0, m.start(3))
        if b64_call_start == -1:
            continue
        i = b64_call_start
        while i > 0 and txt[i - 1] not in "\n;( \t":
            i -= 1
        replace_start = i
        replace_end = m.end(3) + 1
        while replace_end < len(txt) and txt[replace_end - 1] != ")":
            replace_end += 1
        txt = txt[:replace_start] + f"'{decoded}'" + txt[replace_end:]
        stages.append(Stage(
            n=len(stages) + 1,
            technique="XOR multi-byte decode",
            evidence=(f"Repeating {len(key)}-byte XOR key applied over a "
                       f"{len(m.group(3))}-char Base64 blob; recovered "
                       f"{len(decoded)} chars."),
            before=m.group(3)[:80], after=decoded[:200],
            status="fully_decrypted",
        ))
        return txt, True
    return txt, False


# ── Rolling XOR (key derived deterministically from position, e.g. `$i`) ─
# Matches the pattern:
#   $b = [Convert]::FromBase64String("...")
#   $out = for($i=0;$i -lt $b.Length;$i++) { $b[$i] -bxor $i }
_XOR_ROLLING_RE = re.compile(
    r"(?ixs)"
    r"\[?\s*(?:system\.)?convert\]?\s*::\s*frombase64string\s*\(\s*"
    r"(['\"])([A-Za-z0-9+/=]{8,})\1\s*\)"
    r".{0,600}?"
    r"-\s*bxor\s*\$\w+\b(?!\s*\[)"                                              # -bxor $i (not $k[i])
)


def _resolve_rolling_xor(txt: str, stages: list[Stage]) -> tuple[str, bool]:
    # SAFETY GATE — if any runtime key source is nearby, refuse to
    # apply the deterministic rolling-XOR transform. The runtime-key
    # detector will emit the correct `encryption_detected` metadata
    # later. This prevents fabricating plaintext from a XOR whose
    # true key is only known at runtime.
    for pat, _reason, _label in _RUNTIME_KEY_SOURCES:
        if re.search(pat, txt, re.IGNORECASE):
            return txt, False
    for m in list(_XOR_ROLLING_RE.finditer(txt)):
        try:
            raw = base64.b64decode(m.group(2), validate=False)
        except binascii.Error:
            continue
        # Deterministic rolling XOR: byte[i] ^ i
        xored = bytes(b ^ (i & 0xFF) for i, b in enumerate(raw))
        decoded = None
        for enc in ("utf-8", "utf-16-le", "ascii"):
            try:
                decoded = xored.decode(enc, errors="strict")
                break
            except Exception:
                continue
        if decoded is None or len(decoded) < 3 or not any(c.isalpha() for c in decoded):
            continue
        b64_call_start = txt.rfind("FromBase64String", 0, m.start(2))
        if b64_call_start == -1:
            continue
        i = b64_call_start
        while i > 0 and txt[i - 1] not in "\n;( \t":
            i -= 1
        replace_start = i
        replace_end = m.end(2) + 1
        while replace_end < len(txt) and txt[replace_end - 1] != ")":
            replace_end += 1
        txt = txt[:replace_start] + f"'{decoded}'" + txt[replace_end:]
        stages.append(Stage(
            n=len(stages) + 1,
            technique="XOR rolling decode",
            evidence=(f"Rolling XOR (`byte[i] ^ i`) applied over a "
                       f"{len(m.group(2))}-char Base64 blob; recovered "
                       f"{len(decoded)} chars."),
            before=m.group(2)[:80], after=decoded[:200],
            status="fully_decrypted",
        ))
        return txt, True
    return txt, False


# ── RC4 (Rivest Cipher 4) — static literal key + literal base64 ciphertext ─
# Matches idioms observed in Empire, PoshC2, Metasploit:
#   $k = "abcdef"    OR    $k = [Text.Encoding]::UTF8.GetBytes("abcdef")
#   $c = [Convert]::FromBase64String("....")
#   ($rc4-body-that-references-$k-and-$c)
# We look for BOTH markers within a small window plus an explicit
# `-bxor` inside a for/while loop (the RC4 PRGA finalisation step).
_RC4_STATIC_RE = re.compile(
    r"(?ixs)"
    r"\$\w+\s*=\s*['\"]([^'\"]{3,64})['\"]"                                     # $k = "..."
    r".{0,600}?"
    r"\[?\s*(?:system\.)?convert\]?\s*::\s*frombase64string\s*\(\s*"
    r"(['\"])([A-Za-z0-9+/=]{8,})\2\s*\)"                                       # $c = FromB64("...")
    r".{0,800}?"
    r"(?:for\b|while\b|foreach\b|%\s*\{)"                                       # loop keyword
    r".{0,600}?"
    r"-\s*bxor\s*"
)


def _rc4_ksa_prga(key: bytes, ciphertext: bytes) -> bytes:
    """Standard RC4 keystream generator — pure, no side-effects."""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray()
    i = j = 0
    for byte in ciphertext:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) & 0xFF]
        out.append(byte ^ K)
    return bytes(out)


def _resolve_rc4(txt: str, stages: list[Stage]) -> tuple[str, bool]:
    for m in list(_RC4_STATIC_RE.finditer(txt)):
        key_txt = m.group(1)
        try:
            ciphertext = base64.b64decode(m.group(3), validate=False)
        except binascii.Error:
            continue
        if len(ciphertext) < 4:
            continue
        try:
            plaintext = _rc4_ksa_prga(key_txt.encode("utf-8"), ciphertext)
        except Exception:
            continue
        decoded = None
        for enc in ("utf-8", "utf-16-le", "ascii"):
            try:
                decoded = plaintext.decode(enc, errors="strict")
                break
            except Exception:
                continue
        # RC4 has a much wider false-positive surface than XOR — require
        # the recovered plaintext to look like text with a common PS or
        # cmdlet marker. If we can't confirm, DO NOT fabricate output.
        if decoded is None or len(decoded) < 3 or not any(c.isalpha() for c in decoded):
            continue
        _ok = re.search(r"(?i)invoke|iex|write-|new-object|http|"
                         r"[a-z]{5,}", decoded)
        if not _ok:
            # Signal detection but refuse to emit unverifiable plaintext.
            stages.append(Stage(
                n=len(stages) + 1,
                technique="RC4 detected · plaintext unverifiable",
                evidence=(f"Static literal key + Base64 ciphertext structure matches "
                           f"RC4 (key `{key_txt[:24]!r}`, {len(ciphertext)} cipher "
                           "bytes) but the derived plaintext failed the language-shape "
                           "check — refusing to fabricate."),
                before=m.group(3)[:80], after="",
                status="encryption_detected",
                unsupported_reason=KnownUnsupportedReason.UNKNOWN_ALGORITHM,
            ))
            return txt, True
        b64_call_start = txt.rfind("FromBase64String", 0, m.start(3))
        if b64_call_start == -1:
            continue
        i = b64_call_start
        while i > 0 and txt[i - 1] not in "\n;( \t":
            i -= 1
        replace_start = i
        replace_end = m.end(3) + 1
        while replace_end < len(txt) and txt[replace_end - 1] != ")":
            replace_end += 1
        txt = txt[:replace_start] + f"'{decoded}'" + txt[replace_end:]
        stages.append(Stage(
            n=len(stages) + 1,
            technique="RC4 decrypt (static key)",
            evidence=(f"Applied RC4 KSA/PRGA with static literal key "
                       f"`{key_txt[:24]!r}` over a {len(m.group(3))}-char Base64 "
                       f"ciphertext; recovered {len(decoded)} chars."),
            before=m.group(3)[:80], after=decoded[:200],
            status="fully_decrypted",
        ))
        return txt, True
    return txt, False


# ── AES-CBC / AES-ECB (static literal key + IV) ──────────────────
# Matches idioms seen in Empire / Cobalt Strike / PoshC2:
#
#   $key = [Convert]::FromBase64String("...")          # OR "raw ascii key"
#   $iv  = [Convert]::FromBase64String("...")          # required for CBC
#   $ct  = [Convert]::FromBase64String("...")
#   $aes = [Security.Cryptography.AesManaged]::new()
#   $aes.Key = $key
#   $aes.IV  = $iv
#   $aes.Mode = [Security.Cryptography.CipherMode]::CBC   # or ECB
#   $plain = $aes.CreateDecryptor().TransformFinalBlock($ct,0,$ct.Length)
#
# Deterministic — decodes only when key, IV (for CBC), and ciphertext
# are ALL literal base64/string. Never guesses keys.
_AES_KEY_RE = re.compile(
    r"(?ixs)"
    r"\$\w+\s*=\s*"
    r"(?:\[?\s*(?:system\.)?convert\]?\s*::\s*frombase64string\s*\(\s*"
    r"(['\"])([A-Za-z0-9+/=]{16,})\1\s*\)"
    r"|(?:\[text\.encoding\]::(?:utf8|ascii)\.getbytes\s*\(\s*)?"
    r"['\"]([^'\"]{5,64})['\"]\s*\)?)"
)
_AES_IV_RE = re.compile(
    r"(?ixs)"
    r"\$\w+\s*=\s*\[?\s*(?:system\.)?convert\]?\s*::\s*frombase64string\s*\(\s*"
    r"(['\"])([A-Za-z0-9+/=]{16,})\1\s*\)"
)
_AES_CT_RE = re.compile(
    r"(?ixs)"
    r"\$\w+\s*=\s*\[?\s*(?:system\.)?convert\]?\s*::\s*frombase64string\s*\(\s*"
    r"(['\"])([A-Za-z0-9+/=]{16,})\1\s*\)"
)
# Loose signature: presence of AesManaged / AesCryptoServiceProvider
# plus a mode selector.
_AES_SIG_RE = re.compile(
    r"(?ixs)"
    r"\[?\s*(?:system\.)?(?:security\.cryptography\.)?"
    r"(?:aesmanaged|aescryptoserviceprovider|aescng|aes)\]?"
    r".{0,600}?"
    r"(?:ciphermode\]?\s*::\s*(cbc|ecb)"
    r"|\.mode\s*=\s*\[?\s*(?:system\.)?(?:security\.cryptography\.)?ciphermode\]?\s*::\s*(cbc|ecb))"
)


def _pkcs7_strip(data: bytes) -> bytes:
    if not data:
        return data
    pad = data[-1]
    if 0 < pad <= 16 and data[-pad:] == bytes([pad]) * pad:
        return data[:-pad]
    return data


def _try_decode_text(raw: bytes) -> str | None:
    """Try UTF-8 → UTF-16LE → ASCII in the order that best matches
    typical PowerShell payloads. Returns None if the bytes don't look
    like text."""
    if not raw:
        return None
    _has_null = raw.count(b"\x00") >= max(1, len(raw) // 4) and raw[:1] != b"\x00"
    order = (("utf-16-le", "utf-8", "ascii") if _has_null
             else ("utf-8", "utf-16-le", "ascii"))
    for enc in order:
        try:
            s = raw.decode(enc, errors="strict")
            if len(s) >= 3 and any(c.isalpha() for c in s):
                return s
        except Exception:
            continue
    return None


def _resolve_aes(txt: str, stages: list[Stage],
                  r: "DeobfuscationReport") -> tuple[str, bool]:
    """Detect + decrypt AES-CBC / AES-ECB when key, IV (for CBC), and
    ciphertext are ALL statically present. Emits structured
    classifications for every other case per the acceptance matrix."""
    sig = _AES_SIG_RE.search(txt)
    if not sig:
        return txt, False
    mode = (sig.group(1) or sig.group(2) or "").lower()
    if not mode:
        return txt, False

    def _neutralize(t: str) -> str:
        """Rewrite `AesManaged`/`CipherMode::CBC|ECB` markers so this
        resolver does not re-fire on later iterations of the loop."""
        t = re.sub(r"(?i)AesManaged|AesCryptoServiceProvider|AesCng",
                    "AesHandled", t)
        t = re.sub(r"(?i)CipherMode\]?\s*::\s*(cbc|ecb)",
                    "CipherHandled", t)
        return t

    # Runtime-key gate first — never fabricate.
    for pat, reason, label in _RUNTIME_KEY_SOURCES:
        if re.search(pat, txt, re.IGNORECASE):
            stages.append(Stage(
                n=len(stages) + 1,
                technique=f"AES detected · runtime-derived key ({label})",
                evidence=(f"AES-{mode.upper()} primitive present, but the key "
                           f"originates from a runtime source (`{re.search(pat, txt, re.I).group(0)}`)."
                           " Refusing to fabricate plaintext."),
                before="", after="",
                status="encryption_detected",
                unsupported_reason=reason,
                confidence=90,
            ))
            r.unsupported_reasons.append({
                "reason": reason, "component": "aes_key_source",
                "evidence": re.search(pat, txt, re.I).group(0),
            })
            return _neutralize(txt), True

    # Gather up to 3 base64 literals in order — key, iv (if CBC), ct.
    b64s = list(re.finditer(
        r"\[?\s*(?:system\.)?convert\]?\s*::\s*frombase64string\s*\(\s*"
        r"(['\"])([A-Za-z0-9+/=]{16,})\1\s*\)",
        txt, re.IGNORECASE))
    if mode == "cbc" and len(b64s) < 3:
        # Missing IV or missing ciphertext — classify without decrypting.
        stages.append(Stage(
            n=len(stages) + 1,
            technique="AES-CBC detected · missing IV or ciphertext",
            evidence=(f"AES-CBC primitive detected but fewer than 3 static "
                       f"base64 literals present ({len(b64s)}). Refusing to "
                       "fabricate plaintext."),
            before="", after="",
            status="encryption_detected",
            unsupported_reason=KnownUnsupportedReason.UNSUPPORTED_ALGORITHM,
            confidence=85,
        ))
        r.unsupported_reasons.append({
            "reason":    "missing_iv_or_ciphertext",
            "component": "aes_cbc",
            "evidence":  f"static_b64_literals={len(b64s)}",
        })
        return _neutralize(txt), True
    if mode == "ecb" and len(b64s) < 2:
        stages.append(Stage(
            n=len(stages) + 1,
            technique="AES-ECB detected · missing ciphertext",
            evidence=("AES-ECB primitive detected but fewer than 2 static "
                       "base64 literals present. Refusing to fabricate plaintext."),
            before="", after="",
            status="encryption_detected",
            unsupported_reason=KnownUnsupportedReason.UNSUPPORTED_ALGORITHM,
            confidence=85,
        ))
        return _neutralize(txt), True

    if not _AES_LIB_OK:
        stages.append(Stage(
            n=len(stages) + 1,
            technique=f"AES-{mode.upper()} detected · crypto lib unavailable",
            evidence=("AES construction present but the `cryptography` "
                       "Python lib is not installed in this pod."),
            before="", after="",
            status="encryption_detected",
            unsupported_reason=KnownUnsupportedReason.EXTERNAL_DEPENDENCY,
            confidence=80,
        ))
        return _neutralize(txt), True

    try:
        key = base64.b64decode(b64s[0].group(2), validate=False)
        if mode == "cbc":
            iv  = base64.b64decode(b64s[1].group(2), validate=False)
            ct  = base64.b64decode(b64s[2].group(2), validate=False)
        else:
            iv  = None
            ct  = base64.b64decode(b64s[1].group(2), validate=False)
    except binascii.Error:
        return txt, False

    if len(key) not in (16, 24, 32):
        stages.append(Stage(
            n=len(stages) + 1,
            technique=f"AES-{mode.upper()} detected · non-standard key length",
            evidence=f"Key length {len(key)} bytes — not a valid AES key size (16/24/32).",
            before="", after="",
            status="encryption_detected",
            unsupported_reason=KnownUnsupportedReason.UNSUPPORTED_ALGORITHM,
            confidence=80,
        ))
        return _neutralize(txt), True
    if mode == "cbc" and len(iv) != 16:
        stages.append(Stage(
            n=len(stages) + 1,
            technique="AES-CBC detected · invalid IV length",
            evidence=f"IV length {len(iv)} bytes — must be exactly 16.",
            before="", after="",
            status="encryption_detected",
            unsupported_reason=KnownUnsupportedReason.UNSUPPORTED_ALGORITHM,
            confidence=80,
        ))
        return _neutralize(txt), True
    if len(ct) < 16 or len(ct) % 16 != 0:
        stages.append(Stage(
            n=len(stages) + 1,
            technique=f"AES-{mode.upper()} detected · corrupted ciphertext",
            evidence=(f"Ciphertext length {len(ct)} bytes is not a positive "
                       "multiple of 16 — cannot deterministically decrypt."),
            before=b64s[-1].group(2)[:80], after="",
            status="partially_decrypted",
            unsupported_reason=KnownUnsupportedReason.UNSUPPORTED_ALGORITHM,
            confidence=60,
        ))
        return _neutralize(txt), True

    try:
        cipher = _Cipher(_algs.AES(key),
                          _modes.CBC(iv) if mode == "cbc" else _modes.ECB())
        dec = cipher.decryptor()
        plain = dec.update(ct) + dec.finalize()
        plain = _pkcs7_strip(plain)
    except Exception:
        stages.append(Stage(
            n=len(stages) + 1,
            technique=f"AES-{mode.upper()} decrypt failed",
            evidence="AES primitives failed to decrypt with the provided static key/IV/ciphertext.",
            before=b64s[-1].group(2)[:80], after="",
            status="partially_decrypted",
            unsupported_reason=KnownUnsupportedReason.UNKNOWN_ALGORITHM,
            confidence=50,
        ))
        return _neutralize(txt), True

    decoded = _try_decode_text(plain)
    if not decoded:
        stages.append(Stage(
            n=len(stages) + 1,
            technique=f"AES-{mode.upper()} decrypted · plaintext unverifiable",
            evidence=(f"AES-{mode.upper()} decrypted {len(plain)} bytes, but "
                       "the output does not look like text — refusing to "
                       "fabricate a script."),
            before=b64s[-1].group(2)[:80], after="",
            status="partially_decrypted",
            unsupported_reason=KnownUnsupportedReason.UNKNOWN_ALGORITHM,
            confidence=55,
        ))
        return _neutralize(txt), True

    # Replace ONLY the ciphertext base64 sub-expression with the decrypted
    # plaintext literal so the outer IEX / wrapper stays visible.
    ct_match = b64s[-1]
    b64_call_start = txt.rfind("FromBase64String", 0, ct_match.start(2))
    if b64_call_start == -1:
        return txt, False
    i = b64_call_start
    while i > 0 and txt[i - 1] not in "\n;( \t":
        i -= 1
    replace_start = i
    replace_end = ct_match.end(2) + 1
    while replace_end < len(txt) and txt[replace_end - 1] != ")":
        replace_end += 1
    txt = txt[:replace_start] + f"'{decoded}'" + txt[replace_end:]
    stages.append(Stage(
        n=len(stages) + 1,
        technique=f"AES-{mode.upper()} decrypt (static key + IV)"
                   if mode == "cbc" else "AES-ECB decrypt (static key)",
        evidence=(f"Applied AES-{mode.upper()} with a {len(key) * 8}-bit key "
                   f"over a {len(ct)}-byte ciphertext; recovered "
                   f"{len(decoded)} chars."),
        before=ct_match.group(2)[:80], after=decoded[:200],
        status="fully_decrypted",
        confidence=95,
    ))
    return _neutralize(txt), True


# ── Runtime-generated key detection (RC4 / XOR variants) ──────────
# When we see the shape of a keyed decrypt but the key is derived from
# a runtime source (env var, Get-Random, DateTime, network fetch, user
# input), we EMIT a stage that classifies the situation without
# fabricating plaintext. This is a strict "no-hallucination" contract.
_RUNTIME_KEY_SOURCES = [
    (r"\$env:\w+",                            KnownUnsupportedReason.ENVIRONMENT_DEPENDENT,
      "Environment variable"),
    (r"\bget-random\b|\bnew-guid\b",         KnownUnsupportedReason.RUNTIME_GENERATED_KEY,
      "Runtime-generated random / GUID"),
    (r"\[datetime\]::(?:now|utcnow)|\bget-date\b",
                                              KnownUnsupportedReason.RUNTIME_GENERATED_KEY,
      "Runtime timestamp"),
    (r"\binvoke-webrequest\b|\biwr\b|\binvoke-restmethod\b|\birm\b",
                                              KnownUnsupportedReason.NETWORK_FETCH_REQUIRED,
      "Network-fetched key"),
    (r"\bread-host\b",                       KnownUnsupportedReason.USER_INPUT_REQUIRED,
      "User input via Read-Host"),
]

_KEYED_DECRYPT_SIG_RE = re.compile(
    r"(?ixs)"
    r"(?:rc4|-bxor|aesmanaged|aescryptoserviceprovider|"
    r"cryptostream|createdecryptor)"
)


def _detect_runtime_key_boundary(txt: str, stages: list[Stage],
                                    r: DeobfuscationReport) -> bool:
    """Detect that the script uses a keyed decrypt whose key comes from
    a runtime source. Never modifies txt — only emits a metadata stage
    and appends to `r.unsupported_reasons`. Returns True if such a
    boundary was recorded (so downstream logic knows crypto WAS
    detected but intentionally not decoded)."""
    if not _KEYED_DECRYPT_SIG_RE.search(txt):
        return False
    # Only emit once per report.
    if any(s.status == "encryption_detected" and s.technique.startswith("Runtime-derived")
            for s in stages):
        return False
    for pat, reason, label in _RUNTIME_KEY_SOURCES:
        m = re.search(pat, txt, re.IGNORECASE)
        if m:
            stages.append(Stage(
                n=len(stages) + 1,
                technique=f"Runtime-derived key detected · {label}",
                evidence=(f"Encryption primitive is present, but the key is "
                           f"derived from a runtime source (`{m.group(0)}`). "
                           "Refusing to fabricate plaintext."),
                before=m.group(0), after="",
                status="encryption_detected",
                unsupported_reason=reason,
            ))
            r.unsupported_reasons.append({
                "reason":     reason,
                "evidence":   m.group(0),
                "component":  "crypto_key_source",
            })
            return True
    return False


# ═══════════════════════════════════════════════════════════════════════════
#  PHASE 3 · Cluster E + F — Multi-Stage Execution (2026-07-27)
# ═══════════════════════════════════════════════════════════════════════════

# ── Nested IEX / Invoke-Expression peeling ───────────────────────
# Matches `IEX('literal')` or `Invoke-Expression 'literal'` where the
# argument is a single-quoted OR double-quoted string literal. Removes
# ONE layer per iteration — the recursive loop peels multi-level nests
# automatically (deterministic, up to MAX_STAGES).
_IEX_LITERAL_RE = re.compile(
    r"(?ixs)"
    r"\b(?:iex|invoke-expression)\s*\(?\s*"
    r"(['\"])(.{3,4000}?)\1\s*\)?"
)


def _resolve_nested_iex(txt: str, stages: list[Stage]) -> tuple[str, bool]:
    """Peel one IEX-of-literal layer. Only fires when the argument is a
    literal string AND the match consumes cleanly (nothing unexpected
    after the closing quote). Prevents non-greedy `.*?` from truncating
    PowerShell payloads that legitimately embed quotes."""
    m = _IEX_LITERAL_RE.search(txt)
    if not m:
        return txt, False
    quote = m.group(1)
    inner = m.group(2)
    # Reject when the argument contains an un-doubled instance of its
    # own wrapping quote — non-greedy `.*?` will have truncated.
    if quote in inner:
        return txt, False
    # Reject when there's more content after the closing quote that
    # looks like a leaked payload character (`'`, `"`, another letter).
    # Only whitespace, `)`, `;` or EOF are acceptable trailers.
    trailer = txt[m.end():m.end() + 3]
    if trailer and not re.match(r"^[\s\);]*$", trailer):
        return txt, False
    if not re.search(r"(?i)invoke|iex|write-|new-|[a-z]{5,}", inner):
        return txt, False
    replacement = inner
    txt = txt[:m.start()] + replacement + txt[m.end():]
    stages.append(Stage(
        n=len(stages) + 1,
        technique="Peel nested Invoke-Expression",
        evidence=(f"Removed one `IEX(...)` / `Invoke-Expression '...'` "
                   f"wrapper (recovered {len(inner)} chars)."),
        before=(m.group(0)[:80]), after=inner[:200],
        confidence=90,
    ))
    return txt, True


# ── ScriptBlock::Create resolver ─────────────────────────────────
# Static:   [ScriptBlock]::Create("literal")   → replace with the literal
# Dynamic:  [ScriptBlock]::Create($x)           → emit dynamic_execution
_SCRIPTBLOCK_LITERAL_RE = re.compile(
    r"(?ixs)"
    r"\[?\s*(?:(?:system\.)?management\.automation\.)?scriptblock\]?\s*::\s*create\s*\(\s*"
    r"(['\"])(.{1,4000}?)\1\s*\)"
)
_SCRIPTBLOCK_DYNAMIC_RE = re.compile(
    r"(?ixs)"
    r"\[?\s*(?:(?:system\.)?management\.automation\.)?scriptblock\]?\s*::\s*create\s*\(\s*"
    r"(\$\w+|[^'\")]{3,120}?)\s*\)"
)


def _resolve_scriptblock_create(txt: str, stages: list[Stage],
                                   r: "DeobfuscationReport") -> tuple[str, bool]:
    m = _SCRIPTBLOCK_LITERAL_RE.search(txt)
    if m:
        inner = m.group(2)
        txt = txt[:m.start()] + inner + txt[m.end():]
        stages.append(Stage(
            n=len(stages) + 1,
            technique="Resolve [ScriptBlock]::Create (static literal)",
            evidence=(f"Extracted the literal ScriptBlock body "
                       f"({len(inner)} chars) — the recursive loop will "
                       "keep decoding whatever remains."),
            before=m.group(0)[:80], after=inner[:200],
            confidence=95,
        ))
        return txt, True
    m = _SCRIPTBLOCK_DYNAMIC_RE.search(txt)
    if m and "'" not in m.group(1) and '"' not in m.group(1):
        stages.append(Stage(
            n=len(stages) + 1,
            technique="[ScriptBlock]::Create · dynamic argument",
            evidence=(f"ScriptBlock is created from a runtime expression "
                       f"(`{m.group(1)[:40]}`). Refusing to fabricate the "
                       "resulting script."),
            before=m.group(0)[:120], after="",
            status="encryption_detected",
            unsupported_reason=KnownUnsupportedReason.DYNAMIC_EXECUTION,
            confidence=85,
        ))
        r.unsupported_reasons.append({
            "reason":    KnownUnsupportedReason.DYNAMIC_EXECUTION,
            "evidence":  m.group(0)[:120],
            "component": "scriptblock_create",
        })
        # Neutralize so we don't re-emit on next iteration
        replacement = f"'__nvx_scriptblock_dynamic__'"
        txt = txt[:m.start()] + replacement + txt[m.end():]
        return txt, True
    return txt, False


# ── Invoke-Command -ScriptBlock { literal } ──────────────────────
_INVOKE_COMMAND_SB_RE = re.compile(
    r"(?ixs)"
    r"\binvoke-command\b[^{]*?-scriptblock\s*\{\s*(.{3,4000}?)\s*\}"
)


def _resolve_invoke_command(txt: str, stages: list[Stage]) -> tuple[str, bool]:
    m = _INVOKE_COMMAND_SB_RE.search(txt)
    if not m:
        return txt, False
    inner = m.group(1)
    txt = txt[:m.start()] + inner + txt[m.end():]
    stages.append(Stage(
        n=len(stages) + 1,
        technique="Peel Invoke-Command -ScriptBlock",
        evidence=(f"Extracted the ScriptBlock body from an Invoke-Command "
                   f"invocation ({len(inner)} chars)."),
        before=m.group(0)[:80], after=inner[:200],
        confidence=92,
    ))
    return txt, True


# ── Reflection.Assembly.Load / AppDomain.Load / Activator ───────
# NEVER load. Emit a structured stage that classifies the primitive
# and stops the recursive engine on this branch.
_REFLECTION_RE = re.compile(
    r"(?ixs)"
    r"\[?\s*(?:system\.)?reflection\.assembly\]?\s*::\s*(?:load|loadfrom|loadfile)\s*\("
    r"|\[?\s*(?:system\.)?appdomain\]?[^)]*?\.\s*load\s*\("
    r"|\[?\s*(?:system\.)?activator\]?\s*::\s*createinstance\s*\("
)


def _resolve_reflection(txt: str, stages: list[Stage],
                          r: "DeobfuscationReport") -> tuple[str, bool]:
    if any(s.unsupported_reason == KnownUnsupportedReason.REFLECTION
            for s in stages):
        return txt, False
    m = _REFLECTION_RE.search(txt)
    if not m:
        return txt, False
    call = m.group(0)
    stages.append(Stage(
        n=len(stages) + 1,
        technique="Reflection / dynamic assembly load detected",
        evidence=(f"In-memory assembly loading primitive detected "
                   f"(`{call.strip()[:80]}`). NivXRay never loads assemblies — "
                   "this branch of the analysis stops here."),
        before=call[:80], after="",
        status="encryption_detected",
        unsupported_reason=KnownUnsupportedReason.REFLECTION,
        confidence=95,
    ))
    r.unsupported_reasons.append({
        "reason":    KnownUnsupportedReason.REFLECTION,
        "evidence":  call.strip()[:120],
        "component": "reflection_assembly_load",
    })
    return txt, False   # Do NOT rewrite; leave the primitive so the
                          # boundary detector still surfaces it.


# ═══════════════════════════════════════════════════════════════════════════
#  PHASE 3 · Cluster G — Dynamic invocation, [Type]::GetType, env-var reconstruction
# ═══════════════════════════════════════════════════════════════════════════

# Dynamic method invocation:
#   $m = $obj.GetType().GetMethod("Foo"); $m.Invoke($obj, @($a, $b))
_DYNAMIC_INVOKE_RE = re.compile(
    r"(?ixs)"
    r"\.\s*gettype\s*\(\s*\)\s*\.\s*getmethod\s*\(\s*['\"]([^'\"]{1,80})['\"]\s*\)"
    r".{0,400}?"
    r"\.\s*invoke\s*\("
)


def _resolve_dynamic_method_invocation(txt: str, stages: list[Stage],
                                          r: "DeobfuscationReport") -> tuple[str, bool]:
    if any(s.unsupported_reason == KnownUnsupportedReason.DYNAMIC_EXECUTION
            and "GetMethod" in s.evidence
            for s in stages):
        return txt, False
    m = _DYNAMIC_INVOKE_RE.search(txt)
    if not m:
        return txt, False
    method_name = m.group(1)
    stages.append(Stage(
        n=len(stages) + 1,
        technique="Dynamic method invocation detected",
        evidence=(f"Runtime reflection via `GetType().GetMethod('{method_name}')."
                   "Invoke(...)`. NivXRay does not follow dynamic invocations — "
                   "the branch is classified without fabricating output."),
        before=m.group(0)[:120], after="",
        status="encryption_detected",
        unsupported_reason=KnownUnsupportedReason.DYNAMIC_EXECUTION,
        confidence=90,
    ))
    r.unsupported_reasons.append({
        "reason":    KnownUnsupportedReason.DYNAMIC_EXECUTION,
        "evidence":  f"GetType().GetMethod('{method_name}').Invoke(...)",
        "component": "dynamic_method_invocation",
    })
    return txt, False


# [Type]::GetType("literal") — replace with the resolved type name so
# downstream regexes can see it. Dynamic argument → dynamic_execution.
_TYPE_GETTYPE_LITERAL_RE = re.compile(
    r"(?ixs)"
    r"\[\s*type\s*\]\s*::\s*gettype\s*\(\s*(['\"])([^'\"]{3,120})\1\s*\)"
)
_TYPE_GETTYPE_DYNAMIC_RE = re.compile(
    r"(?ixs)"
    r"\[\s*type\s*\]\s*::\s*gettype\s*\(\s*(\$\w+)\s*\)"
)


def _resolve_type_gettype(txt: str, stages: list[Stage],
                            r: "DeobfuscationReport") -> tuple[str, bool]:
    m = _TYPE_GETTYPE_LITERAL_RE.search(txt)
    if m:
        typename = m.group(2)
        replacement = f"'{typename}'"
        txt = txt[:m.start()] + replacement + txt[m.end():]
        stages.append(Stage(
            n=len(stages) + 1,
            technique="Resolve [Type]::GetType (literal)",
            evidence=(f"Statically resolved `[Type]::GetType('{typename[:60]}')` "
                       "to its typename literal."),
            before=m.group(0)[:80], after=typename[:80],
            confidence=95,
        ))
        return txt, True
    m = _TYPE_GETTYPE_DYNAMIC_RE.search(txt)
    if m:
        stages.append(Stage(
            n=len(stages) + 1,
            technique="[Type]::GetType · dynamic argument",
            evidence=(f"`[Type]::GetType({m.group(1)})` — argument comes from "
                       "a runtime variable. Refusing to resolve dynamically."),
            before=m.group(0)[:80], after="",
            status="encryption_detected",
            unsupported_reason=KnownUnsupportedReason.DYNAMIC_EXECUTION,
            confidence=85,
        ))
        r.unsupported_reasons.append({
            "reason":    KnownUnsupportedReason.DYNAMIC_EXECUTION,
            "evidence":  f"[Type]::GetType({m.group(1)})",
            "component": "type_gettype",
        })
        # Neutralize so we don't re-emit next iteration.
        txt = txt[:m.start()] + "'__nvx_type_dynamic__'" + txt[m.end():]
        return txt, True
    return txt, False


# Environment variable reconstruction: `$env:FOO`, `[Environment]::GetEnvironmentVariable("FOO")`
# The value is NEVER substituted — we surface `environment_dependent` in the
# unsupported_reasons list so the analyst knows this branch depends on
# runtime state.
_ENV_VAR_RE = re.compile(
    r"(?i)"
    r"(?:\$env:(\w{1,64})"
    r"|\[\s*environment\s*\]\s*::\s*getenvironmentvariable\s*\(\s*['\"]([^'\"]{1,64})['\"]\s*\))"
)


def _detect_env_var_reconstruction(txt: str,
                                       r: "DeobfuscationReport") -> None:
    """Non-mutating scan — surfaces `environment_dependent` for every
    unique env-var reference. Never rewrites the text."""
    seen: set[str] = {u["evidence"] for u in r.unsupported_reasons
                       if u.get("component") == "env_var_reconstruction"}
    for m in _ENV_VAR_RE.finditer(txt):
        name = m.group(1) or m.group(2) or ""
        ev = f"$env:{name}" if m.group(1) else f"GetEnvironmentVariable({name!r})"
        if ev in seen:
            continue
        seen.add(ev)
        r.unsupported_reasons.append({
            "reason":    KnownUnsupportedReason.ENVIRONMENT_DEPENDENT,
            "evidence":  ev,
            "component": "env_var_reconstruction",
        })


# ── Boundary detection ───────────────────────────────────────────
_BOUNDARY_RE = re.compile(
    r"\b(invoke-expression|iex|invoke-command|start-process|"
    r"add-type|reflection\.assembly|new-object\s+system\.reflection|"
    r"comobject|wmiobject|com\.activate)\b",
    re.IGNORECASE,
)


def _detect_boundary(txt: str) -> str | None:
    m = _BOUNDARY_RE.search(txt)
    return m.group(1) if m else None


# ── Public entrypoint ────────────────────────────────────────────
def deobfuscate(script: str) -> DeobfuscationReport:
    """Run the recursive deterministic decode loop."""
    _t_start = _time.perf_counter()
    r = DeobfuscationReport(original=script or "", final=script or "")
    if not script:
        r.stopped_reason = "empty input"
        return r
    current = script
    hit_max = True
    for _ in range(MAX_STAGES):
        prev = current
        current, _ = _resolve_backticks(current, r.stages)
        current, _ = _resolve_format(current, r.stages)
        current, _ = _resolve_concat(current, r.stages)
        current, _ = _resolve_numeric_char_reconstruction(current, r.stages)
        # Compression wrappers first — they consume the surrounding
        # `[Convert]::FromBase64String(...)` inside them so the plain
        # base64 resolver doesn't grab the inner blob prematurely.
        current, _ = _resolve_compression_stream(current, r.stages)
        # Crypto family (order: multi-byte before single-byte before
        # rolling; RC4 last because its regex is the most permissive).
        current, _ = _resolve_multibyte_xor(current, r.stages)
        current, _ = _resolve_static_xor(current, r.stages)
        current, _ = _resolve_rolling_xor(current, r.stages)
        current, _ = _resolve_aes(current, r.stages, r)
        current, _ = _resolve_rc4(current, r.stages)
        # UTF-16LE wrapper before plain base64 for the same reason.
        current, _ = _resolve_utf16le_base64(current, r.stages)
        current, _ = _resolve_static_base64(current, r.stages)
        current, _ = _resolve_aliases(current, r.stages)
        # ── Phase 3 · Multi-stage execution ───────────────────────
        # These come AFTER base64/alias so IEX('base64...') is peeled
        # in one iteration and the inner script becomes the next round's
        # input. Reflection is emitted (never executed) — it BOTH stops
        # its own branch AND leaves the primitive text intact so the
        # boundary detector still reports it.
        current, _ = _resolve_nested_iex(current, r.stages)
        current, _ = _resolve_scriptblock_create(current, r.stages, r)
        current, _ = _resolve_invoke_command(current, r.stages)
        current, _ = _resolve_reflection(current, r.stages, r)
        # ── Phase 3 Batch 2 · Cluster G ─────────────────────────
        current, _ = _resolve_type_gettype(current, r.stages, r)
        current, _ = _resolve_dynamic_method_invocation(current, r.stages, r)
        if current == prev:
            r.stopped_reason = "fixed_point (no further deterministic transforms)"
            hit_max = False
            break
    if hit_max:
        # Phase 2 · configured stage-explosion protection (2026-07-27).
        r.stopped_reason = (
            f"recursion_limit_reached · exceeded MAX_STAGES={MAX_STAGES} — "
            "aborting further deterministic transforms to prevent resource "
            "exhaustion. Analyst should inspect the payload manually.")
        r.unsupported_reasons.append({
            "reason":    "recursion_limit_reached",
            "evidence":  f"MAX_STAGES={MAX_STAGES}",
            "component": "deobfuscator",
        })

    # Runtime-key boundary — never fabricate. If we see a crypto shape
    # whose key comes from env/network/user/random, log a metadata stage
    # and leave the ciphertext intact for the analyst.
    _detect_runtime_key_boundary(current, r.stages, r)
    # Environment-variable reconstruction — surface every $env:X reference
    # in the report's unsupported_reasons without substituting live values.
    _detect_env_var_reconstruction(current, r)

    # After the loop, check if a true execution boundary remains
    boundary = _detect_boundary(current)
    if boundary:
        r.boundary_op = boundary
        if r.stopped_reason.startswith("fixed_point"):
            r.stopped_reason = (
                f"execution boundary — `{boundary}` present; further evaluation "
                "would require running PowerShell (intentionally skipped).")

    # ── Crypto status roll-up ────────────────────────────────────
    for s in r.stages:
        if s.status and _CRYPTO_STATUS_RANK.get(s.status, -1) > \
                _CRYPTO_STATUS_RANK.get(r.crypto_status, -1):
            r.crypto_status = s.status

    # ── Evidence preservation · post-populate (2026-07-27) ───────
    # Hash + length are computed AFTER the loop so we don't slow the
    # hot path with per-resolver hashing. Total decoder wall-clock is
    # spread evenly across all stages for a proxy elapsed_ms value.
    total_elapsed_ms = (_time.perf_counter() - _t_start) * 1000.0
    per_stage_ms = (total_elapsed_ms / len(r.stages)) if r.stages else 0.0
    for st in r.stages:
        b_bytes = (st.before or "").encode("utf-8", errors="ignore")
        a_bytes = (st.after  or "").encode("utf-8", errors="ignore")
        st.input_hash    = _hashlib.sha256(b_bytes).hexdigest()[:16]
        st.output_hash   = _hashlib.sha256(a_bytes).hexdigest()[:16]
        st.input_length  = len(b_bytes)
        st.output_length = len(a_bytes)
        if not st.elapsed_ms:
            st.elapsed_ms = round(per_stage_ms, 3)

    r.final = current
    return r
