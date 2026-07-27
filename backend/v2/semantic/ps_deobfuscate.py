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
import io as _io
import re
import zlib as _zlib_lib
from dataclasses import dataclass, field, asdict

try:
    import brotli as _brotli_lib          # type: ignore
except Exception:                          # pragma: no cover
    _brotli_lib = None                     # runtime-optional


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
    # Every crypto stage MUST classify itself. Never fabricate. Values:
    #   None                    — non-crypto stage
    #   "fully_decrypted"       — key was static, plaintext recovered
    #   "partially_decrypted"   — partial success (e.g. XOR revealed keywords)
    #   "encryption_detected"   — algorithm identified, key unavailable/dynamic
    status: str | None = None
    unsupported_reason: str | None = None  # see KnownUnsupportedReason.*

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
        current, _ = _resolve_rc4(current, r.stages)
        # UTF-16LE wrapper before plain base64 for the same reason.
        current, _ = _resolve_utf16le_base64(current, r.stages)
        current, _ = _resolve_static_base64(current, r.stages)
        current, _ = _resolve_aliases(current, r.stages)
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

    r.final = current
    return r
