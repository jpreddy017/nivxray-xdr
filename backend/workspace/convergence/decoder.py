"""
Decoder pass · M4 — deterministic decode transformations.

Handles the classical malware-analyst decoder stack:

* ``decoder-powershell-encoded-command`` — extract ``-enc*`` argument,
  decode Base64 + UTF-16LE (PowerShell's native EncodedCommand
  encoding), replace the whole invocation with the decoded script.
* ``decoder-frombase64string-fold`` — ``[Convert]::FromBase64String('B64')``
  → decoded string literal. Enables S05-style ``Gzip → IEX`` chains
  by exposing the decoded bytes as a subsequent-iteration artifact.
* ``decoder-hex-full`` — decode the ENTIRE artifact when it is pure
  hex characters (fixed-length safety guards, printable output).
* ``decoder-base64-full`` — decode the ENTIRE artifact when it is
  pure Base64 (multiple-of-4 length, printable / gzip-magic /
  UTF-16LE output). Chains multi-layer payloads through the outer
  convergence loop.
* ``decoder-xor-byte-array`` — ``0xNN,0xNN,... xor 0xNN`` pattern
  decoded to plaintext (or hex representation on non-printable
  output).

Chain-native design
-------------------
Every decoder produces TEXT. That means multi-layer payloads
(hex → base64 → gzip, RC4 → base64 → utf-16le, etc.) resolve
automatically through successive iterations of the outer
convergence loop — no decoder here needs to know about the ones
that come after it. The Convergence Engine's iteration-until-fixpoint
guarantee is the mechanism that composes them.

Safety
------
Every decoder has a STRICT precondition check that trips before any
work happens. If the precondition fails, the decoder returns the
artifact unchanged and reports 0 fires. This is what keeps the false-
positive rate at zero on already-canonical text.
"""
from __future__ import annotations

import base64
import binascii
import gzip
import re
import zlib

from .artifact import Artifact
from .provenance import PassRecord
from .transformation import Transformation

PASS_NAME = "decoder"


# ─── Utility helpers ────────────────────────────────────────────────


def _mostly_printable(text: str, threshold: float = 0.9) -> bool:
    if not text:
        return False
    good = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
    return good / len(text) >= threshold


def _try_utf16le(raw: bytes) -> str | None:
    if len(raw) < 2 or len(raw) % 2:
        return None
    try:
        text = raw.decode("utf-16le")
    except UnicodeDecodeError:
        return None
    return text if _mostly_printable(text) else None


def _try_utf8(raw: bytes) -> str | None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return text if _mostly_printable(text) else None


def _b64_decode_strict(s: str) -> bytes | None:
    if len(s) % 4 != 0:
        return None
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None


def _try_gzip(raw: bytes) -> bytes | None:
    """Attempt gzip decompression, falling back to raw DEFLATE when
    the gzip trailer (CRC / length) is broken but the compressed body
    itself is valid — a pattern seen in synthesized / malformed
    obfuscator payloads."""
    if not raw.startswith(b"\x1f\x8b"):
        return None
    try:
        return gzip.decompress(raw)
    except (OSError, EOFError, zlib.error):
        pass
    # Fallback: raw DEFLATE with gzip header skipped (10-byte fixed
    # header — no extra fields / filename in obfuscator payloads).
    try:
        return zlib.decompress(raw[10:], -zlib.MAX_WBITS)
    except zlib.error:
        return None


# ─── Decoder 1 · PowerShell -EncodedCommand ─────────────────────────

_ENC_CMD_RE = re.compile(
    r"(?i)"
    r"(?<![A-Za-z0-9_])-enc[A-Za-z]*\s+"
    r"(?P<b64>[A-Za-z0-9+/]{8,}={0,2})"
)
_INVOCATION_HEAD_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_])(?:powershell|pwsh|cmd)(?:\.exe)?(?![A-Za-z0-9_])",
)


def _decode_ps_encoded_command(content: str) -> tuple[str, int]:
    m = _ENC_CMD_RE.search(content)
    if m is None:
        return content, 0
    b64 = m.group("b64")
    raw = _b64_decode_strict(b64)
    if raw is None:
        return content, 0
    # PowerShell -EncodedCommand is always UTF-16LE; fall back to UTF-8
    # for other invocations (S03's `cmd /c powershell -enc` is UTF-16LE).
    text = _try_utf16le(raw) or _try_utf8(raw)
    if text is None:
        return content, 0
    # Extend replacement backward to include a leading
    # `powershell.exe` / `pwsh` / `cmd /c` invocation head so the
    # canonical output is the decoded script, not `powershell.exe
    # DECODED_SCRIPT`.
    start = m.start()
    prefix = content[:start]
    heads = list(_INVOCATION_HEAD_RE.finditer(prefix))
    if heads:
        start = heads[0].start()
    return content[:start] + text + content[m.end():], 1


# ─── Decoder 2 · [Convert]::FromBase64String('B64') fold ────────────

_FROM_B64_RE = re.compile(
    r"(?i)"
    r"\[\s*(?:system\.)?convert\s*\]\s*::\s*frombase64string\s*\(\s*"
    r"'(?P<b64>[A-Za-z0-9+/]{8,}={0,2})'\s*\)"
)


def _decode_from_base64string(content: str) -> tuple[str, int]:
    fires = 0

    def _repl(m: re.Match[str]) -> str:
        nonlocal fires
        b64 = m.group("b64")
        raw = _b64_decode_strict(b64)
        if raw is None:
            return m.group(0)
        # Try gzip (with raw-DEFLATE fallback for broken CRC trailers).
        inflated = _try_gzip(raw)
        if inflated is not None:
            text = _try_utf8(inflated)
            if text is not None:
                fires += 1
                escaped = text.replace("'", "''")
                return "'" + escaped + "'"
        text = _try_utf16le(raw) or _try_utf8(raw)
        if text is None:
            # Binary-magic fallback (Rule 24 §5.1): if the decoded bytes
            # are a known executable / container, inline them as a
            # latin-1 SQ literal so the IEDDE planner can detect the
            # binary artifact and switch terminal state.
            for magic in (b"MZ", b"\x7fELF", b"\xcf\xfa\xed\xfe",
                          b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe",
                          b"PK\x03\x04"):
                if raw.startswith(magic):
                    fires += 1
                    return "'" + raw.decode("latin-1") + "'"
            return m.group(0)
        fires += 1
        escaped = text.replace("'", "''")
        return "'" + escaped + "'"

    return _FROM_B64_RE.sub(_repl, content), fires


# ─── Decoder 3 · hex-full ───────────────────────────────────────────

_HEX_FULL_RE = re.compile(r"\A[0-9a-fA-F]+\Z")


def _decode_hex_full(content: str) -> tuple[str, int]:
    stripped = content.strip()
    if len(stripped) < 8 or len(stripped) % 2 or not _HEX_FULL_RE.match(stripped):
        return content, 0
    try:
        raw = bytes.fromhex(stripped)
    except ValueError:
        return content, 0
    text = _try_utf8(raw)
    if text is None:
        # Fall back to latin-1 only when result is still mostly printable.
        text = raw.decode("latin-1")
        if not _mostly_printable(text):
            return content, 0
    return text, 1


# ─── Decoder 4 · base64-full ────────────────────────────────────────

_B64_FULL_RE = re.compile(r"\A[A-Za-z0-9+/]+={0,2}\Z")


def _decode_base64_full(content: str) -> tuple[str, int]:
    stripped = content.strip()
    if len(stripped) < 12 or len(stripped) % 4 or not _B64_FULL_RE.match(stripped):
        return content, 0
    raw = _b64_decode_strict(stripped)
    if raw is None:
        return content, 0
    # Prefer gzip when magic present (with raw-DEFLATE fallback).
    if raw.startswith(b"\x1f\x8b"):
        inflated = _try_gzip(raw)
        if inflated is not None:
            text = _try_utf8(inflated)
            if text is not None:
                return text, 1
    text = _try_utf16le(raw) or _try_utf8(raw)
    if text is None:
        return content, 0
    return text, 1


# ─── Decoder 5 · XOR byte array ─────────────────────────────────────

_XOR_RE = re.compile(
    r"\A\s*"
    r"(?P<bytes>(?:0x[0-9a-fA-F]+)(?:\s*,\s*0x[0-9a-fA-F]+)+)"
    r"\s+xor\s+"
    r"(?P<key>0x[0-9a-fA-F]+)"
    r"\s*\Z",
    re.IGNORECASE,
)


def _decode_xor_byte_array(content: str) -> tuple[str, int]:
    m = _XOR_RE.match(content)
    if m is None:
        return content, 0
    try:
        bytes_val = [int(b.strip(), 16) for b in m.group("bytes").split(",")]
        key = int(m.group("key"), 16) & 0xFF
    except ValueError:
        return content, 0
    xored = bytes((b ^ key) & 0xFF for b in bytes_val)
    text = _try_utf8(xored)
    if text is None:
        text = xored.decode("latin-1")
        if not _mostly_printable(text):
            # Non-printable → expose as hex so a downstream pass can
            # attempt further decoding.
            text = xored.hex()
    return text, 1


# ─── Decoder 6 · JavaScript unicode-escape strings ──────────────────
#
# GootLoader / SocGholish / ClearFake / ClickFix stagers ship their
# next-stage payload as a single-quoted or double-quoted JavaScript
# string of "\u00XX\u00XX..." escape sequences. Once folded, the
# resulting plaintext is another obfuscated JS payload or a raw
# PowerShell command that later passes fire on.

_JS_UNICODE_ESCAPE_STRING_RE = re.compile(
    # Match ONLY string literals that are pure sequences of \uXXXX
    # escapes (>= 4 escapes, => 16 chars) — no other content.
    r"""
    ( ['"] )                    # opening quote (captured for reuse)
    (
      (?: \\u [0-9a-fA-F]{4} ){4,}
    )
    \1                          # matching closing quote
    """,
    re.VERBOSE,
)


def _decode_js_unicode_escape(content: str) -> tuple[str, int]:
    fires = 0

    def _repl(m: re.Match[str]) -> str:
        nonlocal fires
        escapes = m.group(2)
        try:
            decoded = escapes.encode("ascii").decode("unicode_escape")
        except UnicodeDecodeError:
            return m.group(0)
        if not _mostly_printable(decoded):
            return m.group(0)
        fires += 1
        # Emit as a single-quoted string literal (canonical shape for
        # downstream passes). Escape any single-quotes / backslashes
        # already present in the decoded content.
        escaped = decoded.replace("\\", "\\\\").replace("'", "\\'")
        return "'" + escaped + "'"

    return _JS_UNICODE_ESCAPE_STRING_RE.sub(_repl, content), fires


# ─── Decoder 7 · JavaScript atob() chain ────────────────────────────
#
# atob('B64') / atob(atob('B64B64')) / atob("B64") — the classic
# JavaScript base64 decoder used by GootLoader, SocGholish, Pikabot's
# JS launchers, ChromeLoader HTA droppers, and countless phishing kits.
# The chain resolves through successive iterations of the outer loop:
# a single atob() call fires this pass; nested atob(atob(...)) fires
# the innermost first, then the outer on the next iteration.

_ATOB_CALL_RE = re.compile(
    r"""
    atob \s* \(
      \s* (?P<q> ['"] )
      (?P<b64> [A-Za-z0-9+/]{8,} ={0,2} )
      (?P=q) \s*
    \)
    """,
    re.VERBOSE | re.IGNORECASE,
)


def _decode_js_atob(content: str) -> tuple[str, int]:
    fires = 0

    def _repl(m: re.Match[str]) -> str:
        nonlocal fires
        b64 = m.group("b64")
        raw = _b64_decode_strict(b64)
        if raw is None:
            return m.group(0)
        text = _try_utf8(raw) or _try_utf16le(raw)
        if text is None:
            return m.group(0)
        fires += 1
        # Emit as a single-quoted JS string literal (canonical shape).
        escaped = text.replace("\\", "\\\\").replace("'", "\\'")
        return "'" + escaped + "'"

    return _ATOB_CALL_RE.sub(_repl, content), fires


# ─── Transformation registry ────────────────────────────────────────

TRANSFORMATIONS: tuple[Transformation, ...] = (
    Transformation(
        name="decoder-powershell-encoded-command",
        category="decoder",
        consumes="ASCII PowerShell CLI invocation with -enc<...> switch",
        produces="powershell-text",
        preconditions=(
            "`-enc*` switch followed by valid Base64 (multiple of 4)",
            "Base64 decodes to valid UTF-16LE or UTF-8 text",
            "decoded output is mostly printable",
        ),
        postconditions=(
            "encoded invocation replaced by the decoded PowerShell script",
        ),
        priority=200,
        apply=_decode_ps_encoded_command,
    ),
    Transformation(
        name="decoder-frombase64string-fold",
        category="decoder",
        consumes="[Convert]::FromBase64String('B64') expression",
        produces="SQ string literal containing the decoded content",
        preconditions=(
            "Base64 argument valid and decodes to printable text or gzip",
        ),
        postconditions=(
            "expression replaced by an SQ literal of the decoded content",
        ),
        priority=180,
        apply=_decode_from_base64string,
    ),
    Transformation(
        name="decoder-hex-full",
        category="decoder",
        consumes="entire artifact is hex characters, even length ≥ 8",
        produces="UTF-8 / latin-1 decoded text",
        preconditions=(
            "content matches ^[0-9a-fA-F]+$",
            "decoded output is mostly printable",
        ),
        postconditions=("artifact replaced with decoded plaintext",),
        priority=170,
        apply=_decode_hex_full,
    ),
    Transformation(
        name="decoder-base64-full",
        category="decoder",
        consumes="entire artifact is Base64, length ≥ 12 and multiple of 4",
        produces="UTF-8 / UTF-16LE / gzip-decompressed text",
        preconditions=(
            "content matches ^[A-Za-z0-9+/]+=*$",
            "decoded output printable or gzip-magic present",
        ),
        postconditions=("artifact replaced with decoded plaintext",),
        priority=160,
        apply=_decode_base64_full,
    ),
    Transformation(
        name="decoder-xor-byte-array",
        category="decoder",
        consumes="0xNN,0xNN,... xor 0xNN pattern",
        produces="XOR-decoded plaintext or hex representation",
        preconditions=("input matches byte-array XOR key pattern",),
        postconditions=("artifact replaced with decoded output",),
        priority=150,
        reversible=True,
        apply=_decode_xor_byte_array,
    ),
    Transformation(
        name="decoder-js-unicode-escape",
        category="decoder",
        consumes="JavaScript string literal of `\\uXXXX` escape sequences",
        produces="single-quoted string literal of decoded plaintext",
        preconditions=(
            "string literal contains only `\\uXXXX` sequences (\u2265 4 escapes)",
            "decoded output is mostly printable",
        ),
        postconditions=("literal replaced with decoded SQ string",),
        priority=145,
        apply=_decode_js_unicode_escape,
    ),
    Transformation(
        name="decoder-js-atob",
        category="decoder",
        consumes="JavaScript `atob('B64')` / `atob(\"B64\")` call",
        produces="single-quoted string literal of Base64-decoded plaintext",
        preconditions=(
            "atob() argument is a valid Base64 literal (\u2265 8 chars, mod-4)",
            "decoded output is mostly printable (UTF-8 or UTF-16LE)",
        ),
        postconditions=(
            "atob() call replaced with an SQ string literal",
            "chains through successive iterations for nested atob(atob(\u2026))",
        ),
        priority=140,
        apply=_decode_js_atob,
    ),
)


def run(artifact: Artifact) -> tuple[Artifact, PassRecord]:
    content = artifact.content
    fired: list[str] = []
    for xf in TRANSFORMATIONS:
        assert xf.apply is not None
        new_content, count = xf.apply(content)
        if count > 0:
            fired.append(f"{xf.name} x{count}")
            content = new_content
    if content == artifact.content:
        return artifact, PassRecord(
            name=PASS_NAME, changed=False, transformations=(), notes=(),
        )
    return artifact.replace(content=content), PassRecord(
        name=PASS_NAME, changed=True, transformations=tuple(fired),
    )


__all__ = ["PASS_NAME", "TRANSFORMATIONS", "run"]
