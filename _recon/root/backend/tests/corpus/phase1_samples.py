"""NivXRay Corpus · Phase 1 — Naked-Script Encoding Families
─────────────────────────────────────────────────────────────

Locked with SOC user 2026-07-27.

This module registers **naked** PowerShell samples (no
`powershell.exe -EncodedCommand …` wrapper) that exercise the entire
encoding-family surface. Each sample defines the FULL golden
specification:

    expected_decode_chain     – ordered technique labels (subset match, order-preserving)
    expected_final_payload    – case-insensitive substring the final resolved string MUST contain
    expected_boundary         – execution boundary op the deobfuscator must halt at
    expected_verdict          – allowed verdict values
    expected_mitre            – MITRE technique IDs (any-of)
    expected_behaviors        – behavior IDs (subset match)
    expected_iocs             – dict[kind → list[str]] of substrings to find in artifacts
    expected_coverage         – decode-coverage category tags the sample proves
    expected_storyline_flags  – { section_key → "observed" | "not_observed" }
    expected_confidence       – allowed verdict-confidence bands

Adding a sample = adding a function decorated with @phase1_sample.
Everything else is picked up automatically by
`test_corpus_phase1_regression.py`.
"""
from __future__ import annotations

import base64
import gzip as _gzip
import zlib as _zlib

try:
    import brotli as _brotli
except Exception:                          # pragma: no cover
    _brotli = None


# ── Registry ─────────────────────────────────────────────────────
CORPUS_PHASE1: list["Phase1Sample"] = []


from dataclasses import dataclass, field


@dataclass
class Phase1Sample:
    id:            str
    category:      str
    label:         str
    cmdline:       str
    expected_decode_chain:     list[str]
    expected_final_payload:    str
    expected_boundary:         str | None
    expected_verdict:          set[str]
    expected_mitre:            list[str]
    expected_behaviors:        list[str] = field(default_factory=list)
    expected_iocs:             dict = field(default_factory=dict)
    expected_coverage:         list[str] = field(default_factory=list)
    expected_storyline_flags:  dict = field(default_factory=dict)
    expected_confidence:       set[str] = field(default_factory=lambda: {"high", "medium", "low"})


def phase1_sample(*, id, category, label,
                    expected_decode_chain, expected_final_payload,
                    expected_boundary, expected_verdict, expected_mitre,
                    expected_behaviors=None, expected_iocs=None,
                    expected_coverage=None, expected_storyline_flags=None,
                    expected_confidence=None):
    """Decorator — the wrapped function returns the raw cmdline string."""
    def deco(fn):
        cmdline = fn()
        CORPUS_PHASE1.append(Phase1Sample(
            id=id, category=category, label=label, cmdline=cmdline,
            expected_decode_chain=list(expected_decode_chain),
            expected_final_payload=expected_final_payload,
            expected_boundary=expected_boundary,
            expected_verdict=set(expected_verdict),
            expected_mitre=list(expected_mitre),
            expected_behaviors=list(expected_behaviors or []),
            expected_iocs=dict(expected_iocs or {}),
            expected_coverage=list(expected_coverage or []),
            expected_storyline_flags=dict(expected_storyline_flags or {}),
            expected_confidence=set(expected_confidence or {"high", "medium", "low"}),
        ))
        return fn
    return deco


# ── Fixed target payload used across most samples ────────────────
# A single well-known plaintext keeps assertions deterministic and lets
# the golden checker verify that different encoding paths converge to
# the SAME final string.
TARGET_PAYLOAD = "Write-Host 'Hello, from PowerShell!'"


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _deflate_raw(data: bytes) -> bytes:
    """PowerShell DeflateStream emits raw deflate (no zlib header)."""
    c = _zlib.compressobj(-1, _zlib.DEFLATED, -_zlib.MAX_WBITS)
    return c.compress(data) + c.flush()


# ═══════════════════════════════════════════════════════════════════════════
#  ENCODING FAMILY SAMPLES (naked scripts — no `powershell.exe` wrapper)
# ═══════════════════════════════════════════════════════════════════════════


@phase1_sample(
    id="naked_base64", category="encoding", label="Base64 · [Convert]::FromBase64String",
    expected_decode_chain=["Decode Base64 payload"],
    expected_final_payload=TARGET_PAYLOAD,
    expected_boundary="Invoke-Expression",
    expected_verdict={"suspicious", "needs_review"},
    expected_mitre=["T1027", "T1059.001"],
    expected_behaviors=["invoke_expression", "payload_decode"],
    expected_coverage=["base64"],
    expected_storyline_flags={"initial_execution": "observed"},
)
def _naked_base64():
    blob = _b64(TARGET_PAYLOAD.encode("utf-8"))
    return f'IEX ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("{blob}")))'


@phase1_sample(
    id="naked_utf16le_b64", category="encoding",
    label="UTF-16LE Base64 · [Encoding]::Unicode.GetString(FromBase64String)",
    expected_decode_chain=["Decode UTF-16LE Base64"],
    expected_final_payload=TARGET_PAYLOAD,
    expected_boundary="Invoke-Expression",
    expected_verdict={"suspicious", "needs_review"},
    expected_mitre=["T1027", "T1059.001"],
    expected_behaviors=["invoke_expression", "payload_decode"],
    expected_coverage=["utf16le", "base64"],
    expected_storyline_flags={"initial_execution": "observed"},
)
def _naked_utf16le_b64():
    blob = _b64(TARGET_PAYLOAD.encode("utf-16-le"))
    return f'IEX ([System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("{blob}")))'


@phase1_sample(
    id="naked_gzip_b64", category="encoding",
    label="GZip over Base64 · [IO.Compression.GzipStream]",
    expected_decode_chain=["Decompress GZip stream"],
    expected_final_payload=TARGET_PAYLOAD,
    expected_boundary="Invoke-Expression",
    expected_verdict={"suspicious", "needs_review", "malicious"},
    expected_mitre=["T1027", "T1059.001", "T1140"],
    expected_behaviors=["invoke_expression", "payload_decompression"],
    expected_coverage=["gzip", "base64"],
    expected_storyline_flags={"initial_execution": "observed"},
)
def _naked_gzip_b64():
    blob = _b64(_gzip.compress(TARGET_PAYLOAD.encode("utf-8")))
    return (f'IEX ([IO.StreamReader]::new([IO.Compression.GzipStream]::new('
            f'[IO.MemoryStream][Convert]::FromBase64String("{blob}"),'
            f'[IO.Compression.CompressionMode]::Decompress)).ReadToEnd())')


@phase1_sample(
    id="naked_deflate_b64", category="encoding",
    label="Deflate over Base64 · [IO.Compression.DeflateStream]",
    expected_decode_chain=["Decompress Deflate stream"],
    expected_final_payload=TARGET_PAYLOAD,
    expected_boundary="Invoke-Expression",
    expected_verdict={"suspicious", "needs_review", "malicious"},
    expected_mitre=["T1027", "T1059.001", "T1140"],
    expected_behaviors=["invoke_expression", "payload_decompression"],
    expected_coverage=["deflate", "base64"],
    expected_storyline_flags={"initial_execution": "observed"},
)
def _naked_deflate_b64():
    blob = _b64(_deflate_raw(TARGET_PAYLOAD.encode("utf-8")))
    return (f'IEX ([IO.StreamReader]::new([IO.Compression.DeflateStream]::new('
            f'[IO.MemoryStream][Convert]::FromBase64String("{blob}"),'
            f'[IO.Compression.CompressionMode]::Decompress)).ReadToEnd())')


@phase1_sample(
    id="naked_brotli_b64", category="encoding",
    label="Brotli over Base64 · [IO.Compression.BrotliStream]",
    expected_decode_chain=["Decompress Brotli stream"],
    expected_final_payload=TARGET_PAYLOAD,
    expected_boundary="Invoke-Expression",
    expected_verdict={"suspicious", "needs_review", "malicious"},
    expected_mitre=["T1027", "T1059.001", "T1140"],
    expected_behaviors=["invoke_expression", "payload_decompression"],
    expected_coverage=["brotli", "base64"],
    expected_storyline_flags={"initial_execution": "observed"},
)
def _naked_brotli_b64():
    if _brotli is None:
        # If brotli lib is unavailable at collection time, register a placeholder
        # command line that will produce a benign decode-error — the test will
        # skip when the runtime brotli lib isn't installed.
        return "IEX 'brotli-unavailable-at-collection-time'"
    blob = _b64(_brotli.compress(TARGET_PAYLOAD.encode("utf-8")))
    return (f'IEX ([IO.StreamReader]::new([IO.Compression.BrotliStream]::new('
            f'[IO.MemoryStream][Convert]::FromBase64String("{blob}"),'
            f'[IO.Compression.CompressionMode]::Decompress)).ReadToEnd())')


@phase1_sample(
    id="naked_hex", category="encoding", label="Hex char array · [Convert]::ToInt16(x,16)",
    expected_decode_chain=["Hex ASCII reconstruction"],
    expected_final_payload=TARGET_PAYLOAD,
    expected_boundary="Invoke-Expression",
    expected_verdict={"suspicious", "needs_review", "malicious"},
    expected_mitre=["T1027", "T1059.001", "T1027.010"],
    expected_behaviors=["invoke_expression", "char_array_join"],
    expected_coverage=["hex", "char_array"],
    expected_storyline_flags={"initial_execution": "observed"},
)
def _naked_hex():
    hex_list = ",".join(f"0x{ord(c):02x}" for c in TARGET_PAYLOAD)
    return (f'$s = -join (({hex_list}) | %{{ [char][Convert]::ToInt16($_,16) }});'
            f'Invoke-Expression $s')


@phase1_sample(
    id="naked_octal", category="encoding", label="Octal char array · [Convert]::ToInt16(x,8)",
    expected_decode_chain=["Octal ASCII reconstruction"],
    expected_final_payload=TARGET_PAYLOAD,
    expected_boundary="Invoke-Expression",
    expected_verdict={"suspicious", "needs_review", "malicious"},
    expected_mitre=["T1027", "T1059.001", "T1027.010"],
    expected_behaviors=["invoke_expression", "char_array_join"],
    expected_coverage=["octal", "char_array"],
    expected_storyline_flags={"initial_execution": "observed"},
)
def _naked_octal():
    oct_list = ",".join(oct(ord(c))[2:] for c in TARGET_PAYLOAD)
    return (f'$s = [String]::Join([char]0, [char[]](({oct_list}) '
            f'| %{{ [char][Convert]::ToInt16($_,8) }})); Invoke-Expression $s')


@phase1_sample(
    id="naked_binary", category="encoding", label="Binary char array · [Convert]::ToInt16(x,2)",
    expected_decode_chain=["Binary ASCII reconstruction"],
    expected_final_payload=TARGET_PAYLOAD,
    expected_boundary="Invoke-Expression",
    expected_verdict={"suspicious", "needs_review", "malicious"},
    expected_mitre=["T1027", "T1059.001", "T1027.010"],
    expected_behaviors=["invoke_expression", "char_array_join"],
    expected_coverage=["binary", "char_array"],
    expected_storyline_flags={"initial_execution": "observed"},
)
def _naked_binary():
    bin_list = ",".join(bin(ord(c))[2:] for c in TARGET_PAYLOAD)
    return (f'$s = -join (({bin_list}) | %{{ [char][Convert]::ToInt16($_,2) }});'
            f'Invoke-Expression $s')


@phase1_sample(
    id="naked_decimal", category="encoding", label="Decimal char array · [char[]](87,114,...)",
    expected_decode_chain=["Decimal char[] reconstruction"],
    expected_final_payload=TARGET_PAYLOAD,
    expected_boundary="Invoke-Expression",
    expected_verdict={"suspicious", "needs_review", "malicious"},
    expected_mitre=["T1027", "T1059.001", "T1027.010"],
    expected_behaviors=["invoke_expression", "char_array_join"],
    expected_coverage=["decimal", "char_array"],
    expected_storyline_flags={"initial_execution": "observed"},
)
def _naked_decimal():
    dec_list = ",".join(str(ord(c)) for c in TARGET_PAYLOAD)
    return (f'$s = -join ([char[]](({dec_list}) | %{{ [char]$_ }}));'
            f'Invoke-Expression $s')


@phase1_sample(
    id="naked_variable_radix", category="encoding",
    label="Variable radix · octal → hex → decimal char rebuild inside a `-f` wrapper",
    expected_decode_chain=[
        "Resolve .NET string format",
        "Octal ASCII reconstruction",
    ],
    expected_final_payload=TARGET_PAYLOAD,
    expected_boundary="Invoke-Expression",
    expected_verdict={"suspicious", "needs_review", "malicious"},
    expected_mitre=["T1027", "T1059.001", "T1027.010"],
    expected_behaviors=["invoke_expression", "char_array_join"],
    expected_coverage=["octal", "hex", "decimal", "string_format"],
    expected_storyline_flags={"initial_execution": "observed"},
)
def _naked_variable_radix():
    oct_list = ",".join(oct(ord(c))[2:] for c in TARGET_PAYLOAD)
    return (f'$cmDwhy=[TyPe]("{{0}}{{1}}" -f \'S\',\'TrING\');'
            f'$s=[String]::Join([char]0,[char[]](({oct_list}) '
            f'| %{{ [char][Convert]::ToInt16($_,8) }}));'
            f'Invoke-Expression $s')


@phase1_sample(
    id="naked_mixed_gzip_b64_utf16", category="encoding",
    label="Mixed chain · GZip → Base64 (transport) with UTF-16LE payload interpretation",
    expected_decode_chain=[
        "Decompress GZip stream",
    ],
    expected_final_payload=TARGET_PAYLOAD,
    expected_boundary="Invoke-Expression",
    expected_verdict={"suspicious", "needs_review", "malicious"},
    expected_mitre=["T1027", "T1059.001", "T1140"],
    expected_behaviors=["invoke_expression", "payload_decompression"],
    expected_coverage=["gzip", "utf16le", "base64"],
    expected_storyline_flags={"initial_execution": "observed"},
)
def _naked_mixed_gzip_b64_utf16():
    blob = _b64(_gzip.compress(TARGET_PAYLOAD.encode("utf-16-le")))
    return (f'IEX ([IO.StreamReader]::new([IO.Compression.GzipStream]::new('
            f'[IO.MemoryStream][Convert]::FromBase64String("{blob}"),'
            f'[IO.Compression.CompressionMode]::Decompress)).ReadToEnd())')


# ── Public accessors ─────────────────────────────────────────────
def all_phase1_samples() -> list[Phase1Sample]:
    return list(CORPUS_PHASE1)
