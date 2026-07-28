"""NivXRay decoder diagnostic codes — stable machine-readable identifiers.

Introduced in v1.5.0 (follow-up) so analysts, dashboards, CI, and
downstream integrations key off codes instead of parsing free-text
reasons. Codes are:

* **Stable** — once assigned, a code number NEVER changes meaning.
  New codes get new numbers; deprecated codes are marked, never
  reused.
* **Namespaced** — ``DX1xxx`` = extraction / decoder failures,
  ``DX2xxx`` = engine / orchestration halts, ``DX3xxx`` = safety
  aborts. Higher digit = more severe.
* **Deterministic** — a given input always produces the same code.

Consumers should treat unknown codes as opaque and fall back to
``DecodeDiagnostic.reason`` for human-readable context.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DiagnosticCodeMeta:
    """One row in the code table. Kept alongside the code so the API
    can surface titles and categories without extra lookups."""
    code:       str
    title:      str
    category:   str       # "extraction" | "orchestration" | "safety"


# ── DX1xxx · Extraction / decoder failures ──────────────────────
CODE_INVALID_BASE64_LENGTH = "DX1001"
CODE_INVALID_BASE64_ALPHABET = "DX1002"
CODE_UTF16LE_DECODE_FAILED = "DX1003"
CODE_GZIP_DECOMPRESSION_FAILED = "DX1101"
CODE_DEFLATE_DECOMPRESSION_FAILED = "DX1102"
CODE_BROTLI_DECOMPRESSION_FAILED = "DX1103"
CODE_VARIABLE_RESOLUTION_FAILED = "DX1201"
CODE_UNSUPPORTED_COMPRESSION_STREAM = "DX1301"

# ── DX2xxx · Engine / orchestration halts ───────────────────────
CODE_MAX_DEPTH_REACHED = "DX2001"
CODE_NO_TRANSFORMATION = "DX2002"
CODE_LOOP_DETECTED     = "DX2003"


# Canonical registry. Kept as a plain dict so callers can enumerate
# it (docs generator, dashboard config, CI table validators). The
# order matches numerical code order for consistency.
DIAGNOSTIC_CODES: dict[str, DiagnosticCodeMeta] = {
    CODE_INVALID_BASE64_LENGTH:          DiagnosticCodeMeta(
        CODE_INVALID_BASE64_LENGTH,
        "Invalid Base64 length",
        "extraction",
    ),
    CODE_INVALID_BASE64_ALPHABET:        DiagnosticCodeMeta(
        CODE_INVALID_BASE64_ALPHABET,
        "Invalid Base64 alphabet",
        "extraction",
    ),
    CODE_UTF16LE_DECODE_FAILED:          DiagnosticCodeMeta(
        CODE_UTF16LE_DECODE_FAILED,
        "UTF-16LE decode failed",
        "extraction",
    ),
    CODE_GZIP_DECOMPRESSION_FAILED:      DiagnosticCodeMeta(
        CODE_GZIP_DECOMPRESSION_FAILED,
        "GZip decompression failed",
        "extraction",
    ),
    CODE_DEFLATE_DECOMPRESSION_FAILED:   DiagnosticCodeMeta(
        CODE_DEFLATE_DECOMPRESSION_FAILED,
        "Deflate decompression failed",
        "extraction",
    ),
    CODE_BROTLI_DECOMPRESSION_FAILED:    DiagnosticCodeMeta(
        CODE_BROTLI_DECOMPRESSION_FAILED,
        "Brotli decompression failed",
        "extraction",
    ),
    CODE_VARIABLE_RESOLUTION_FAILED:     DiagnosticCodeMeta(
        CODE_VARIABLE_RESOLUTION_FAILED,
        "Variable resolution failed",
        "extraction",
    ),
    CODE_UNSUPPORTED_COMPRESSION_STREAM: DiagnosticCodeMeta(
        CODE_UNSUPPORTED_COMPRESSION_STREAM,
        "Unsupported compression stream",
        "extraction",
    ),
    CODE_MAX_DEPTH_REACHED:              DiagnosticCodeMeta(
        CODE_MAX_DEPTH_REACHED,
        "Maximum recursion depth reached",
        "orchestration",
    ),
    CODE_NO_TRANSFORMATION:              DiagnosticCodeMeta(
        CODE_NO_TRANSFORMATION,
        "No further deterministic transformation",
        "orchestration",
    ),
    CODE_LOOP_DETECTED:                  DiagnosticCodeMeta(
        CODE_LOOP_DETECTED,
        "Recursion loop detected via content-hash",
        "orchestration",
    ),
}


__all__ = [
    "DiagnosticCodeMeta",
    "DIAGNOSTIC_CODES",
    "CODE_INVALID_BASE64_LENGTH",
    "CODE_INVALID_BASE64_ALPHABET",
    "CODE_UTF16LE_DECODE_FAILED",
    "CODE_GZIP_DECOMPRESSION_FAILED",
    "CODE_DEFLATE_DECOMPRESSION_FAILED",
    "CODE_BROTLI_DECOMPRESSION_FAILED",
    "CODE_VARIABLE_RESOLUTION_FAILED",
    "CODE_UNSUPPORTED_COMPRESSION_STREAM",
    "CODE_MAX_DEPTH_REACHED",
    "CODE_NO_TRANSFORMATION",
    "CODE_LOOP_DETECTED",
]
