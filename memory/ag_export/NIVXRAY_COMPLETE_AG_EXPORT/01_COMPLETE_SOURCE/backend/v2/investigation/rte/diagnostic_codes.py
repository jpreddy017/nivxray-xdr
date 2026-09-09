"""NivXRay decoder diagnostic codes — stable machine-readable identifiers.

Introduced in v1.5.0 (follow-up) so analysts, dashboards, CI, and
downstream integrations key off codes instead of parsing free-text
reasons. Codes are:

* **Stable** — once assigned, a code number NEVER changes meaning.
  New codes get new numbers; deprecated codes are marked, never
  reused.
* **Namespaced by reserved range** (v1.5.0 · pre-allocated for v2.0
  so we never repaint the palette):

    ``DX1xxx``  Decoder / extraction failures
    ``DX2xxx``  RTE engine / orchestration halts
    ``DX3xxx``  Semantic resolver (def-use, variable chains) · v1.6.0+
    ``DX4xxx``  Crypto (XOR / RC4 / AES) · v1.6.0+
    ``DX5xxx``  IOC extraction · v1.6.0+
    ``DX6xxx``  Parser (PowerShell AST, CMD tokeniser) · v1.7.0+
    ``DX7xxx``  Output / evidence validation · v1.7.0+
    ``DX8xxx``  Corpus / regression harness · v1.7.0+
    ``DX9xxx``  Internal / infrastructure

* **Deterministic** — a given input always produces the same code.
* **Causal** — every ``DecodeDiagnostic`` carries an optional
  ``caused_by`` pointer so the UI can render a directed graph
  (``DX2002 ← DX1001 ← Blob length = 2635``) rather than a flat
  list.
* **Severity-tagged** — ``error`` / ``warning`` / ``info`` so
  dashboards can prioritise.

Consumers should treat unknown codes as opaque and fall back to
``DecodeDiagnostic.reason`` for human-readable context.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DiagnosticCodeMeta:
    """One row in the code table. Kept alongside the code so the API
    can surface titles, categories and severity without extra
    lookups.

    ``severity`` values:

    * ``"error"``   — decoding was requested and could not proceed.
    * ``"warning"`` — the pipeline stopped for a reason that MIGHT
      still be the correct terminal state but deserves review.
    * ``"info"``    — informational only; expected in the normal
      convergence path.
    """
    code:       str
    title:      str
    category:   str       # "extraction" | "orchestration" | "safety"
    severity:   str       # "error" | "warning" | "info"


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
        "extraction", "error",
    ),
    CODE_INVALID_BASE64_ALPHABET:        DiagnosticCodeMeta(
        CODE_INVALID_BASE64_ALPHABET,
        "Invalid Base64 alphabet",
        "extraction", "error",
    ),
    CODE_UTF16LE_DECODE_FAILED:          DiagnosticCodeMeta(
        CODE_UTF16LE_DECODE_FAILED,
        "UTF-16LE decode failed",
        "extraction", "error",
    ),
    CODE_GZIP_DECOMPRESSION_FAILED:      DiagnosticCodeMeta(
        CODE_GZIP_DECOMPRESSION_FAILED,
        "GZip decompression failed",
        "extraction", "error",
    ),
    CODE_DEFLATE_DECOMPRESSION_FAILED:   DiagnosticCodeMeta(
        CODE_DEFLATE_DECOMPRESSION_FAILED,
        "Deflate decompression failed",
        "extraction", "error",
    ),
    CODE_BROTLI_DECOMPRESSION_FAILED:    DiagnosticCodeMeta(
        CODE_BROTLI_DECOMPRESSION_FAILED,
        "Brotli decompression failed",
        "extraction", "error",
    ),
    CODE_VARIABLE_RESOLUTION_FAILED:     DiagnosticCodeMeta(
        CODE_VARIABLE_RESOLUTION_FAILED,
        "Variable resolution failed",
        "extraction", "warning",
    ),
    CODE_UNSUPPORTED_COMPRESSION_STREAM: DiagnosticCodeMeta(
        CODE_UNSUPPORTED_COMPRESSION_STREAM,
        "Unsupported compression stream",
        "extraction", "info",
    ),
    CODE_MAX_DEPTH_REACHED:              DiagnosticCodeMeta(
        CODE_MAX_DEPTH_REACHED,
        "Maximum recursion depth reached",
        "orchestration", "warning",
    ),
    CODE_NO_TRANSFORMATION:              DiagnosticCodeMeta(
        CODE_NO_TRANSFORMATION,
        "No further deterministic transformation",
        "orchestration", "info",
    ),
    CODE_LOOP_DETECTED:                  DiagnosticCodeMeta(
        CODE_LOOP_DETECTED,
        "Recursion loop detected via content-hash",
        "orchestration", "warning",
    ),
}


def severity_of(code: str) -> str:
    """Return the canonical severity for ``code`` or ``"unknown"``.

    Consumers should always tolerate ``"unknown"`` gracefully so newer
    codes emitted by an upgraded engine never break older dashboards.
    """
    meta = DIAGNOSTIC_CODES.get(code)
    return meta.severity if meta else "unknown"


__all__ = [
    "DiagnosticCodeMeta",
    "DIAGNOSTIC_CODES",
    "severity_of",
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
