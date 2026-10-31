"""UAIE · Deterministic Planner (Priority 3 · frozen).

Replaces plugin-insertion-order dispatch with an artifact-type
dependency graph, so capabilities always execute in the CORRECT
forensic order regardless of registration order:

    Text
      │
      ├── powershell.*  (normalizers first — reconstruct, alias,
      │                   backtick, hex_escape)  → powershell_normalized
      │
    powershell_normalized
      │
      ├── powershell.encoded_command → powershell (base64 → utf-16le)
      │
    powershell
      │
      ├── base64.from_base64_string → base64_decoded
      ├── base64.bare               → base64_decoded
      │
    base64_decoded
      │
      ├── gzip.inflate  → gzip_decoded
      ├── zlib.inflate  → zlib_decoded
      │
    gzip_decoded / zlib_decoded
      │
      ├── shellcode.string_scan     → evidence only
      ├── shellcode.analyzer        → pe_bytes / cs_config_raw children
      │
    pe_bytes           → pe.analyzer         → pe_report evidence
    cs_config_raw      → family.cobalt_strike.beacon_config
                                              → cs_config.* evidence
    <unclassified>     → crypto.xor_brute    → xor_decoded child

Contract
────────
    plan(artifact_type, available_capabilities) → List[Capability]
        · deterministic ordering (sort key)
        · idempotent (same input → same order)
        · never drops capabilities — orders them
        · analyzer capabilities always run BEFORE family emitters
          (fixes the current 3 xfails)

The Planner does NOT decide EXCLUSION.  The Orchestrator remains
responsible for the ``requires_evidence`` / ``requires_artifact_type``
prerequisite check.  The Planner only decides ORDER.
"""
from __future__ import annotations

from typing import Dict, List

from .capability import Capability


# ── Dependency-graph priority table (lower = earlier).  Any plugin
# not listed defaults to ``_DEFAULT_PRIORITY`` (10).
_PRIORITY: Dict[str, int] = {
    # Text-layer normalizers first
    "powershell.reconstruct":            10,
    "powershell.alias_normalizer":       11,
    "powershell.backtick_normalizer":    12,
    "powershell.hex_escape":             13,
    # Priority-3 op-adapter PS transformers (canonicalise → un-obfuscate)
    "op.powershell-normalize":           14,
    "op.powershell-reverse-string":      15,
    "op.powershell-reverse-regex-swap":  16,
    "op.powershell-semantic-mini":       17,
    "op.powershell-hex-csv-inline":      18,
    "op.powershell-xor-inline-key":      19,
    # Encoded-command → powershell
    "powershell.encoded_command":        20,
    "op.ps-encodedcommand-multilayer":   21,
    # Base64 layer
    "base64.from_base64_string":         30,
    "base64.bare":                       31,
    # Compression layer
    "gzip.inflate":                      40,
    "zlib.inflate":                      41,
    # ANALYSIS layer (must run BEFORE family emitters — fixes xfails)
    "shellcode.analyzer":                50,
    "pe.extractor":                      50,   # extract embedded PEs first
    "pe.analyzer":                       51,
    "pe.dotnet_recognizer":              52,   # after pe.analyzer
    # STRING SCAN (baseline evidence — before family emitters)
    "shellcode.string_scan":             52,
    # FAMILY layer (runs LAST so it consumes analyzer output)
    "family.cobalt_strike.beacon_config": 60,
    "family.universal_recognizer":        61,
    # CRYPTO fallback (only when nothing else has matched)
    "op.crypto-api-annotator":           45,  # signal-only annotator early
    "crypto.shape_detector":             46,  # detect ciphertext presence
    "op.rc4-inline-decrypt":             47,  # deterministic inline RC4
    "crypto.rc4":                        48,  # RC4 with key-hunt
    "crypto.aes_cbc":                    49,  # AES-CBC with key/IV hunt
    "crypto.xor_brute":                  99,
}
_DEFAULT_PRIORITY = 55


def priority_of(cap: Capability) -> int:
    """Deterministic priority for one capability."""
    return _PRIORITY.get(getattr(cap, "name", ""), _DEFAULT_PRIORITY)


def plan(available: List[Capability]) -> List[Capability]:
    """Deterministic capability order for an artifact.

    Stable-sorted by ``priority_of`` then by name so two runs on
    identical input produce identical execution order (R28 purity).
    """
    return sorted(
        available,
        key=lambda c: (priority_of(c), getattr(c, "name", "")),
    )


__all__ = ["plan", "priority_of"]
