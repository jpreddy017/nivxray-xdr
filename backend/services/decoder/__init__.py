"""NivXRay XDR · Universal Decoder & Command Deobfuscation Engine
────────────────────────────────────────────────────────────────
P0-1B Phase 2 · Gate 2A scaffold · owner-locked 2026-09-02.

**XDR-OWNED. NO runtime dependency on any external project.**
Bridges to CyberChef / CMD-DeObfuscator / Invoke-DOSfuscation /
Invoke-Obfuscation / PowerDecode / PSDecode / batch_deobfuscator /
BatchAlchemy are FORBIDDEN. Knowledge harvested from those sources
is documented under `ATTRIBUTION/` and reimplemented clean-room.

Static safety invariants (baked in at the type level, verified by
`DecodedLayer.__post_init__` and `RECONSTRUCTION_INVARIANTS`):
  · `static_only=True`          — never emulate arbitrary execution
  · `execution=False`           — never invoke the language interpreter
  · `attck_promotion=False`     — decoding is EVIDENCE, not a verdict
  · DECODED ≠ EXECUTED          — analysts see reconstruction only
  · provenance mandatory        — every layer carries `decoded_from`
  · NO EVIDENCE → NO CLAIM      — unresolved cases return UNCERTAIN,
                                  never fabricated
  · LLM never authoritatively decodes — validators only

Capability classification (per `Capability.kind`):
  DECODER       reverses a codec (Base64, GZIP, XOR, …)          — Plane A
  DEOBFUSCATOR  strips syntactic obfuscation (carets, backticks) — Plane B
  TRANSFORM     lossless syntactic transform (reverse, join)     — Plane A/B
  PARSER        structural extraction (tokens, AST)              — Plane B
  STATIC_ANALYZER    passive analysis                             — either
  IOC           indicator extraction                              — either
  DETECTION     surface rule / pattern                            — either
  KNOWLEDGE     registry lookup (LOLBAS, cmdlet alias)           — Plane B
  DYNAMIC       execution-required (REJECTED)                    — forbidden
  UI            interactive (REJECTED for engine layer)          — forbidden
  IRRELEVANT    not applicable                                    — rejected

Gate 2A ships:
  · Engine types + registry + orchestrator
  · CMD sub-engine (caret · %VAR% · !VAR! · SET reassembly)
  · Acceptance harness scaffolding
  · Zero PowerShell / Bash / codec expansion (later gates)
"""
from __future__ import annotations

from .types import (
    DecodedLayer,
    ReconstructionResult,
    Capability,
    CapabilityKind,
    Provenance,
    RECONSTRUCTION_INVARIANTS,
)
from .registry import CapabilityRegistry, get_registry
from .engine import UniversalDecoderEngine, decode as decode_universal

__all__ = [
    "DecodedLayer",
    "ReconstructionResult",
    "Capability",
    "CapabilityKind",
    "Provenance",
    "RECONSTRUCTION_INVARIANTS",
    "CapabilityRegistry",
    "get_registry",
    "UniversalDecoderEngine",
    "decode_universal",
]

# Semantic versioning of the engine. Bumped on every gate.
ENGINE_VERSION = "0.3.0-gate2c"
