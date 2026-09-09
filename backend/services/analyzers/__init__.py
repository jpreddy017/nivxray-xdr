"""Artifact analyzers — separate from codecs (owner architectural rule).

PE + shellcode are *analyzers* / parsers, not codecs.  The Universal
Decoder invokes them via a clean adapter when evidence indicates an
artifact (MZ header for PE, prologue/entropy signature for shellcode);
they never become part of the base/encoding/compression/crypto codec
surface.

Gate 2D-B3.2 status:
  · PE       — authoritative impl at `services.analyzers.pe`
                (legacy re-export shim: `services.pe_analyzer`)
  · Shellcode — authoritative impl at `services.analyzers.shellcode`
                (legacy re-export shim: `shellcode_analyzer`)

Invariants (preserved end-to-end):
    static_only         = True
    execution           = False
    network_access      = False
    attck_promotion     = False
    provenance_required = True

Analyzers NEVER execute an artifact.  They read bytes, parse structure,
extract deterministic evidence, and emit a report.
"""
from __future__ import annotations

# Convenience re-exports so callers can `from services.analyzers import pe, shellcode`
from . import pe as pe               # noqa: F401
from . import shellcode as shellcode # noqa: F401


ANALYZER_INVARIANTS = {
    "static_only":         True,
    "execution":           False,
    "network_access":      False,
    "attck_promotion":     False,
    "provenance_required": True,
}


__all__ = ["pe", "shellcode", "ANALYZER_INVARIANTS"]
