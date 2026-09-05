"""Type contracts for the Universal Decoder Engine.

Every reconstruction the engine produces flows through
`ReconstructionResult` and `DecodedLayer`.  The static-safety
invariants (`static_only=True`, `execution=False`,
`attck_promotion=False`) are enforced structurally — an instance
that violates them cannot be constructed.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any


# ══════════════════════════════════════════════════════════════════
# Invariant contract (imported and asserted by every consumer)
# ══════════════════════════════════════════════════════════════════
RECONSTRUCTION_INVARIANTS = {
    "static_only":      True,
    "execution":        False,
    "attck_promotion":  False,
    "llm_authoritative": False,
    "runtime_bridge":   False,
}


class CapabilityKind(str, Enum):
    """Owner-locked classification per Phase-1 scope contract."""
    DECODER          = "DECODER"
    DEOBFUSCATOR     = "DEOBFUSCATOR"
    TRANSFORM        = "TRANSFORM"
    PARSER           = "PARSER"
    STATIC_ANALYZER  = "STATIC_ANALYZER"
    IOC              = "IOC"
    DETECTION        = "DETECTION"
    KNOWLEDGE        = "KNOWLEDGE"
    # ── rejected ──
    DYNAMIC          = "DYNAMIC"       # execution-required
    UI               = "UI"            # interactive
    IRRELEVANT       = "IRRELEVANT"


_ACCEPTED_KINDS = frozenset({
    CapabilityKind.DECODER,
    CapabilityKind.DEOBFUSCATOR,
    CapabilityKind.TRANSFORM,
    CapabilityKind.PARSER,
    CapabilityKind.STATIC_ANALYZER,
    CapabilityKind.IOC,
    CapabilityKind.DETECTION,
    CapabilityKind.KNOWLEDGE,
})


@dataclass(frozen=True)
class Capability:
    """A single named unit of decoding/deobfuscation capability."""
    name:           str
    kind:           CapabilityKind
    language:       str        # "cmd" | "powershell" | "bash" | "generic"
    version:        str = "0.1.0"
    description:    str = ""

    def __post_init__(self):
        if self.kind not in _ACCEPTED_KINDS:
            raise ValueError(
                f"Capability '{self.name}' declared as rejected kind "
                f"{self.kind}. Engine registry only accepts static-safe "
                f"kinds; move it out of the runtime path."
            )


@dataclass(frozen=True)
class Provenance:
    """Trace-back envelope for a single reconstruction layer."""
    decoded_from:      str
    capability_name:   str
    engine_version:    str
    recorded_at:       str
    static_only:       bool = True
    execution:         bool = False
    attck_promotion:   bool = False

    def __post_init__(self):
        # Structural enforcement: the three invariants are
        # non-negotiable.  Any attempt to construct with a violation
        # is rejected at instantiation time.
        if self.static_only is not True:
            raise ValueError("Provenance.static_only must be True.")
        if self.execution is not False:
            raise ValueError("Provenance.execution must be False.")
        if self.attck_promotion is not False:
            raise ValueError("Provenance.attck_promotion must be False.")


@dataclass(frozen=True)
class DecodedLayer:
    """One reconstruction step — a canonical CHILD of its parent input."""
    layer_index:      int
    stage:            str            # "cmd.caret_strip", "cmd.set_reassembly", ...
    language:         str            # "cmd" | "powershell" | "bash" | "generic"
    bytes_in:         int
    bytes_out:        int
    input_preview:    str
    output:           str
    capability:       Capability
    provenance:       Provenance
    confidence:       str = "HIGH"   # "HIGH" | "MEDIUM" | "LOW" | "UNCERTAIN"
    notes:            str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["capability"] = {
            "name":     self.capability.name,
            "kind":     self.capability.kind.value,
            "language": self.capability.language,
            "version":  self.capability.version,
        }
        d["op"] = self.stage
        d["decoder"] = self.stage
        d["sequence"] = self.layer_index
        d["reason"] = self.notes or f"Matched {self.stage}"
        d["why"] = d["reason"]
        d["why_selected"] = d["reason"]
        d["output_preview"] = self.output[:200] if self.output else ""
        d["preview"] = d["output_preview"]
        d["output_payload"] = self.output
        d["text"] = self.output
        d["output_length"] = self.bytes_out
        d["in_len"] = self.bytes_in
        d["out_len"] = self.bytes_out
        d["input_length"] = self.bytes_in
        d["status"] = "success"
        d["duration_ms"] = 0.0
        return d


@dataclass
class ReconstructionResult:
    """The complete engine output for a single input string.

    Consumers get a deterministic layer chain plus a `final` text
    that fully-peeled reconstruction produced (or the original raw
    input if no capability made progress — NEVER a fabricated
    guess).
    """
    raw_input:          str
    final:              str
    layers:             list[DecodedLayer]      = field(default_factory=list)
    unresolved_reasons: list[str]               = field(default_factory=list)
    partial:            bool                     = False
    engine_version:     str                      = ""
    # For A→G measurement.  Consumers do NOT read this to shape
    # detection — it is for reporting only.
    static_only_verified: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw_input":          self.raw_input,
            "final":              self.final,
            "layers":             [l.to_dict() for l in self.layers],
            "unresolved_reasons": list(self.unresolved_reasons),
            "partial":            self.partial,
            "engine_version":     self.engine_version,
            "static_only_verified": self.static_only_verified,
        }

    def has_progress(self) -> bool:
        return any(l.bytes_out > 0 and l.output for l in self.layers)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


__all__ = [
    "Capability",
    "CapabilityKind",
    "Provenance",
    "DecodedLayer",
    "ReconstructionResult",
    "RECONSTRUCTION_INVARIANTS",
    "now_iso",
]
