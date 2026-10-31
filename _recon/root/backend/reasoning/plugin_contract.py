"""NivXRay Decoder Plugin Contract (Feb-2026 roadmap).

Standardized interface every decoder MAY implement so the reasoning engine
can dispatch uniformly. Existing 87+ ops in `operations.py` / `ops_extended.py`
remain callable through `run_operation(op_id, input, args)`; this contract
is an OPT-IN wrapper that lets a plugin declare rich metadata for the
reasoning loop.

Contract (per user's Feb-2026 architectural prompt):

    CanDecode(input)   → bool
        Cheap upfront check. Returns True iff this decoder has a plausible
        chance of producing meaningful output. Enables O(1) candidate pruning.

    Confidence(input)  → float ∈ [0.0, 1.0]
        Structural-validity confidence BEFORE decoding. E.g. base64 shape
        with valid padding = 0.9, ambiguous mixed-case = 0.4, non-alphabet
        char = 0.0.

    Decode(input, args) → str | bytes
        Perform the transformation. Raises on invalid input.

    Validate(output)   → bool
        Post-decode sanity check. E.g. gzip CRC valid, JSON parseable,
        printable ratio above threshold.

    Explain()          → str
        Human-readable rationale — surfaced in the analyst UI.

    SuggestNext(output) → list[str]
        Ordered list of op_ids likely to be useful on the decoded output.
        E.g. base64-decode → ["utf16le-decode", "gzip-decompress"].

The reasoning engine calls these in this order:
    1. CanDecode → filter candidates
    2. Confidence → rank candidates
    3. Decode → apply top-K
    4. Validate → confirm improvement
    5. Explain → surface the "why"
    6. SuggestNext → seed the next iteration
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class DecoderResult:
    """Result of a single decoder invocation."""
    op: str
    output: str
    input_confidence: float          # Structural pre-decode confidence [0,1]
    validation_passed: bool          # Post-decode Validate() result
    explanation: str                 # Human-readable rationale
    next_suggestions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "op": self.op,
            "output": self.output,
            "input_confidence": round(self.input_confidence, 4),
            "validation_passed": self.validation_passed,
            "explanation": self.explanation,
            "next_suggestions": self.next_suggestions,
            "metadata": self.metadata,
        }


class DecoderPlugin(ABC):
    """Abstract base — every rich-metadata decoder implements this.

    Plugins register themselves via `PLUGIN_REGISTRY.register(instance)`.
    The reasoning engine iterates registered plugins in `CanDecode()` order
    to build a candidate list.
    """

    # Human-readable identifier (also used as op_id in run_operation).
    op_id: str = "abstract"
    # Rough category tag for grouping in UI: "encoding", "compression",
    # "cipher", "container", "obfuscation", "text-transform".
    category: str = "encoding"

    @abstractmethod
    def can_decode(self, text: str) -> bool: ...

    @abstractmethod
    def confidence(self, text: str) -> float:
        """Pre-decode structural confidence. Return in [0.0, 1.0]."""

    @abstractmethod
    def decode(self, text: str, args: Optional[Dict[str, Any]] = None) -> str:
        """Perform the transformation. Raises on invalid input."""

    def validate(self, output: str) -> bool:
        """Post-decode sanity check. Default: non-empty printable-ish text."""
        if not output:
            return False
        printable = sum(1 for c in output if 32 <= ord(c) < 127 or c in "\r\n\t")
        return printable / max(len(output), 1) >= 0.60

    def explain(self) -> str:
        """Default one-line explanation."""
        return f"{self.op_id} ({self.category})"

    def suggest_next(self, output: str) -> List[str]:
        """Default: no follow-ups. Override for chain hints."""
        return []


class _PluginRegistry:
    """Thread-unsafe (single-process) plugin registry.

    Plugins are OPT-IN — registered explicitly, not auto-imported. Keeps
    the existing 87+ ops untouched while allowing new decoders to declare
    the rich contract when it adds value (nested obfuscation, ciphers,
    LLM-assisted decoders).
    """

    def __init__(self):
        self._plugins: Dict[str, DecoderPlugin] = {}

    def register(self, plugin: DecoderPlugin) -> None:
        if not plugin.op_id or plugin.op_id == "abstract":
            raise ValueError("plugin.op_id must be set")
        self._plugins[plugin.op_id] = plugin

    def get(self, op_id: str) -> Optional[DecoderPlugin]:
        return self._plugins.get(op_id)

    def candidates(self, text: str, min_confidence: float = 0.10) -> List[DecoderPlugin]:
        """Return plugins whose can_decode(text) is True, sorted by
        confidence descending. Cheap: no actual decoding happens here."""
        eligible: List[tuple] = []
        for p in self._plugins.values():
            try:
                if not p.can_decode(text):
                    continue
                conf = p.confidence(text)
                if conf < min_confidence:
                    continue
                eligible.append((conf, p))
            except Exception:
                continue
        eligible.sort(key=lambda x: -x[0])
        return [p for _, p in eligible]

    def all(self) -> List[DecoderPlugin]:
        return list(self._plugins.values())


PLUGIN_REGISTRY = _PluginRegistry()
