"""Engine data models — the shared contract every layer speaks.

Design notes
------------
- Pydantic v2 is used ONLY where a JSON-serialisable, self-documenting cross-layer
  contract clearly pays off (Fingerprint, TraceStep, DetectResult, DecodeResult).
- Plain dataclasses are used for hot-path runtime objects (Budget, TraceBuffer,
  AnalysisContext) to avoid per-call validation overhead.
- schema_version is minimal today (bumped by hand); trace records it so future
  replays can pick the right decoder version.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# L0 output — Fingerprint
# ---------------------------------------------------------------------------
class Fingerprint(BaseModel):
    """Structural probe result for a single payload.

    Emitted by L0 probes; consumed by L2 decoder registry to filter candidates.
    Kept small and JSON-friendly so it can be rendered on the frontend Trace panel.
    """
    input_len: int
    printable_ratio: float = 0.0            # 0..1
    english_density: float = 0.0            # 0..1
    entropy: float = 0.0                    # Shannon bits/byte
    is_binary: bool = False
    encoding_candidates: List[Dict[str, Any]] = Field(default_factory=list)
    # e.g. [{"name": "base64", "alphabet_fit": 0.98, "length_mod": 0}, ...]
    file_type: Optional[str] = None         # "PE", "OLE", "OOXML", "RTF", ...
    wrapper_type: Optional[str] = None      # "powershell", "cmd", "hta", ...
    notes: List[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Decoder plug-in contract
# ---------------------------------------------------------------------------
class DetectResult(BaseModel):
    """A decoder's confidence that it applies to the current payload."""
    confidence: float = Field(ge=0.0, le=1.0)
    why: str = ""
    args: Dict[str, Any] = Field(default_factory=dict)
    # args passes decoder-specific config (e.g. xor key candidate list) to decode()


class DecodeResult(BaseModel):
    """A decoder's output after applying decode()."""
    output: str                             # decoded text (or Latin-1 encoded bytes)
    output_is_binary: bool = False
    notes: List[str] = Field(default_factory=list)
    sub_iocs: Dict[str, List[str]] = Field(default_factory=dict)
    # sub_iocs lets a decoder surface IOCs it saw locally (e.g. XOR key reveals URL)


class TraceStep(BaseModel):
    """One layer of the recursive decode chain. Displayed on the frontend."""
    layer: int
    decoder: str                            # canonical id, e.g. "base64-decode"
    schema_version: str = "1.0"
    confidence: float
    why: str
    in_len: int
    out_len: int
    exec_ms: int
    preview: str                            # first 200 chars of decoded output
    args: Dict[str, Any] = Field(default_factory=dict)
    sub_iocs: Dict[str, List[str]] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Terminal outcome
# ---------------------------------------------------------------------------
class DecodeOutcome(BaseModel):
    """Final orchestrator result surfaced to callers (routers, tests, frontend)."""
    output: str
    trace: List[TraceStep] = Field(default_factory=list)
    fingerprint_history: List[Fingerprint] = Field(default_factory=list)
    terminal: str = "no-op"                 # "shellcode" | "english" | "budget" | "no-candidate" | ...
    stopped_reason: str = ""
    elapsed_ms: int = 0
    engine: str = "orchestrator-v1"


# ---------------------------------------------------------------------------
# Runtime objects (dataclasses — fast, mutable, no validation cost)
# ---------------------------------------------------------------------------
@dataclass
class Budget:
    """Single source of truth for orchestrator resource limits.

    All limits are checked at each layer boundary. When any limit is breached,
    the orchestrator terminates with `terminal="budget"`.
    """
    max_depth: int = 12
    max_branches: int = 3
    wall_time_ms: int = 5000
    start_ns: int = field(default_factory=time.monotonic_ns)

    def elapsed_ms(self) -> int:
        return (time.monotonic_ns() - self.start_ns) // 1_000_000

    def time_left_ms(self) -> int:
        return max(0, self.wall_time_ms - self.elapsed_ms())

    def exhausted(self, depth: int) -> Optional[str]:
        if depth >= self.max_depth:
            return f"depth_cap:{self.max_depth}"
        if self.elapsed_ms() >= self.wall_time_ms:
            return f"time_cap:{self.wall_time_ms}ms"
        return None


@dataclass
class TraceBuffer:
    """Append-only trace collector. Passed through every layer via AnalysisContext."""
    steps: List[TraceStep] = field(default_factory=list)
    fingerprints: List[Fingerprint] = field(default_factory=list)

    def add_step(self, step: TraceStep) -> None:
        self.steps.append(step)

    def add_fingerprint(self, fp: Fingerprint) -> None:
        self.fingerprints.append(fp)


@dataclass
class AnalysisContext:
    """Per-request context carried through L0-L1-L2-L3.

    Purposely minimal in Phase A. Extended in later phases with cache, ai_gate,
    settings, request_id, user, etc.
    """
    budget: Budget = field(default_factory=Budget)
    trace: TraceBuffer = field(default_factory=TraceBuffer)
    ai_enabled: bool = False
    settings: Dict[str, Any] = field(default_factory=dict)
