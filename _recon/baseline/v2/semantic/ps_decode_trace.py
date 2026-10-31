"""NivXRay Explainable Decoder Trace (Phase 9.4).

Records every decoder step the semantic pipeline attempted — INCLUDING
skipped ones — with a human-readable explanation of *why* each step ran
or was declined.

Purpose: the analyst UI renders this as a vertical `Full Decode
Timeline` so a Tier-2 can audit the engine's decisions.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class DecodeStep:
    order: int
    decoder: str
    status: str                 # applied | skipped | failed
    reason: str                 # human-facing WHY
    input_hash: str = ""
    output_hash: str = ""
    input_len: int = 0
    output_len: int = 0
    duration_ms: float = 0.0
    preview: str = ""           # first 200 chars of output
    meta: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def _sha256(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8", errors="ignore")
    return hashlib.sha256(data).hexdigest()[:16]


class DecodeTrace:
    """Ordered, immutable-after-write trace of decoder decisions."""
    def __init__(self) -> None:
        self._steps: list[DecodeStep] = []

    def add(self, decoder: str, *, status: str, reason: str,
            input_val: str = "", output_val: str = "",
            duration_ms: float = 0.0, meta: dict | None = None) -> None:
        self._steps.append(DecodeStep(
            order=len(self._steps),
            decoder=decoder,
            status=status,
            reason=reason,
            input_hash=_sha256(input_val) if input_val else "",
            output_hash=_sha256(output_val) if output_val else "",
            input_len=len(input_val),
            output_len=len(output_val),
            duration_ms=round(duration_ms, 3),
            preview=(output_val[:200] if output_val else ""),
            meta=meta or {},
        ))

    def timed(self, decoder: str, *, reason: str,
              input_val: str, fn) -> Optional[str]:
        """Run `fn(input_val)` while recording the step. Returns the fn
        result. On exception, records status=failed and returns None."""
        t0 = time.perf_counter()
        try:
            out = fn(input_val)
        except Exception as e:  # noqa: BLE001
            self.add(decoder, status="failed", reason=f"{reason} · exception: {type(e).__name__}",
                     input_val=input_val, duration_ms=(time.perf_counter() - t0) * 1000)
            return None
        dt = (time.perf_counter() - t0) * 1000
        if not out:
            self.add(decoder, status="skipped", reason=f"{reason} · decoder returned no output",
                     input_val=input_val, duration_ms=dt)
            return None
        self.add(decoder, status="applied", reason=reason,
                 input_val=input_val, output_val=out, duration_ms=dt)
        return out

    def skipped(self, decoder: str, *, reason: str, input_val: str = "") -> None:
        self.add(decoder, status="skipped", reason=reason, input_val=input_val)

    def to_list(self) -> list[dict]:
        return [s.to_dict() for s in self._steps]

    @property
    def steps(self) -> list[DecodeStep]:
        return list(self._steps)
