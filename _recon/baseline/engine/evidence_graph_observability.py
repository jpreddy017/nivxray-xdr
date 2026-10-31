"""RC5 · Phase 11.0 · Evidence Graph — side-car observability.

In-memory rolling telemetry for every side-car build. Operational only —
NEVER influences verdicts, scoring, or any analyst-visible output beyond
the dedicated `/api/rc5/evidence-graph/metrics` endpoint.

Design
------
* Bounded `collections.deque` with a fixed window (default 500 most
  recent builds). Constant-time append; zero unbounded memory growth.
* Thread-safe via a single module-level `Lock`.
* Aggregation is computed on-demand from the current window — no
  background threads, no persistence. Preview only.
* Failed builds are counted separately so the success rate is honest.

Contract
--------
`record(metrics=None, error=False)` is the only write path.
`aggregate()` returns the current window's summary.
`reset()` clears the window (used by tests + admin diagnostic reset).
"""
from __future__ import annotations

import statistics
import threading
from collections import deque
from dataclasses import dataclass, asdict
from typing import Any, Deque, Dict, Optional

from .evidence_graph_config import EvidenceGraphMetrics

# Window sized for a couple of minutes of preview-tier traffic. Bumped
# via `set_window_size()` in tests; production preview will not exceed
# this in the periods observability actually matters.
_WINDOW: int = 500
_LOCK = threading.Lock()
_SAMPLES: Deque[EvidenceGraphMetrics] = deque(maxlen=_WINDOW)
_ERRORS: int = 0
_TOTAL: int = 0


@dataclass(frozen=True)
class ObservabilitySnapshot:
    window_size: int
    sample_count: int
    total_seen: int
    error_count: int
    success_rate: float
    build_ms_p50: float
    build_ms_p95: float
    build_ms_max: float
    peak_memory_kb_p50: float
    peak_memory_kb_p95: float
    peak_memory_kb_max: float
    node_count_mean: float
    edge_count_mean: float
    integrity_error_total: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def record(metrics: Optional[EvidenceGraphMetrics], error: bool = False) -> None:
    """Record a single sidecar build outcome. `metrics` may be None when
    `error=True` (the build failed and metrics couldn't be collected)."""
    global _ERRORS, _TOTAL
    with _LOCK:
        _TOTAL += 1
        if error or metrics is None:
            _ERRORS += 1
            return
        _SAMPLES.append(metrics)


def reset() -> None:
    global _ERRORS, _TOTAL
    with _LOCK:
        _SAMPLES.clear()
        _ERRORS = 0
        _TOTAL = 0


def set_window_size(n: int) -> None:
    """Only used by tests to shrink the window for fast fixture setup."""
    global _SAMPLES, _WINDOW
    with _LOCK:
        _WINDOW = max(1, int(n))
        _SAMPLES = deque(_SAMPLES, maxlen=_WINDOW)


def _pct(vals, q: float) -> float:
    if not vals:
        return 0.0
    xs = sorted(vals)
    k = max(0, min(len(xs) - 1, int(round(q / 100.0 * (len(xs) - 1)))))
    return float(xs[k])


def aggregate() -> ObservabilitySnapshot:
    with _LOCK:
        snapshot = list(_SAMPLES)
        errors = _ERRORS
        total = _TOTAL
    build_ms = [m.build_ms for m in snapshot]
    peak_kb  = [m.peak_memory_kb for m in snapshot]
    node_cnt = [m.node_count for m in snapshot]
    edge_cnt = [m.edge_count for m in snapshot]
    integ    = sum(m.integrity_errors for m in snapshot)

    success_rate = 1.0
    if total > 0:
        success_rate = round((total - errors) / total, 4)

    return ObservabilitySnapshot(
        window_size=_WINDOW,
        sample_count=len(snapshot),
        total_seen=total,
        error_count=errors,
        success_rate=success_rate,
        build_ms_p50=round(_pct(build_ms, 50), 3),
        build_ms_p95=round(_pct(build_ms, 95), 3),
        build_ms_max=round(max(build_ms) if build_ms else 0.0, 3),
        peak_memory_kb_p50=round(_pct(peak_kb, 50), 3),
        peak_memory_kb_p95=round(_pct(peak_kb, 95), 3),
        peak_memory_kb_max=round(max(peak_kb) if peak_kb else 0.0, 3),
        node_count_mean=round(statistics.fmean(node_cnt) if node_cnt else 0.0, 2),
        edge_count_mean=round(statistics.fmean(edge_cnt) if edge_cnt else 0.0, 2),
        integrity_error_total=integ,
    )


__all__ = ["record", "reset", "aggregate", "set_window_size", "ObservabilitySnapshot"]
