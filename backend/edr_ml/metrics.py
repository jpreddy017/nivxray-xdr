"""ML observability. Counts, latency and state size only; never telemetry values."""
from __future__ import annotations

from collections import Counter
from typing import Any, Dict

NAMES = ("events_processed", "events_rejected", "duplicates", "features_extracted", "features_unknown",
         "features_cold", "cold_start", "unknown_outcomes", "signals_emitted", "signals_suppressed",
         "model_errors", "schema_mismatch", "baseline_updates", "baseline_duplicates",
         "baseline_rate_limited", "baseline_frozen", "baseline_time_rejected")
_BASELINE = {"UPDATED": "baseline_updates", "DUPLICATE": "baseline_duplicates",
             "RATE_LIMITED": "baseline_rate_limited", "FROZEN": "baseline_frozen",
             "TIME_REJECTED": "baseline_time_rejected"}


class MLMetrics:
    def __init__(self) -> None:
        self.c: Counter = Counter()
        self.per_model: Counter = Counter()
        self.latency_ms_total = self.latency_ms_max = 0.0
        self.latency_samples = 0
        self.baseline_state_size = 0

    def inc(self, name: str, n: int = 1) -> None:
        if name not in NAMES:
            raise KeyError(name)
        self.c[name] += n

    def baseline(self, outcome: str) -> None:
        self.inc(_BASELINE[outcome])

    def model_outcome(self, model_id: str, version: str, outcome: str) -> None:
        self.per_model[(model_id, version, outcome)] += 1

    def latency(self, ms: float) -> None:
        self.latency_ms_total += ms
        self.latency_samples += 1
        self.latency_ms_max = max(self.latency_ms_max, ms)

    def snapshot(self) -> Dict[str, Any]:
        return {"counters": {n: self.c.get(n, 0) for n in NAMES},
                "per_model": {f"{m}@{v}:{o}": n for (m, v, o), n in sorted(self.per_model.items())},
                "latency_ms": {"samples": self.latency_samples, "max": round(self.latency_ms_max, 3),
                               "avg": round(self.latency_ms_total / self.latency_samples, 3)
                               if self.latency_samples else 0.0},
                "baseline_state_size": self.baseline_state_size}
