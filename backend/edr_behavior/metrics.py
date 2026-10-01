"""Engine observability. Counts and latencies only; never telemetry values."""
from __future__ import annotations

from collections import Counter
from typing import Any, Dict

NAMES = ("events_evaluated", "events_rejected_malformed", "tenant_isolation_rejections",
         "candidate_rules", "sequence_states", "matches", "suppressed_matches",
         "insufficient_evidence", "budget_exceeded", "window_truncated", "rule_errors",
         "detections_created", "detections_merged", "duplicates_prevented",
         "concurrency_retries", "replay_runs", "replay_events")


class Metrics:
    def __init__(self) -> None:
        self.c: Counter = Counter()
        self.per_rule: Counter = Counter()
        self.latency_ms_total = 0.0
        self.latency_ms_max = 0.0
        self.latency_samples = 0
        self.state_size_max = 0

    def inc(self, name: str, n: int = 1) -> None:
        if name not in NAMES:
            raise KeyError(name)
        self.c[name] += n

    def rule_outcome(self, rule_id: str, version: int, outcome: str) -> None:
        self.per_rule[(rule_id, version, outcome)] += 1

    def latency(self, ms: float) -> None:
        self.latency_ms_total += ms
        self.latency_samples += 1
        self.latency_ms_max = max(self.latency_ms_max, ms)

    def state(self, size: int) -> None:
        self.state_size_max = max(self.state_size_max, size)

    def snapshot(self) -> Dict[str, Any]:
        return {"counters": {n: self.c.get(n, 0) for n in NAMES},
                "per_rule": {f"{r}@v{v}:{o}": n for (r, v, o), n in sorted(self.per_rule.items())},
                "latency_ms": {"samples": self.latency_samples, "max": round(self.latency_ms_max, 3),
                               "avg": round(self.latency_ms_total / self.latency_samples, 3)
                               if self.latency_samples else 0.0},
                "window_state_size_max": self.state_size_max}
