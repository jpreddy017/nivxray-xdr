"""RC2.3 latency profiler.

Runs the benchmark corpus with full plugin_report captured, then reports:
  * p50 / p95 / p99 / max latency across all samples
  * slowest 5 samples with per-stage breakdown
  * aggregate time spent per plugin_id across the entire corpus
  * fingerprint / decode / intelligence-pass / tail-trim split when identifiable

The profiler reads timings from `AnalystReport.plugin_report.entries`, which
already records `exec_ms` for every accepted or rejected plugin invocation.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from collections import defaultdict
from typing import Any, Dict, List

from engine import AnalysisContext, Budget, Orchestrator
import decoders  # noqa: F401 — register all plugins

from tests.rc23_benchmark import SAMPLES


def _run_one(sample: Dict[str, Any], wall_time_ms: int = 8000) -> Dict[str, Any]:
    ctx = AnalysisContext(budget=Budget(wall_time_ms=wall_time_ms))
    t0 = time.monotonic_ns()
    report = Orchestrator(ctx).run(sample["input"])
    total_ms = (time.monotonic_ns() - t0) // 1_000_000

    # Per-plugin aggregation across all layers
    per_plugin: Dict[str, int] = defaultdict(int)
    per_outcome: Dict[str, int] = defaultdict(int)
    for e in report.plugin_report.entries:
        per_plugin[e.plugin] += e.exec_ms or 0
        per_outcome[e.outcome] += 1

    return {
        "id": sample["id"],
        "category": sample["category"],
        "total_ms": total_ms,
        "engine_ms": report.plugin_report.total_time_ms,
        "orchestrator_overhead_ms": max(0, total_ms - report.plugin_report.total_time_ms),
        "layers_run": report.plugin_report.layers_run,
        "per_plugin_ms": dict(per_plugin),
        "outcome_counts": dict(per_outcome),
        "input_len": len(sample["input"]),
    }


def _pct(values: List[int], pct: float) -> int:
    if not values:
        return 0
    s = sorted(values)
    k = int(round(pct * (len(s) - 1)))
    return s[k]


def main(argv: List[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="RC2.3 latency profiler")
    p.add_argument("--json", help="Write full JSON here")
    args = p.parse_args(argv)

    results = [_run_one(s) for s in SAMPLES]

    latencies = [r["total_ms"] for r in results]
    print("\n" + "=" * 78)
    print("  RC2.3 Latency Profile — full corpus")
    print("=" * 78)
    print(f"\n  Samples:       {len(latencies)}")
    print(f"  Mean:          {int(statistics.mean(latencies))} ms")
    print(f"  Median (p50):  {_pct(latencies, 0.50)} ms")
    print(f"  p90:           {_pct(latencies, 0.90)} ms")
    print(f"  p95:           {_pct(latencies, 0.95)} ms")
    print(f"  p99:           {_pct(latencies, 0.99)} ms")
    print(f"  Max:           {max(latencies)} ms")

    print("\n  Slowest 5 samples:")
    slowest = sorted(results, key=lambda r: -r["total_ms"])[:5]
    for r in slowest:
        top_plugins = sorted(
            r["per_plugin_ms"].items(), key=lambda kv: -kv[1]
        )[:5]
        breakdown = ", ".join(f"{k}={v}ms" for k, v in top_plugins)
        print(f"    {r['id']:40s} {r['total_ms']:>5d} ms  (layers={r['layers_run']}, in_len={r['input_len']})")
        print(f"      top plugins: {breakdown}")

    print("\n  Aggregate time per plugin across full corpus:")
    plugin_totals: Dict[str, int] = defaultdict(int)
    plugin_calls: Dict[str, int] = defaultdict(int)
    for r in results:
        for pid, ms in r["per_plugin_ms"].items():
            plugin_totals[pid] += ms
        for outcome, n in r["outcome_counts"].items():
            plugin_calls[outcome] += n

    for pid, ms in sorted(plugin_totals.items(), key=lambda kv: -kv[1])[:12]:
        print(f"    {pid:35s} {ms:>5d} ms")

    print("\n  Outcome counts (total plugin invocations across corpus):")
    for outcome, n in sorted(plugin_calls.items(), key=lambda kv: -kv[1]):
        print(f"    {outcome:20s} {n:>4d}")

    print("\n  Under 500ms target?", sum(1 for l in latencies if l < 500),
          f"/{len(latencies)}")
    print("  Under 3s target?  ", sum(1 for l in latencies if l < 3000),
          f"/{len(latencies)}")
    print("=" * 78)

    if args.json:
        with open(args.json, "w") as f:
            json.dump({
                "p50": _pct(latencies, 0.50),
                "p95": _pct(latencies, 0.95),
                "p99": _pct(latencies, 0.99),
                "max": max(latencies),
                "results": results,
            }, f, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
