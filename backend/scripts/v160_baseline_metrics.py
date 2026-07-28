"""P0.5 · Baseline metrics capture for the v1.6.0 planning gate.

Per SME steer 2026-02-XX: before Phase 1 lands, capture the CURRENT
decoder performance and behaviour envelope so every subsequent phase
can be diffed against a locked baseline.

Metrics captured
================
Per corpus sample AND aggregated:

    * decode latency (P50, P95, max, mean) over N=5 warm runs
    * RTE recursion depth
    * RTE steps count
    * peak process RSS during decode (Linux only)
    * pipeline coverage (which stages fired)
    * verdict band
    * intents fired count
    * determinism hash (repeated 2x — must be identical)

This script is pure OBSERVATION. It does not modify the pipeline; it
only invokes ``investigate()`` and reads the resulting dicts.

Usage
=====

    python -m scripts.v160_baseline_metrics --out memory/V1_6_0_BASELINE_METRICS.md
    python -m scripts.v160_baseline_metrics --json         # for CI diffing

Output
======
Markdown table sorted by sample id, aggregate section at the top.
"""
from __future__ import annotations

import argparse
import gc
import json
import os
import resource
import statistics
import sys
import time
from pathlib import Path
from typing import Any

_BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))


_CORPUS_DIR = _BACKEND_ROOT / "tests" / "trust_corpus"


def _peak_rss_kb() -> int:
    """Peak resident-set-size in KB for THIS process (Linux)."""
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss


def _time_investigate(text: str, n: int = 5) -> dict[str, Any]:
    """Run investigate() N times, capturing per-run latency."""
    from v2.investigation.pipeline import investigate
    # Warm-up run — first invocation pays JIT / import-cache costs.
    _ = investigate(text)
    gc.collect()
    rss_before = _peak_rss_kb()
    latencies_ms: list[float] = []
    hashes: list[str] = []
    inv_last = None
    for _ in range(n):
        t0 = time.perf_counter_ns()
        inv_last = investigate(text)
        latencies_ms.append((time.perf_counter_ns() - t0) / 1e6)
        d = inv_last.to_dict() if hasattr(inv_last, "to_dict") else {}
        h = ((d.get("rte") or {}).get("determinism_hash")
             or d.get("determinism_hash") or "")
        hashes.append(h)
    rss_after = _peak_rss_kb()
    inv_d = inv_last.to_dict() if inv_last and hasattr(inv_last, "to_dict") else {}
    rte = inv_d.get("rte") or {}
    v = inv_d.get("verdict") or {}
    intent = inv_d.get("intent") or {}
    coverage = inv_d.get("coverage") or []
    return {
        "latency_p50_ms": statistics.median(latencies_ms),
        "latency_p95_ms": (sorted(latencies_ms)[int(0.95 * (n - 1))]
                           if n > 1 else latencies_ms[0]),
        "latency_max_ms": max(latencies_ms),
        "latency_mean_ms": statistics.mean(latencies_ms),
        "runs":            n,
        "rte_depth":       rte.get("depth"),
        "rte_layers":      len(rte.get("artifacts") or []),
        "rte_steps":       len(rte.get("steps") or []),
        "rte_stop":        rte.get("stop_reason"),
        "diagnostics":     [d.get("code") for d in (rte.get("diagnostics") or [])],
        "coverage":        coverage,
        "verdict_band":    v.get("band"),
        "verdict_conf":    v.get("confidence"),
        "intents_fired":   len(intent.get("intents") or []),
        "determinism_hash_first": hashes[0],
        "determinism_hash_stable": len(set(hashes)) == 1,
        "peak_rss_kb":     rss_after,
        "rss_delta_kb":    rss_after - rss_before,
    }


def _load_yaml_samples() -> list[tuple[str, str, str]]:
    """Return [(sample_id, input, expected_verdict), …]."""
    import yaml
    out: list[tuple[str, str, str]] = []
    for f in sorted(_CORPUS_DIR.glob("*.yaml")):
        d = yaml.safe_load(f.read_text(encoding="utf-8"))
        out.append((d["id"], d["input"].strip(), d.get("expected_verdict", "?")))
    return out


def collect_baseline(n: int = 5) -> dict[str, Any]:
    samples = _load_yaml_samples()
    per_sample: list[dict[str, Any]] = []
    for sid, text, expected in samples:
        m = _time_investigate(text, n=n)
        m["sample_id"] = sid
        m["expected_verdict"] = expected
        m["actual_matches_expected"] = (m["verdict_band"] == expected)
        m["input_bytes"] = len(text)
        per_sample.append(m)

    # Aggregate
    latencies_p50 = [s["latency_p50_ms"] for s in per_sample]
    latencies_p95 = [s["latency_p95_ms"] for s in per_sample]
    latencies_max = [s["latency_max_ms"] for s in per_sample]
    depths        = [s["rte_depth"] or 0 for s in per_sample]
    steps         = [s["rte_steps"] for s in per_sample]
    hashes_stable = all(s["determinism_hash_stable"] for s in per_sample)

    # Corpus pass rate (verdict-band match)
    pass_hits = sum(1 for s in per_sample if s["actual_matches_expected"])
    # False-positive rate: benign samples that got malicious/suspicious
    fp = sum(
        1 for s in per_sample
        if s["expected_verdict"] == "benign"
        and s["verdict_band"] in ("malicious", "suspicious")
    )
    fp_denom = sum(1 for s in per_sample if s["expected_verdict"] == "benign")

    return {
        "captured_at":         time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "commit_baseline":     os.popen("cd /app && git rev-parse HEAD 2>/dev/null").read().strip()[:12],
        "runs_per_sample":     n,
        "total_samples":       len(per_sample),
        "aggregate": {
            "latency_p50_ms_min":  round(min(latencies_p50), 2),
            "latency_p50_ms_max":  round(max(latencies_p50), 2),
            "latency_p50_ms_mean": round(statistics.mean(latencies_p50), 2),
            "latency_p95_ms_max":  round(max(latencies_p95), 2),
            "latency_max_ms":      round(max(latencies_max), 2),
            "rte_depth_min":       min(depths),
            "rte_depth_max":       max(depths),
            "rte_steps_max":       max(steps),
            "determinism_hash_stable_all": hashes_stable,
            "pass_rate":           round(pass_hits / len(per_sample), 4),
            "pass_count":          pass_hits,
            "false_positive_rate": round(fp / fp_denom, 4) if fp_denom else 0.0,
            "false_positive_count": fp,
            "peak_rss_kb":         max(s["peak_rss_kb"] for s in per_sample),
        },
        "per_sample": per_sample,
    }


def render_markdown(data: dict[str, Any]) -> str:
    a = data["aggregate"]
    L: list[str] = []
    L.append(f"# NivXRay v1.6.0 · Baseline Metrics (P0.5)")
    L.append("")
    L.append(f"- **Captured**: `{data['captured_at']}`")
    L.append(f"- **Commit (approx)**: `{data['commit_baseline']}`")
    L.append(f"- **Corpus size**: {data['total_samples']} samples")
    L.append(f"- **Runs per sample**: {data['runs_per_sample']}")
    L.append("")
    L.append("## Aggregate")
    L.append("")
    L.append("| Metric | Value |")
    L.append("| --- | --- |")
    L.append(f"| Latency P50 min / mean / max (ms) | {a['latency_p50_ms_min']} / {a['latency_p50_ms_mean']} / {a['latency_p50_ms_max']} |")
    L.append(f"| Latency P95 max (ms) | {a['latency_p95_ms_max']} |")
    L.append(f"| Latency max observed (ms) | {a['latency_max_ms']} |")
    L.append(f"| RTE depth min / max | {a['rte_depth_min']} / {a['rte_depth_max']} |")
    L.append(f"| RTE steps max | {a['rte_steps_max']} |")
    L.append(f"| Peak RSS across corpus (KB) | {a['peak_rss_kb']:,} |")
    L.append(f"| Corpus pass rate | **{a['pass_rate']*100:.1f} %** ({a['pass_count']}/{data['total_samples']}) |")
    L.append(f"| False-positive rate (benign → mal/susp) | **{a['false_positive_rate']*100:.2f} %** ({a['false_positive_count']}) |")
    L.append(f"| Determinism hash stable across all samples | **{a['determinism_hash_stable_all']}** |")
    L.append("")
    L.append("## Per-sample")
    L.append("")
    L.append("| sample_id | bytes | depth | steps | stop | P50 ms | P95 ms | verdict | expected | ✓ | DX |")
    L.append("| --- | ---: | ---: | ---: | --- | ---: | ---: | --- | --- | :---: | --- |")
    for s in data["per_sample"]:
        L.append(
            f"| `{s['sample_id']}` | {s['input_bytes']} | {s['rte_depth']} | "
            f"{s['rte_steps']} | {s['rte_stop']} | "
            f"{s['latency_p50_ms']:.1f} | {s['latency_p95_ms']:.1f} | "
            f"{s['verdict_band']} | {s['expected_verdict']} | "
            f"{'✅' if s['actual_matches_expected'] else '❌'} | "
            f"{','.join(s['diagnostics']) if s['diagnostics'] else '—'} |"
        )
    L.append("")
    L.append("## How to use this file")
    L.append("")
    L.append("Every v1.6.0 PR that touches the decode pipeline MUST attach a")
    L.append("**delta table** against these numbers, produced by re-running")
    L.append("`python -m scripts.v160_baseline_metrics --json` on the PR branch.")
    L.append("Regressions:")
    L.append("")
    L.append("- P95 latency ↑ > 15 %  → **HARD FAIL** (requires SME sign-off).")
    L.append("- Any sample flips from ✅ to ❌  → **HARD FAIL**.")
    L.append("- Any determinism hash becomes unstable  → **HARD FAIL**.")
    L.append("- False-positive rate ↑ from 0  → **HARD FAIL**.")
    L.append("- Peak RSS ↑ > 25 %  → soft fail (review, may be legitimate).")
    L.append("")
    L.append("_This file is generated. Do NOT edit by hand — re-run the")
    L.append("script to refresh._")
    return "\n".join(L)


def main() -> int:
    p = argparse.ArgumentParser(description="v1.6.0 baseline metrics capture")
    p.add_argument("--out", help="markdown output path")
    p.add_argument("--json", action="store_true", help="emit JSON instead")
    p.add_argument("--runs", type=int, default=5, help="runs per sample (default 5)")
    a = p.parse_args()
    data = collect_baseline(n=a.runs)
    if a.json:
        print(json.dumps(data, indent=2, sort_keys=True))
        return 0
    md = render_markdown(data)
    if a.out:
        Path(a.out).write_text(md, encoding="utf-8")
        print(f"wrote {a.out} · {len(md):,} bytes")
    else:
        print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
