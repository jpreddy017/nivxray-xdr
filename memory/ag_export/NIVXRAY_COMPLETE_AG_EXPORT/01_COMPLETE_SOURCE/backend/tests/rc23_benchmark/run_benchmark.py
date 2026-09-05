"""RC2.3 Chain-Completeness Benchmark harness.

Runs every sample in `SAMPLES` through the current Orchestrator and produces
a per-sample record + per-category summary. This measures the tool AS-IS —
it does NOT modify decoders. Use it to establish baselines and prove that
future changes are pure improvements.

Usage
-----
$ cd /app/backend && python -m tests.rc23_benchmark.run_benchmark
$ cd /app/backend && python -m tests.rc23_benchmark.run_benchmark --json out.json

Fields captured per sample (per user requirements)
--------------------------------------------------
  * Sample ID
  * Category
  * Initial detection (terminal state)
  * Decode depth
  * Chain complete (bool)
  * Final readable payload (bool)
  * Stop reason (terminal + stopped_reason)
  * Confidence (risk_score)
  * Time taken (ms)
  * Notes
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict
from typing import Any, Dict, List

# Import registers all plugins as a side-effect
from engine import AnalysisContext, Budget, Orchestrator  # noqa: F401
import decoders  # noqa: F401 — triggers plugin registration

from tests.rc23_benchmark import SAMPLES


def _run_one(sample: Dict[str, Any], wall_time_ms: int = 8000) -> Dict[str, Any]:
    ctx = AnalysisContext(budget=Budget(wall_time_ms=wall_time_ms))
    t0 = time.monotonic_ns()
    try:
        report = Orchestrator(ctx).run(sample["input"])
        error = None
    except Exception as exc:                                # pragma: no cover
        report = None
        error = f"{type(exc).__name__}: {exc}"
    t1 = time.monotonic_ns()
    elapsed_ms = (t1 - t0) // 1_000_000

    if report is None:
        return {
            "id": sample["id"], "category": sample["category"],
            "error": error, "time_ms": elapsed_ms,
        }

    # Chain completeness: all expected_terms present (case-insensitive) in either
    # final output OR any trace preview (so partial-chain finds still count).
    haystack = (report.output or "").lower()
    for step in report.trace:
        haystack += "\n" + (step.preview or "").lower()
    expected = [t.lower() for t in sample.get("expected_terms", [])]
    hits = [t for t in expected if t in haystack]
    complete = len(hits) == len(expected)

    # Final readable payload: printable ratio ≥ 0.85 AND at least one expected
    # term present.
    from engine.fingerprint_util import compute as _fp
    fp = _fp(report.output)
    final_readable = fp.printable_ratio >= 0.85 and any(t in haystack for t in expected)

    # IOC extraction: check must_extract dict
    ioc_expected = sample.get("must_extract", {})
    iocs_missing: List[str] = []
    for kind, values in ioc_expected.items():
        found = set(getattr(report.findings.iocs, kind, []) or [])
        for v in values:
            if v not in found:
                iocs_missing.append(f"{kind}:{v}")

    # False-positive IOCs: extracted URLs/IPs that weren't in must_extract
    false_positives: List[str] = []
    if ioc_expected:
        expected_urls = set(ioc_expected.get("urls", []))
        for u in report.findings.iocs.urls:
            if u not in expected_urls and "example." not in u and "evil." not in u \
                    and "mal." not in u and "c2." not in u and "phish." not in u \
                    and "drop." not in u and "tail." not in u and "bad." not in u \
                    and "cmd-c2." not in u:
                false_positives.append(u)

    return {
        "id": sample["id"],
        "category": sample["category"],
        "decode_depth": len(report.trace),
        "chain_complete": complete,
        "final_readable": final_readable,
        "terms_hit": f"{len(hits)}/{len(expected)}",
        "terms_missing": [t for t in expected if t not in haystack],
        "iocs_missing": iocs_missing,
        "false_positive_iocs": false_positives,
        "stop_reason": report.terminal,
        "stopped_detail": (report.stopped_reason or "")[:120],
        "confidence": report.findings.risk_score,
        "verdict": report.findings.verdict,
        "expected_verdict": sample.get("expected_verdict"),
        "time_ms": elapsed_ms,
        "chain": [s.decoder for s in report.trace],
        "notes": sample.get("notes", ""),
    }


def _summarise(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    by_cat = defaultdict(list)
    for r in results:
        by_cat[r["category"]].append(r)

    summary_rows = []
    total_complete = 0
    total_readable = 0
    total_correct_verdict = 0
    total_false_positive = 0
    for cat, rows in sorted(by_cat.items()):
        n = len(rows)
        complete = sum(1 for r in rows if r.get("chain_complete"))
        readable = sum(1 for r in rows if r.get("final_readable"))
        verdict_ok = sum(
            1 for r in rows
            if r.get("verdict") == r.get("expected_verdict")
        )
        false_pos = sum(len(r.get("false_positive_iocs") or []) for r in rows)
        avg_ms = sum(r.get("time_ms", 0) for r in rows) / max(1, n)
        summary_rows.append({
            "category": cat,
            "total": n,
            "chain_complete": f"{complete}/{n}",
            "chain_complete_pct": round(100 * complete / n, 1),
            "final_readable": f"{readable}/{n}",
            "verdict_precise": f"{verdict_ok}/{n}",
            "false_positive_iocs": false_pos,
            "avg_time_ms": int(avg_ms),
        })
        total_complete += complete
        total_readable += readable
        total_correct_verdict += verdict_ok
        total_false_positive += false_pos

    overall_n = len(results)
    return {
        "overall": {
            "total_samples": overall_n,
            "chain_complete": f"{total_complete}/{overall_n}",
            "chain_complete_pct": round(100 * total_complete / overall_n, 1),
            "final_readable": f"{total_readable}/{overall_n}",
            "verdict_precise": f"{total_correct_verdict}/{overall_n}",
            "false_positive_iocs": total_false_positive,
            "avg_time_ms": int(sum(r.get("time_ms", 0) for r in results) / max(1, overall_n)),
        },
        "by_category": summary_rows,
    }


def _print_summary(summary: Dict[str, Any], results: List[Dict[str, Any]]) -> None:
    print("\n" + "=" * 78)
    print("  RC2.3 Chain-Completeness Benchmark")
    print("=" * 78)

    print("\nPer-sample:")
    hdr = f"  {'ID':32s} {'CAT':13s} {'DEPTH':>5s} {'CHAIN':>5s} {'MS':>5s}  STOP"
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))
    for r in results:
        depth = str(r.get("decode_depth", "-"))
        chain = "OK" if r.get("chain_complete") else "..."
        ms = str(r.get("time_ms", 0))
        stop = (r.get("stop_reason") or "-")[:20]
        print(f"  {r['id']:32s} {r['category']:13s} {depth:>5s} {chain:>5s} {ms:>5s}  {stop}")

    print("\nPer-category:")
    hdr = f"  {'CATEGORY':16s} {'TOTAL':>5s} {'COMPLETE':>10s} {'READABLE':>10s} {'VERDICT':>10s} {'FP':>3s} {'ms/avg':>7s}"
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))
    for row in summary["by_category"]:
        print(f"  {row['category']:16s} "
              f"{row['total']:>5d} "
              f"{row['chain_complete']:>10s} "
              f"{row['final_readable']:>10s} "
              f"{row['verdict_precise']:>10s} "
              f"{row['false_positive_iocs']:>3d} "
              f"{row['avg_time_ms']:>7d}")

    print("\nOverall:")
    o = summary["overall"]
    print(f"  Total samples:          {o['total_samples']}")
    print(f"  Chain complete:         {o['chain_complete']}  ({o['chain_complete_pct']}%)")
    print(f"  Final readable:         {o['final_readable']}")
    print(f"  Verdict precision:      {o['verdict_precise']}")
    print(f"  False-positive IOCs:    {o['false_positive_iocs']}")
    print(f"  Avg decode time:        {o['avg_time_ms']} ms")
    print("=" * 78)


def main(argv: List[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="RC2.3 chain-completeness benchmark")
    p.add_argument("--json", help="Write full JSON results here")
    p.add_argument("--wall-time-ms", type=int, default=8000)
    args = p.parse_args(argv)

    results = [_run_one(s, wall_time_ms=args.wall_time_ms) for s in SAMPLES]
    summary = _summarise(results)
    _print_summary(summary, results)
    if args.json:
        with open(args.json, "w") as f:
            json.dump({"summary": summary, "results": results}, f, indent=2)
        print(f"\nFull results written to {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
