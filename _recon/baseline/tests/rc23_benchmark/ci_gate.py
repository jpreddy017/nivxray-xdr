"""RC2.3 benchmark CI gate.

Runs the full RC2.3 chain-completeness benchmark and fails the build if:
  * chain_complete_pct drops below the frozen RC2.3 baseline (77.4%)
  * false_positive_iocs > 0 (any FP-IOC regression is a hard failure)
  * any sample takes longer than MAX_SAMPLE_MS (default 8000ms)

Exit codes
----------
    0  → all gates passed
    1  → chain-completeness regression
    2  → false-positive IOC regression
    3  → performance regression
    4  → benchmark itself failed to run

Usage
-----
    # From /app/backend:
    $ python -m tests.rc23_benchmark.ci_gate
    $ python -m tests.rc23_benchmark.ci_gate --min-chain-pct 77.4 --max-fp 0

The frozen baseline is RC2.3 Stable = 24/31 = 77.4%. Future work that
lowers this floor must be an intentional, reviewed, and re-labelled release.
"""
from __future__ import annotations

import argparse
import sys
from typing import List

# Side-effect: register all plugins
import decoders  # noqa: F401
from tests.rc23_benchmark import SAMPLES
from tests.rc23_benchmark.run_benchmark import _run_one, _summarise


# RC3.0 Stable baseline — frozen 2026-02-20 after production deploy + user validation.
# The RC2.3 floor (77.4%) is preserved as an ABSOLUTE FLOOR — anything below
# that is a catastrophic regression. The RC3.0 baseline is where every merge
# must live from Feb-2026 onward.
BASELINE_CHAIN_PCT = 96.7          # 30/31 · locked at RC3.0
BASELINE_VERDICT_PRECISION = 15    # 15/31 · locked at RC3.0
BASELINE_MAX_FP_IOCS = 0
BASELINE_MAX_AVG_MS = 500          # blink-of-eye · avg per-sample ≤ 500ms
DEFAULT_MAX_SAMPLE_MS = 8000
ABSOLUTE_FLOOR_PCT = 77.4          # RC2.3 catastrophic-regression floor


def main(argv: List[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="RC3.0 benchmark CI gate")
    p.add_argument("--min-chain-pct", type=float, default=BASELINE_CHAIN_PCT,
                   help=f"minimum chain_complete_pct (default={BASELINE_CHAIN_PCT})")
    p.add_argument("--min-verdict", type=int, default=BASELINE_VERDICT_PRECISION,
                   help=f"minimum verdict-precision hits (default={BASELINE_VERDICT_PRECISION}/31)")
    p.add_argument("--max-fp", type=int, default=BASELINE_MAX_FP_IOCS,
                   help=f"maximum false-positive IOCs (default={BASELINE_MAX_FP_IOCS})")
    p.add_argument("--max-avg-ms", type=int, default=BASELINE_MAX_AVG_MS,
                   help=f"maximum avg latency per sample (default={BASELINE_MAX_AVG_MS}ms)")
    p.add_argument("--max-sample-ms", type=int, default=DEFAULT_MAX_SAMPLE_MS)
    args = p.parse_args(argv)

    try:
        results = [_run_one(s, wall_time_ms=args.max_sample_ms) for s in SAMPLES]
        summary = _summarise(results)
    except Exception as exc:                                # pragma: no cover
        print(f"[ci-gate] FATAL: benchmark run failed — {exc}", file=sys.stderr)
        return 4

    chain_pct = summary["overall"]["chain_complete_pct"]
    fp_iocs = summary["overall"]["false_positive_iocs"]
    # `verdict_precise` is a "N/M" string ("15/31"). Parse the numerator.
    vp_raw = summary["overall"].get("verdict_precise", "0/0")
    try:
        verdict_hits = int(str(vp_raw).split("/")[0])
    except (ValueError, IndexError):
        verdict_hits = 0
    avg_ms = summary["overall"]["avg_time_ms"]

    print(f"[ci-gate] chain_complete_pct    = {chain_pct}%  "
          f"(RC3.0 floor {args.min_chain_pct}%, RC2.3 hard floor {ABSOLUTE_FLOOR_PCT}%)")
    print(f"[ci-gate] verdict_precision     = {verdict_hits}/31 "
          f"(RC3.0 floor {args.min_verdict}/31)")
    print(f"[ci-gate] false_positive_iocs   = {fp_iocs}     "
          f"(ceiling {args.max_fp})")
    print(f"[ci-gate] avg_time_ms           = {avg_ms} ms "
          f"(RC3.0 ceiling {args.max_avg_ms}ms)")
    print(f"[ci-gate] chain_complete        = "
          f"{summary['overall']['chain_complete']}")

    slow: List[str] = []
    for r in results:
        if r.get("time_ms", 0) > args.max_sample_ms - 500:
            slow.append(f"{r['id']}={r['time_ms']}ms")
    if slow:
        print(f"[ci-gate] slow samples          = {', '.join(slow)}")

    failed = False
    rc = 0
    if chain_pct < ABSOLUTE_FLOOR_PCT:
        print(f"[ci-gate] CATASTROPHIC: chain-completeness {chain_pct}% "
              f"< absolute floor {ABSOLUTE_FLOOR_PCT}%", file=sys.stderr)
        failed = True; rc = 1
    elif chain_pct < args.min_chain_pct:
        print(f"[ci-gate] FAIL: chain-completeness {chain_pct}% "
              f"< RC3.0 baseline {args.min_chain_pct}%", file=sys.stderr)
        failed = True; rc = 1
    if verdict_hits < args.min_verdict:
        print(f"[ci-gate] FAIL: verdict-precision {verdict_hits}/31 "
              f"< RC3.0 baseline {args.min_verdict}/31", file=sys.stderr)
        failed = True; rc = rc or 5
    if fp_iocs > args.max_fp:
        print(f"[ci-gate] FAIL: false-positive IOCs {fp_iocs} "
              f"> ceiling {args.max_fp}", file=sys.stderr)
        failed = True; rc = rc or 2
    if avg_ms > args.max_avg_ms:
        print(f"[ci-gate] FAIL: avg latency {avg_ms}ms "
              f"> RC3.0 ceiling {args.max_avg_ms}ms", file=sys.stderr)
        failed = True; rc = rc or 3

    if not failed:
        print("[ci-gate] PASS — RC3.0 Stable baseline maintained")
        return 0
    return rc


if __name__ == "__main__":
    sys.exit(main())
