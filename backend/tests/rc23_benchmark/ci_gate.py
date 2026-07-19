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


# RC2.3 Stable baseline — freeze on the day this file is committed.
BASELINE_CHAIN_PCT = 77.4
BASELINE_MAX_FP_IOCS = 0
DEFAULT_MAX_SAMPLE_MS = 8000


def main(argv: List[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="RC2.3 benchmark CI gate")
    p.add_argument("--min-chain-pct", type=float, default=BASELINE_CHAIN_PCT,
                   help=f"minimum chain_complete_pct (default={BASELINE_CHAIN_PCT})")
    p.add_argument("--max-fp", type=int, default=BASELINE_MAX_FP_IOCS,
                   help=f"maximum false-positive IOCs (default={BASELINE_MAX_FP_IOCS})")
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

    print(f"[ci-gate] chain_complete_pct    = {chain_pct}%  "
          f"(floor {args.min_chain_pct}%)")
    print(f"[ci-gate] false_positive_iocs   = {fp_iocs}     "
          f"(ceiling {args.max_fp})")
    print(f"[ci-gate] avg_time_ms           = {summary['overall']['avg_time_ms']} ms")
    print(f"[ci-gate] chain_complete        = "
          f"{summary['overall']['chain_complete']}")

    slow: List[str] = []
    for r in results:
        if r.get("time_ms", 0) > args.max_sample_ms - 500:
            slow.append(f"{r['id']}={r['time_ms']}ms")
    if slow:
        print(f"[ci-gate] slow samples          = {', '.join(slow)}")

    failed = False
    if chain_pct < args.min_chain_pct:
        print(f"[ci-gate] FAIL: chain-completeness {chain_pct}% "
              f"< baseline {args.min_chain_pct}%", file=sys.stderr)
        failed = True
        rc = 1
    if fp_iocs > args.max_fp:
        print(f"[ci-gate] FAIL: false-positive IOCs {fp_iocs} "
              f"> ceiling {args.max_fp}", file=sys.stderr)
        failed = True
        rc = 2 if not failed else rc

    if not failed:
        print("[ci-gate] PASS — RC2.3 Stable baseline maintained")
        return 0
    return locals().get("rc", 1)


if __name__ == "__main__":
    sys.exit(main())
