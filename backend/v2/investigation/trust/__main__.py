"""CLI entry point:  python -m v2.investigation.trust <corpus_dir>"""
from __future__ import annotations

import argparse
import json
import sys

from . import load_corpus, score


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="v2.investigation.trust",
                                 description="Trust Metrics harness")
    p.add_argument("corpus", help="corpus directory or single .yaml file")
    p.add_argument("--json", metavar="PATH", help="write JSON report to PATH")
    p.add_argument("--fail-under", type=float, default=None,
                    help="exit non-zero if accuracy < this fraction (0.0-1.0)")
    args = p.parse_args(argv)

    samples = load_corpus(args.corpus)
    report = score(samples)

    print(f"Trust Metrics Report · {report.total_samples} sample(s)")
    print(f"  accuracy         : {report.accuracy * 100:5.1f}%")
    print(f"  honesty          : {report.honesty * 100:5.1f}%")
    print(f"  explainability   : {report.explainability * 100:5.1f}%")
    print(f"  unknown_handling : {report.unknown_handling * 100:5.1f}%")
    print(f"  hard_failures    : {report.hard_failures}")
    print()
    for s in report.per_sample:
        badge = "PASS" if s.passed else "FAIL"
        print(f"  [{badge}] {s.sample_id}"
              f" (verdict: expected={s.verdict_expected} actual={s.verdict_actual})")
        for f in s.failures:
            print(f"         · {f}")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report.to_dict(), fh, indent=2)
        print(f"\nreport written to {args.json}")

    if args.fail_under is not None and report.accuracy < args.fail_under:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
