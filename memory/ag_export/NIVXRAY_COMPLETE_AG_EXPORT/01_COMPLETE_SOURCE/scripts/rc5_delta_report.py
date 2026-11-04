#!/usr/bin/env python3
"""RC5 · Phase 9 · Shadow-Run Delta Report CLI.

Generates a daily and cumulative delta report from MongoDB and prints
a human-readable summary. Suitable for cron / GitHub Actions:

    python scripts/rc5_delta_report.py --daily
    python scripts/rc5_delta_report.py --cumulative --days 30
    python scripts/rc5_delta_report.py --both

The script talks to MongoDB via `backend/deps.py` (respects `MONGO_URL`
and `DB_NAME` env vars). Read-only.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from datetime import datetime, timezone

HERE = os.path.abspath(os.path.dirname(__file__))
BACKEND = os.path.abspath(os.path.join(HERE, "..", "backend"))
sys.path.insert(0, BACKEND)

from deps import client, init_database, db  # noqa: E402  (relative-path import)
from engine.shadow import daily_report, cumulative_report  # noqa: E402


def _print_header(title: str) -> None:
    print("=" * 70)
    print(title)
    print("=" * 70)


def _print_report(rpt: dict) -> None:
    total = rpt.get("total", 0)
    print(f"Total snapshots analysed: {total}")
    if total == 0:
        print("  (no snapshots to report)")
        return
    vs = rpt.get("verdict_change_summary", {})
    print("\nVerdict changes:")
    print(f"  unchanged  = {vs.get('unchanged', 0)}")
    print(f"  upgraded   = {vs.get('upgraded', 0)}   (v1<v2 severity)")
    print(f"  downgraded = {vs.get('downgraded', 0)}   (v1>v2 severity)")

    print(f"\nFP change: {rpt.get('fp_change', 0)}")
    print(f"FN change: {rpt.get('fn_change', 0)}")

    lat = rpt.get("latency_ms", {})
    print("\nLatency (ms):")
    print(f"  RC4 p50/p95/p99 = {lat.get('rc4_p50')}/{lat.get('rc4_p95')}/{lat.get('rc4_p99')}")
    print(f"  RC5 p50/p95/p99 = {lat.get('rc5_p50')}/{lat.get('rc5_p95')}/{lat.get('rc5_p99')}")
    print(f"  RC5 p95 regression ratio vs RC4 = {lat.get('rc5_regression_ratio_p95')}")

    conf = rpt.get("confidence_medians", {})
    print("\nConfidence medians (RC5, 5 stages):")
    for k in ("decode", "semantic_reconstruction", "behavior",
              "mitre", "verdict", "weighted_overall"):
        print(f"  {k:24s} = {conf.get(k)}")

    par = rpt.get("parser", {})
    print("\nParser:")
    print(f"  warnings_total           = {par.get('warnings_total')}")
    print(f"  RC4 exceptions           = {par.get('rc4_exceptions')}")
    print(f"  RC5 exceptions           = {par.get('rc5_exceptions')}")
    print(f"  Crash delta per 1000     = {par.get('crash_delta_per_1000')}")

    mit = rpt.get("mitre", {})
    print("\nMITRE deltas (top-5 each):")
    print(f"  added   : {mit.get('added_top', [])[:5]}")
    print(f"  removed : {mit.get('removed_top', [])[:5]}")
    print(f"  kept    : {mit.get('kept_total', 0)}")

    lol = rpt.get("lolbins", {})
    print("\nLOLBIN state model vs legacy RC4 scanner:")
    print(f"  RC5 executed     = {lol.get('executed_total')}")
    print(f"  RC5 expanded     = {lol.get('expanded_total')}")
    print(f"  RC5 referenced   = {lol.get('referenced_total')}")
    print(f"  RC4 flat total   = {lol.get('rc4_flat_total')}")
    print(f"  New executed hits (in v2, absent in v1) = {lol.get('new_executed_hits_vs_rc4')}")
    print(f"  Missed hits      (in v1, absent from v2 executed) = {lol.get('missed_vs_rc4')}")

    rec = rpt.get("reconstruction", {})
    print("\nReconstruction:")
    print(f"  median nodes     = {rec.get('median_nodes')}")
    print(f"  median unresolved = {rec.get('median_unresolved')}")
    print(f"  max unresolved   = {rec.get('max_unresolved')}")

    print()


async def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--daily", action="store_true", help="daily report (default: today UTC)")
    p.add_argument("--cumulative", action="store_true", help="cumulative report")
    p.add_argument("--both", action="store_true", help="daily AND cumulative")
    p.add_argument("--day", default=None, help="YYYY-MM-DD UTC for daily report")
    p.add_argument("--days", type=int, default=30, help="cumulative window in days")
    p.add_argument("--json", action="store_true", help="emit raw JSON")
    args = p.parse_args()

    init_database()

    do_daily = args.daily or args.both or (not args.cumulative and not args.both)
    do_cumulative = args.cumulative or args.both

    reports: dict = {}
    if do_daily:
        reports["daily"] = await daily_report(db, day=args.day)
    if do_cumulative:
        reports["cumulative"] = await cumulative_report(db, since_days=args.days)

    if args.json:
        print(json.dumps(reports, default=str, indent=2))
    else:
        for kind, rpt in reports.items():
            _print_header(f"RC5 Shadow-Run {kind.upper()} Report — "
                          f"{rpt.get('scope', '?')} "
                          f"{rpt.get('day') or rpt.get('since') or ''}")
            _print_report(rpt)
    client.close()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
