"""Governance-gated baseline refresh tool.

Regenerates `/app/backend/baselines/rc5_baseline.json` from a fresh
Golden-Corpus run. **DO NOT USE CASUALLY** — per GOVERNANCE.md §A22
this must only be invoked as part of an approved amendment.

Guardrails:
  • Requires an explicit `--i-know-what-im-doing` flag.
  • Requires an environment variable `NIVX_REBASELINE_TICKET`
    describing the governance amendment id (e.g. "AMEND-2026-03-01").
  • Prints a diff of before / after headline metrics and refuses to
    overwrite unless `--force` is also passed.

Usage:
    NIVX_REBASELINE_TICKET=AMEND-2026-03-01 \\
        python -m tests.tools.rebaseline \\
        --i-know-what-im-doing --force
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import statistics
import sys
from pathlib import Path

BASELINE_PATH = Path(__file__).resolve().parents[2] / "baselines" / "rc5_baseline.json"


def _q(values, p: float) -> float:
    if not values:
        return 0.0
    values = sorted(values)
    return values[min(len(values) - 1, int(len(values) * p))]


def _capture() -> dict:
    from engine.golden_corpus import run_corpus
    r = run_corpus()
    lat = [s.duration_ms for s in r.samples]
    sample_ids = [s.sample_id for s in r.samples]
    baseline_id = hashlib.sha256(json.dumps(sample_ids).encode()).hexdigest()[:16]
    per_sample = {
        s.sample_id: {
            "verdict": s.got_verdict,
            "passed": s.passed,
            "mitre": s.mitre_technique_ids,
            "weighted_conf": round(s.weighted_conf, 3) if s.weighted_conf else 0.0,
        }
        for s in r.samples
    }
    sample_map_hash = hashlib.sha256(
        json.dumps(per_sample, sort_keys=True).encode()
    ).hexdigest()
    return {
        "schema_version": 1,
        "captured_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "baseline_id": baseline_id,
        "sample_map_hash": sample_map_hash,
        "corpus_size": r.total,
        "golden": {
            "passed": r.passed,
            "failed": r.failed,
            "pass_rate": r.pass_rate,
            "newly_failing": list(r.newly_failing),
            "mitre_technique_count": r.mitre_technique_count,
            "mitre_technique_ids": sorted(r.mitre_technique_ids),
        },
        "category_coverage": r.category_coverage,
        "latency_ms": {
            "p50": _q(lat, 0.5),
            "p95": _q(lat, 0.95),
            "p99": _q(lat, 0.99),
            "mean": round(statistics.mean(lat), 3) if lat else 0.0,
            "max": max(lat) if lat else 0.0,
        },
        "accuracy": r.accuracy,
        "coverage": r.coverage,
        "per_sample": per_sample,
        "tolerance": {
            "latency_p50_multiplier": 1.10,
            "latency_p95_multiplier": 1.15,
            "latency_p99_multiplier": 1.20,
            "pass_rate_min_drop": 0.0,
            "accuracy_min_drop": 0.0,
        },
        "notes": "Regenerated via tests.tools.rebaseline. See governance ticket.",
    }


def _diff(before: dict, after: dict) -> list[str]:
    lines: list[str] = []
    lines.append(f"corpus_size:      {before.get('corpus_size')} → {after.get('corpus_size')}")
    lines.append(
        "pass_rate:        "
        f"{before.get('golden', {}).get('pass_rate')} → "
        f"{after.get('golden', {}).get('pass_rate')}"
    )
    for q in ("p50", "p95", "p99"):
        b = before.get("latency_ms", {}).get(q)
        a = after.get("latency_ms", {}).get(q)
        lines.append(f"latency_{q}:      {b} → {a}")
    lines.append(f"baseline_id:      {before.get('baseline_id')} → {after.get('baseline_id')}")
    lines.append(f"sample_map_hash:  {before.get('sample_map_hash', '')[:16]}… → {after.get('sample_map_hash', '')[:16]}…")
    return lines


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--i-know-what-im-doing", action="store_true")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    ticket = os.environ.get("NIVX_REBASELINE_TICKET", "").strip()
    if not ticket:
        print("ERROR: NIVX_REBASELINE_TICKET env var is required.", file=sys.stderr)
        return 2
    if not args.i_know_what_im_doing:
        print("ERROR: pass --i-know-what-im-doing to acknowledge governance.", file=sys.stderr)
        return 2

    before = {}
    if BASELINE_PATH.exists():
        with BASELINE_PATH.open() as f:
            before = json.load(f)

    after = _capture()
    after["governance_ticket"] = ticket
    if before:
        after["prev_baseline_id"] = before.get("baseline_id")

    print(f"Governance ticket: {ticket}")
    print("Diff:")
    for line in _diff(before, after):
        print(f"  {line}")

    if args.dry_run:
        print("(dry-run — no write)")
        return 0
    if BASELINE_PATH.exists() and not args.force:
        print("ERROR: baseline exists — pass --force to overwrite.", file=sys.stderr)
        return 2

    BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with BASELINE_PATH.open("w") as f:
        json.dump(after, f, indent=2)
    print(f"Wrote {BASELINE_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
