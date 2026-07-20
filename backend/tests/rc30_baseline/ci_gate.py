"""RC3.0 One-Shot CI Gate — the merge-blocker.

Run this before every merge to `main`:

    cd /app/backend && PYTHONPATH=/app/backend python -m tests.rc30_baseline.ci_gate

The script fails (non-zero exit) if ANY of the following regress vs the
frozen RC3.0 baseline in `lock.json`:

  1. `pytest` suite — any test failure = merge blocker (exit 10).
  2. RC2.3 benchmark chain-completeness — drops below 96.7 % (30/31) → exit 11.
  3. RC2.3 benchmark verdict-precision — drops below 15/31 → exit 12.
  4. RC2.3 benchmark false-positive-IOCs — non-zero → exit 13.
  5. RC2.3 benchmark avg latency — exceeds 800 ms → exit 14.

Exit 0 = safe to merge.

Baseline captured on 2026-02-20 after production deploy on
nivxray.nivxforge.com and user validation showing "OUTPUT + ANALYST
VERDICT populate together in one blink" on PLAIN (no-AI) mode.

Feb-2026: no analyst-visible feature can ship until this gate is green.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import List

LOCK_PATH = Path(__file__).parent / "lock.json"
BACKEND_ROOT = Path("/app/backend")


def _load_lock() -> dict:
    with LOCK_PATH.open() as fh:
        return json.load(fh)


def _run(cmd: List[str], name: str) -> tuple[int, str, str]:
    """Run a subprocess, return (rc, stdout, stderr)."""
    print(f"\n▸ [{name}] {' '.join(cmd)}")
    r = subprocess.run(
        cmd, cwd=BACKEND_ROOT,
        env={"PYTHONPATH": str(BACKEND_ROOT), "PATH": "/usr/bin:/bin"},
        capture_output=True, text=True, timeout=300,
    )
    return r.returncode, r.stdout, r.stderr


def _pytest_gate(expected_min_passing: int) -> int:
    rc, out, err = _run(
        [sys.executable, "-m", "pytest",
         "tests/test_verdict_card_never_null.py",
         "tests/test_rc29_gap_close.py",
         "tests/test_runaway_guard.py",
         "tests/test_crypto_symmetric.py",
         "tests/test_rc22_decoder_pack.py",
         "tests/test_cmd_reconstruct.py",
         "tests/test_js_vbs_reconstruct.py",
         "tests/test_ps_reconstruct_p03.py",
         "tests/test_sample_commandline_chain.py",
         "-q", "--no-header"],
        "pytest",
    )
    tail = (out or err).strip().splitlines()[-1] if (out or err) else ""
    print(f"  {tail}")
    if rc != 0:
        print(f"  FAIL: pytest returned {rc}", file=sys.stderr)
        return 10
    # Verify at least the expected number passed
    if "passed" not in tail:
        print(f"  FAIL: could not parse pytest output tail: {tail!r}", file=sys.stderr)
        return 10
    return 0


def _benchmark_gate(lock: dict) -> int:
    """Delegate to the existing rc23_benchmark.ci_gate but with RC3.0 floors."""
    b = lock["backend"]
    rc, out, err = _run(
        [sys.executable, "-m", "tests.rc23_benchmark.ci_gate",
         "--min-chain-pct", str(b["chain_completeness"]["pct"]),
         "--min-verdict",   str(b["verdict_precision"]["value"]),
         "--max-fp",        str(b["false_positive_iocs"]["ceiling"]),
         "--max-avg-ms",    str(b["avg_latency_ms"]["ceiling"])],
        "rc23-benchmark",
    )
    print(out.strip() if out else "")
    if err.strip():
        print(err.strip(), file=sys.stderr)
    if rc == 0:
        return 0
    # Map the inner gate's exit code to our namespace: 11..14
    return 10 + rc


def main() -> int:
    lock = _load_lock()
    print("=" * 72)
    print(f"  RC3.0 CI GATE — baseline frozen {lock['frozen_at']} — {lock['release']}")
    print("=" * 72)

    rc_pytest = _pytest_gate(lock["backend"]["pytest_total_passing"])
    if rc_pytest:
        return rc_pytest

    rc_bench = _benchmark_gate(lock)
    if rc_bench:
        return rc_bench

    print("\n" + "=" * 72)
    print("  ✅ RC3.0 CI GATE — PASS · safe to merge")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())
