#!/usr/bin/env python3
"""P0.5 closure · attribute a failing file to the wave, or clear it.

Runs the SAME test file against the pre-wave tree (`b4dfc4b0`, checked out as
a git worktree at /tmp/prewave) and against HEAD. Identical outcome =
PRE_EXISTING. Worse at HEAD = NEW_REGRESSION, and it must be fixed.

    python3 scripts/p0_5_prewave_attribution.py tests/test_x.py [more...]
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

COUNTS = re.compile(r"(\d+) (passed|failed|error|errors|skipped|xfailed)")
TREES = {"prewave": Path("/tmp/prewave/backend"), "head": Path("/app/backend")}


def run(tree: Path, rel: str) -> dict:
    try:
        p = subprocess.run(
            ["python3", "-m", "pytest", rel, "-q", "--no-header", "-p",
             "no:cacheprovider", "--tb=no"],
            cwd=tree, capture_output=True, text=True, timeout=1200)
        out = p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        return {"timeout": True}
    counts: dict[str, int] = {}
    for line in out.splitlines()[-30:]:
        for n, kind in COUNTS.findall(line):
            counts[kind.rstrip("s")] = int(n)
    return counts


def main() -> int:
    out_path = Path("/app/test_reports/p0_5_prewave_attribution.json")
    results = json.loads(out_path.read_text()) if out_path.exists() else {}
    for rel in sys.argv[1:]:
        pre = run(TREES["prewave"], rel)
        head = run(TREES["head"], rel)
        bad = lambda c: c.get("failed", 0) + c.get("error", 0)
        verdict = ("PRE_EXISTING" if bad(head) <= bad(pre)
                   else "NEW_REGRESSION")
        results[rel] = {"prewave": pre, "head": head, "verdict": verdict}
        print(f"{verdict:>15}  {rel}  pre={pre} head={head}", flush=True)
        out_path.write_text(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
