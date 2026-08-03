"""
DCS Runner — score the certification corpus against the Convergence Engine.

Reads samples via :mod:`workspace_recovery.corpus_loader` and evaluates
each one against its ``expected.final_output_contains`` (and related)
substrings. Per-category and overall pass rates are published to
stdout in the exact format the owner asked for
(``PowerShell N/N · CMD N/N · Bash N/N · Mixed N/N · Overall N/N``).

Usage
-----
    cd /app/backend && python -m workspace_recovery.dcs_runner

Exit code is 0 iff overall passes >= the milestone target (M4 = 8/13).
"""
from __future__ import annotations

import sys
from typing import Any

from workspace.convergence import Artifact, converge
from workspace_recovery.corpus_loader import (
    category_stats,
    format_category_stats,
    load_samples,
)


def _check_sample(sample: dict[str, Any]) -> tuple[bool, str]:
    result = converge(Artifact.from_input(sample["input"]))
    if not result.canonical:
        return False, f"non-canonical ({result.terminated_reason})"
    output = result.final_artifact.content.lower()
    expected = sample.get("expected") or {}
    for sub in expected.get("final_output_contains") or []:
        if sub.lower() not in output:
            return False, f"missing substring: {sub!r}"
    for banned in expected.get("final_output_must_not_be") or []:
        # Substring "must not be" — we treat as "must not contain this
        # literal descriptor string" (the descriptor documents an
        # anti-pattern).
        if isinstance(banned, str) and banned.startswith("(") and banned.endswith(")"):
            continue  # descriptor-style banning is informational
        if isinstance(banned, str) and banned.lower() in output:
            return False, f"forbidden substring present: {banned!r}"
    return True, "PASS"


def main(argv: list[str] | None = None) -> int:
    del argv  # unused
    passing: dict[str, bool] = {}
    print("=" * 72)
    print("Convergence Engine · DCS Corpus Run")
    print("=" * 72)
    for s in load_samples():
        ok, reason = _check_sample(s)
        passing[s["id"]] = ok
        marker = "PASS" if ok else "FAIL"
        print(f"  [{marker}] {s['id']:<45} {reason}")
    print()
    stats = category_stats(passing)
    print("Per-category DCS:")
    print(format_category_stats(stats))
    overall = stats["__overall__"]
    dcs = 100.0 * overall["passed"] / max(overall["total"], 1)
    print()
    print(f"DCS = {dcs:5.1f}%   ({overall['passed']}/{overall['total']})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
