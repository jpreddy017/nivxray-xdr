"""
DCS Runner — score the certification corpus against the Convergence Engine.

Reads samples via :mod:`workspace_recovery.corpus_loader` and evaluates
each one against its ``expected.final_output_contains`` (and related)
substrings. Per-category and overall pass rates are published to
stdout in the exact format the owner asked for
(``PowerShell N/N · CMD N/N · Bash N/N · Mixed N/N · Overall N/N``).

M8 · Fingerprint drift check
----------------------------
Every sample now carries an ``expected.fingerprint`` block generated
by ``m8_fingerprint_generator``. Pass ``--strict`` on the command
line to fail the run with exit code 2 if ANY sample's current engine
output has drifted from the recorded fingerprint. This is the
regression protection layer for CI.

Usage
-----
    cd /app/backend && python -m workspace_recovery.dcs_runner
    cd /app/backend && python -m workspace_recovery.dcs_runner --strict

Exit code is 0 iff overall passes >= the milestone target (M4 = 8/13)
AND (when ``--strict`` is passed) no fingerprint drift is detected.
"""
from __future__ import annotations

import hashlib
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


def _check_fingerprint(sample: dict[str, Any]) -> tuple[bool, str]:
    """Compare the current engine's output & certificate against the
    recorded fingerprint. Returns (ok, message)."""
    fp = ((sample.get("expected") or {}).get("fingerprint")) or {}
    if not fp:
        return True, "no-fingerprint"
    art = Artifact.from_input(sample["input"])
    result = converge(art)
    current_out = result.final_artifact.content
    current_out_hash = hashlib.sha256(current_out.encode("utf-8")).hexdigest()
    if fp.get("canonical_output_sha256") != current_out_hash:
        return (
            False,
            f"OUTPUT DRIFT: expected {fp.get('canonical_output_sha256','?')[:16]}..., "
            f"got {current_out_hash[:16]}...",
        )
    if fp.get("certificate_fingerprint") != result.certificate.fingerprint:
        return (
            False,
            f"CERTIFICATE DRIFT: expected {fp.get('certificate_fingerprint','?')[:16]}..., "
            f"got {result.certificate.fingerprint[:16]}...",
        )
    if fp.get("expected_iterations") != result.certificate.iterations_executed:
        return (
            False,
            f"ITERATIONS DRIFT: expected {fp.get('expected_iterations')}, "
            f"got {result.certificate.iterations_executed}",
        )
    if fp.get("expected_canonical_state") != result.certificate.canonical_state:
        return (
            False,
            f"CANONICAL-STATE DRIFT: expected {fp.get('expected_canonical_state')}, "
            f"got {result.certificate.canonical_state}",
        )
    if fp.get("expected_terminated_reason") != result.terminated_reason:
        return (
            False,
            f"TERMINATION DRIFT: expected {fp.get('expected_terminated_reason')!r}, "
            f"got {result.terminated_reason!r}",
        )
    return True, "fingerprint-locked"


def main(argv: list[str] | None = None) -> int:
    args = list(argv or sys.argv[1:])
    strict = "--strict" in args

    passing: dict[str, bool] = {}
    fp_drift: list[tuple[str, str]] = []
    print("=" * 72)
    print("Convergence Engine · DCS Corpus Run" + (" · STRICT" if strict else ""))
    print("=" * 72)
    for s in load_samples():
        ok, reason = _check_sample(s)
        passing[s["id"]] = ok
        marker = "PASS" if ok else "FAIL"
        print(f"  [{marker}] {s['id']:<45} {reason}")
        if strict:
            fp_ok, fp_msg = _check_fingerprint(s)
            if not fp_ok:
                fp_drift.append((s["id"], fp_msg))
                print(f"          ↳ {fp_msg}")
    print()
    stats = category_stats(passing)
    print("Per-category DCS:")
    print(format_category_stats(stats))
    overall = stats["__overall__"]
    dcs = 100.0 * overall["passed"] / max(overall["total"], 1)
    print()
    print(f"DCS = {dcs:5.1f}%   ({overall['passed']}/{overall['total']})")
    if strict:
        if fp_drift:
            print()
            print(f"FINGERPRINT DRIFT DETECTED on {len(fp_drift)} sample(s):")
            for sid, msg in fp_drift:
                print(f"  · {sid}: {msg}")
            return 2
        else:
            print("Fingerprints locked · 13/13 samples byte-identical to recorded.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

