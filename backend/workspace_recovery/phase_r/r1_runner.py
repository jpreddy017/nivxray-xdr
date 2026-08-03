"""
Phase R1 DCS runner — scores the Phase R malware-family corpus against
the Convergence Engine and (in strict mode) enforces fingerprint locks.

Usage
-----
    cd /app/backend && python -m workspace_recovery.phase_r.r1_runner
    cd /app/backend && python -m workspace_recovery.phase_r.r1_runner --strict

Exit codes
----------
* 0  — every sample converges canonically AND (with ``--strict``)
       every fingerprint matches the recorded value.
* 1  — one or more samples fail their expected substrings.
* 2  — (``--strict``) one or more fingerprints have drifted.
"""
from __future__ import annotations

import hashlib
import sys
from collections import defaultdict
from typing import Any

from workspace.convergence import Artifact, converge
from workspace_recovery.phase_r.r1_loader import load_samples


def _check_sample(sample: dict[str, Any]) -> tuple[bool, str]:
    result = converge(Artifact.from_input(sample["input"]))
    if not result.canonical:
        return False, f"non-canonical ({result.terminated_reason})"
    out = result.final_artifact.content
    expected = sample.get("expected") or {}
    for sub in expected.get("final_output_contains") or []:
        if sub.lower() not in out.lower():
            return False, f"missing substring: {sub!r}"
    for ioc in expected.get("iocs_contains") or []:
        if ioc.lower() not in out.lower():
            return False, f"missing IOC: {ioc!r}"
    return True, "PASS"


def _check_fingerprint(sample: dict[str, Any]) -> tuple[bool, str]:
    fp = ((sample.get("expected") or {}).get("fingerprint")) or {}
    if not fp:
        return True, "no-fingerprint"
    art = Artifact.from_input(sample["input"])
    r = converge(art)
    out_hash = hashlib.sha256(r.final_artifact.content.encode("utf-8")).hexdigest()
    if fp.get("canonical_output_sha256") != out_hash:
        return False, f"OUTPUT DRIFT: expected {fp['canonical_output_sha256'][:16]}..., got {out_hash[:16]}..."
    if fp.get("certificate_fingerprint") != r.certificate.fingerprint:
        return False, "CERTIFICATE DRIFT"
    if fp.get("expected_iterations") != r.certificate.iterations_executed:
        return False, f"ITERATIONS DRIFT: expected {fp['expected_iterations']}, got {r.certificate.iterations_executed}"
    if fp.get("expected_canonical_state") != r.certificate.canonical_state:
        return False, "CANONICAL-STATE DRIFT"
    if fp.get("expected_terminated_reason") != r.terminated_reason:
        return False, "TERMINATION DRIFT"
    return True, "fingerprint-locked"


def main(argv: list[str] | None = None) -> int:
    args = list(argv or sys.argv[1:])
    strict = "--strict" in args

    samples = load_samples()
    by_family: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for s in samples:
        by_family[s["family_id"]].append(s)

    print("=" * 82)
    print("Phase R1 · Malware-Family Corpus Run" + (" · STRICT" if strict else ""))
    print("=" * 82)

    total = 0
    passed = 0
    fp_drift: list[tuple[str, str]] = []

    for family_id in sorted(by_family):
        family_samples = by_family[family_id]
        fpass = 0
        print(f"\n[{family_id}]  {len(family_samples)} samples")
        for s in family_samples:
            total += 1
            ok, reason = _check_sample(s)
            marker = "PASS" if ok else "FAIL"
            print(f"   [{marker}]  {s['id']:<8} {s.get('variant', ''):<48} {reason}")
            if ok:
                fpass += 1
                passed += 1
            if strict:
                ok_fp, fp_msg = _check_fingerprint(s)
                if not ok_fp:
                    fp_drift.append((s["id"], fp_msg))
                    print(f"            \u21b3 {fp_msg}")
        print(f"   family-DCS: {fpass}/{len(family_samples)}")

    dcs = 100.0 * passed / max(total, 1)
    print()
    print("=" * 82)
    print(f"Phase R1 DCS = {dcs:5.1f}%   ({passed}/{total})")
    if strict:
        if fp_drift:
            print(f"FINGERPRINT DRIFT on {len(fp_drift)} sample(s):")
            for sid, msg in fp_drift:
                print(f"  \u00b7 {sid}: {msg}")
            return 2
        print(f"Fingerprints locked \u00b7 {total}/{total} byte-identical to recorded.")

    if passed != total:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
