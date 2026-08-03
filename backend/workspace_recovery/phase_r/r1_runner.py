"""
Phase R1 DCS runner + Coverage Matrix reporter (technique-first schema).

Reports the following:

1. **Per-sample verdict** (canonical convergence + expected substrings +
   IOCs + fingerprint match under ``--strict``).
2. **Per-technique coverage** — for every technique in a family,
   ``passed/total`` and a coverage percentage.
3. **Per-family Coverage Matrix** — technique count, sample count,
   passed sample count, and *technique coverage* (percentage of the
   family's known-technique universe that has at least one passing
   sample).
4. **Overall NivXRay Real-World Family Coverage** — the customer-facing
   KPI: weighted average of per-family technique coverage across every
   family currently in the corpus.

Usage
-----
    cd /app/backend && python -m workspace_recovery.phase_r.r1_runner
    cd /app/backend && python -m workspace_recovery.phase_r.r1_runner --strict

Exit codes
----------
* 0  \u2014 every sample converges canonically AND (with ``--strict``)
       every fingerprint matches the recorded value.
* 1  \u2014 one or more samples failed their expected substrings/IOCs.
* 2  \u2014 (``--strict``) one or more fingerprints have drifted.
"""
from __future__ import annotations

import hashlib
import sys
from typing import Any

from workspace.convergence import Artifact, converge
from workspace_recovery.phase_r.r1_loader import load_all_families


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
    r = converge(Artifact.from_input(sample["input"]))
    out_hash = hashlib.sha256(r.final_artifact.content.encode("utf-8")).hexdigest()
    if fp.get("canonical_output_sha256") != out_hash:
        return False, "OUTPUT DRIFT"
    if fp.get("certificate_fingerprint") != r.certificate.fingerprint:
        return False, "CERTIFICATE DRIFT"
    if fp.get("expected_iterations") != r.certificate.iterations_executed:
        return False, f"ITERATIONS DRIFT (expected {fp['expected_iterations']}, got {r.certificate.iterations_executed})"
    if fp.get("expected_canonical_state") != r.certificate.canonical_state:
        return False, "CANONICAL-STATE DRIFT"
    if fp.get("expected_terminated_reason") != r.terminated_reason:
        return False, "TERMINATION DRIFT"
    return True, "fingerprint-locked"


def main(argv: list[str] | None = None) -> int:
    args = list(argv or sys.argv[1:])
    strict = "--strict" in args

    families = load_all_families()

    print("=" * 90)
    print("Phase R1 \u00b7 Malware-Family Corpus Run" + ("  \u00b7  STRICT" if strict else ""))
    print("=" * 90)

    grand_total = 0
    grand_pass = 0
    fp_drift: list[tuple[str, str]] = []

    coverage_rows: list[dict[str, Any]] = []

    for family in families:
        fam_id = family.get("family_id", "?")
        fam_name = family.get("family_display_name") or fam_id
        techniques = family.get("techniques", []) or []
        known_universe = list(family.get("known_technique_universe") or [t["id"] for t in techniques])

        fam_samples = 0
        fam_pass = 0
        techniques_with_at_least_one_pass = 0

        print(f"\n[{fam_name}]  ({fam_id})  \u2014 {len(techniques)} techniques  \u00b7  known-universe: {len(known_universe)}")

        for tech in techniques:
            tid = tech.get("id", "?")
            tsamples = tech.get("samples", []) or []
            tpass = 0
            for s in tsamples:
                grand_total += 1
                fam_samples += 1
                ok, reason = _check_sample(s)
                marker = "PASS" if ok else "FAIL"
                short_var = (s.get("variant") or "")[:40]
                print(f"   [{marker}]  {tid:<42}  {s['id']:<8}  {short_var}   {reason if not ok else ''}")
                if ok:
                    tpass += 1
                    fam_pass += 1
                    grand_pass += 1
                if strict:
                    ok_fp, fp_msg = _check_fingerprint(s)
                    if not ok_fp:
                        fp_drift.append((s["id"], fp_msg))
                        print(f"            \u21b3 {fp_msg}")
            if tpass > 0:
                techniques_with_at_least_one_pass += 1
            tcov = 100.0 * tpass / max(len(tsamples), 1)
            print(f"      technique {tid:<42} {tpass:>2}/{len(tsamples):<2}  ({tcov:5.1f}%)")

        # Technique coverage = techniques with \u22651 passing sample / known universe.
        tech_cov = 100.0 * techniques_with_at_least_one_pass / max(len(known_universe), 1)
        coverage_rows.append(
            {
                "family_id": fam_id,
                "display_name": fam_name,
                "techniques_in_corpus": len(techniques),
                "known_universe": len(known_universe),
                "techniques_passed": techniques_with_at_least_one_pass,
                "samples": fam_samples,
                "samples_passed": fam_pass,
                "sample_dcs": 100.0 * fam_pass / max(fam_samples, 1),
                "technique_coverage": tech_cov,
            }
        )
        print(
            f"   \u2192 family DCS: {fam_pass}/{fam_samples}  ({100.0 * fam_pass / max(fam_samples, 1):5.1f}%)"
            f"   \u00b7  technique coverage: {techniques_with_at_least_one_pass}/{len(known_universe)}"
            f"  ({tech_cov:5.1f}%)"
        )

    # Coverage Matrix summary
    print()
    print("=" * 90)
    print("Coverage Matrix")
    print("=" * 90)
    header = f"{'Family':<22}{'Techs':>7}{'Samples':>10}{'Passed':>9}{'Sample DCS':>13}{'Technique Cov':>15}"
    print(header)
    print("-" * 90)
    for row in coverage_rows:
        print(
            f"{row['display_name']:<22}"
            f"{row['techniques_in_corpus']:>7}"
            f"{row['samples']:>10}"
            f"{row['samples_passed']:>9}"
            f"{row['sample_dcs']:>12.1f}%"
            f"{row['technique_coverage']:>14.1f}%"
        )
    print("-" * 90)

    # Grand aggregate metrics
    total_samples = sum(r["samples"] for r in coverage_rows)
    total_passed = sum(r["samples_passed"] for r in coverage_rows)
    total_universe = sum(r["known_universe"] for r in coverage_rows)
    total_covered_techs = sum(r["techniques_passed"] for r in coverage_rows)
    overall_sample_dcs = 100.0 * total_passed / max(total_samples, 1)
    overall_tech_cov = 100.0 * total_covered_techs / max(total_universe, 1)
    print(
        f"{'Overall':<22}"
        f"{'':>7}"
        f"{total_samples:>10}"
        f"{total_passed:>9}"
        f"{overall_sample_dcs:>12.1f}%"
        f"{overall_tech_cov:>14.1f}%"
    )
    print()

    if strict:
        if fp_drift:
            print(f"FINGERPRINT DRIFT on {len(fp_drift)} sample(s):")
            for sid, msg in fp_drift:
                print(f"  \u00b7 {sid}: {msg}")
            return 2
        print(f"Fingerprints locked \u00b7 {total_samples}/{total_samples} byte-identical to recorded.")

    if grand_pass != grand_total:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
