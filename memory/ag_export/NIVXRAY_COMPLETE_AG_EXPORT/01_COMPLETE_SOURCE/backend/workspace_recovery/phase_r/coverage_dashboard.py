"""
Phase R1 Coverage Dashboard \u2014 3-axis KPI reporter.

Produces a customer-facing dashboard combining:

1. **Family Coverage** \u2014 per-family sample DCS + technique coverage %
   (populated by :mod:`workspace_recovery.phase_r.r1_runner`).
2. **Transformation Coverage** \u2014 percentage of the Convergence
   Engine's transformation registry that fires on at least one sample
   in the corpus. Ground truth is
   :mod:`workspace.convergence.registry`.
3. **Per-Language Technique Coverage** \u2014 aggregate technique
   coverage grouped by interpreter language (PowerShell / CMD /
   Bash / JavaScript / Generic).

The dashboard is emitted BOTH as a human-readable table (stdout) and
as a machine-readable JSON artifact
(``phase_r/coverage_dashboard.json``) so downstream trend-charting can
consume it deterministically.

Usage
-----
    cd /app/backend && python -m workspace_recovery.phase_r.coverage_dashboard
    cd /app/backend && python -m workspace_recovery.phase_r.coverage_dashboard --json
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from workspace.convergence import Artifact, converge
from workspace.convergence.registry import REGISTRY, TransformationDescriptor
from workspace_recovery.phase_r.r1_loader import load_all_families, load_samples

DASHBOARD_JSON = Path(__file__).resolve().parent / "coverage_dashboard.json"


def _sample_provenance(sample: dict) -> set[str]:
    """Return the set of transformation names that fired on ``sample``."""
    r = converge(Artifact.from_input(sample["input"]))
    fired: set[str] = set()
    for it in r.iterations:
        for pr in it.passes:
            for t in pr.transformations:
                # ``t`` looks like ``"decoder-js-atob x2"`` \u2014 keep just the name.
                fired.add(t.split(" x")[0])
    return fired


def _family_row(family: dict) -> dict:
    fid = family["family_id"]
    techs = family.get("techniques", []) or []
    universe = list(family.get("known_technique_universe") or [t["id"] for t in techs])
    samples = 0
    passed = 0
    tech_pass_count = 0
    for tech in techs:
        tsamples = tech.get("samples", []) or []
        any_pass = False
        for s in tsamples:
            samples += 1
            r = converge(Artifact.from_input(s["input"]))
            if not r.canonical:
                continue
            out = r.final_artifact.content.lower()
            exp = s.get("expected") or {}
            ok = all(sub.lower() in out for sub in (exp.get("final_output_contains") or []))
            ok = ok and all(ioc.lower() in out for ioc in (exp.get("iocs_contains") or []))
            if ok:
                passed += 1
                any_pass = True
        if any_pass:
            tech_pass_count += 1
    return {
        "family_id": fid,
        "display_name": family.get("family_display_name", fid),
        "techniques_in_corpus": len(techs),
        "known_universe": len(universe),
        "techniques_passed": tech_pass_count,
        "samples": samples,
        "samples_passed": passed,
        "sample_dcs_pct": 100.0 * passed / max(samples, 1),
        "technique_coverage_pct": 100.0 * tech_pass_count / max(len(universe), 1),
    }


def _transformation_coverage() -> tuple[list[dict], dict]:
    """Return per-transformation coverage rows and per-language aggregates.

    A transformation is counted as "covered" when it fires on at least
    one sample in the R1 corpus."""
    all_fired: set[str] = set()
    for s in load_samples():
        all_fired |= _sample_provenance(s)

    rows: list[dict] = []
    per_lang_total: dict[str, int] = defaultdict(int)
    per_lang_covered: dict[str, int] = defaultdict(int)
    per_cat_total: dict[str, int] = defaultdict(int)
    per_cat_covered: dict[str, int] = defaultdict(int)

    for xf in REGISTRY:
        covered = xf.name in all_fired
        rows.append(
            {
                "name": xf.name,
                "category": xf.category,
                "language": xf.language,
                "version": xf.version,
                "covered": covered,
                "families_declared": list(xf.families_covered),
                "techniques_declared": list(xf.techniques_covered),
            }
        )
        per_lang_total[xf.language] += 1
        per_cat_total[xf.category] += 1
        if covered:
            per_lang_covered[xf.language] += 1
            per_cat_covered[xf.category] += 1

    language_rows = [
        {
            "language": lang,
            "transformations": per_lang_total[lang],
            "covered": per_lang_covered[lang],
            "coverage_pct": 100.0 * per_lang_covered[lang] / max(per_lang_total[lang], 1),
        }
        for lang in sorted(per_lang_total)
    ]
    category_rows = [
        {
            "category": cat,
            "transformations": per_cat_total[cat],
            "covered": per_cat_covered[cat],
            "coverage_pct": 100.0 * per_cat_covered[cat] / max(per_cat_total[cat], 1),
        }
        for cat in sorted(per_cat_total)
    ]

    return rows, {
        "by_language": language_rows,
        "by_category": category_rows,
        "total_transformations": len(REGISTRY),
        "covered_transformations": sum(1 for r in rows if r["covered"]),
        "overall_coverage_pct": 100.0 * sum(1 for r in rows if r["covered"]) / max(len(REGISTRY), 1),
    }


def build_dashboard() -> dict:
    families = load_all_families()
    family_rows = [_family_row(f) for f in families]
    xf_rows, xf_agg = _transformation_coverage()

    total_samples = sum(r["samples"] for r in family_rows)
    total_passed = sum(r["samples_passed"] for r in family_rows)
    total_universe = sum(r["known_universe"] for r in family_rows)
    total_covered = sum(r["techniques_passed"] for r in family_rows)

    # Capability KPI \u2014 counts unique capability tags across the whole
    # R1 corpus. Not a coverage ratio; a raw breadth metric that grows
    # as new capabilities are exercised.
    from workspace_recovery.phase_r.capabilities import KNOWN_CAPABILITIES
    used_capabilities: set[str] = set()
    for s in load_samples():
        for c in (s.get("expected") or {}).get("capabilities") or []:
            used_capabilities.add(c)
    capability_kpi = {
        "vocabulary_size": len(KNOWN_CAPABILITIES),
        "capabilities_exercised": len(used_capabilities),
        "coverage_pct": 100.0 * len(used_capabilities) / max(len(KNOWN_CAPABILITIES), 1),
    }

    return {
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "kpi_panel": {
            "families_covered": len(family_rows),
            "capabilities_exercised": len(used_capabilities),
            "technique_coverage_pct": 100.0 * total_covered / max(total_universe, 1),
            "transformation_coverage_pct": xf_agg["overall_coverage_pct"],
            "sample_dcs_pct": 100.0 * total_passed / max(total_samples, 1),
            "regression_status": "PASS" if total_passed == total_samples else "FAIL",
            # Certification corpus status is fed by dcs_runner --strict;
            # this field is populated by ``_certification_status`` below.
            "certification_corpus_status": _certification_status(),
        },
        "capability_kpi": capability_kpi,
        "families": family_rows,
        "family_overall": {
            "families": len(family_rows),
            "samples": total_samples,
            "samples_passed": total_passed,
            "sample_dcs_pct": 100.0 * total_passed / max(total_samples, 1),
            "techniques_known": total_universe,
            "techniques_passed": total_covered,
            "technique_coverage_pct": 100.0 * total_covered / max(total_universe, 1),
        },
        "transformations": xf_rows,
        "transformation_overall": xf_agg,
    }


def _certification_status() -> str:
    """Run the M8 certification corpus strict-mode runner and return
    a short PASS/FAIL string. Kept side-effect-free (import + call) so
    it can be embedded in the dashboard artifact."""
    from workspace_recovery.dcs_runner import main as m8_main
    import io, contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        exit_code = m8_main(["--strict"])
    return "PASS" if exit_code == 0 else "FAIL"


def _print_dashboard(dash: dict) -> None:
    print("=" * 90)
    print("NivXRay Coverage Dashboard")
    print(f"generated: {dash['generated_at']}")
    print("=" * 90)

    # Top-line KPI Panel
    kp = dash["kpi_panel"]
    print("\nKPI Panel")
    print("-" * 90)
    print(f"  Families Covered            {kp['families_covered']}")
    print(f"  Capabilities Exercised      {kp['capabilities_exercised']} / {dash['capability_kpi']['vocabulary_size']}"
          f"   ({dash['capability_kpi']['coverage_pct']:.1f}%)")
    print(f"  Sample DCS                  {kp['sample_dcs_pct']:.1f}%")
    print(f"  Technique Coverage          {kp['technique_coverage_pct']:.1f}%")
    print(f"  Transformation Coverage     {kp['transformation_coverage_pct']:.1f}%")
    print(f"  R1 Regression Status        {kp['regression_status']}")
    print(f"  M8 Certification Corpus     {kp['certification_corpus_status']}")

    print("\nFamily Coverage")
    print("-" * 90)
    hdr = f"{'Family':<24}{'Techs':>7}{'Samples':>10}{'Passed':>9}{'Sample DCS':>13}{'Technique Cov':>16}"
    print(hdr)
    print("-" * 90)
    for r in dash["families"]:
        print(
            f"{r['display_name']:<24}"
            f"{r['techniques_in_corpus']:>7}"
            f"{r['samples']:>10}"
            f"{r['samples_passed']:>9}"
            f"{r['sample_dcs_pct']:>12.1f}%"
            f"{r['technique_coverage_pct']:>15.1f}%"
        )
    fo = dash["family_overall"]
    print("-" * 90)
    print(
        f"{'Overall':<24}"
        f"{'':>7}"
        f"{fo['samples']:>10}"
        f"{fo['samples_passed']:>9}"
        f"{fo['sample_dcs_pct']:>12.1f}%"
        f"{fo['technique_coverage_pct']:>15.1f}%"
    )

    print("\nTransformation Coverage \u00b7 by language")
    print("-" * 60)
    print(f"{'Language':<16}{'Total':>10}{'Covered':>10}{'Coverage':>14}")
    print("-" * 60)
    for row in dash["transformation_overall"]["by_language"]:
        print(
            f"{row['language']:<16}"
            f"{row['transformations']:>10}"
            f"{row['covered']:>10}"
            f"{row['coverage_pct']:>13.1f}%"
        )
    xo = dash["transformation_overall"]
    print("-" * 60)
    print(
        f"{'Overall':<16}"
        f"{xo['total_transformations']:>10}"
        f"{xo['covered_transformations']:>10}"
        f"{xo['overall_coverage_pct']:>13.1f}%"
    )

    print("\nTransformation Coverage \u00b7 by category")
    print("-" * 60)
    print(f"{'Category':<16}{'Total':>10}{'Covered':>10}{'Coverage':>14}")
    print("-" * 60)
    for row in dash["transformation_overall"]["by_category"]:
        print(
            f"{row['category']:<16}"
            f"{row['transformations']:>10}"
            f"{row['covered']:>10}"
            f"{row['coverage_pct']:>13.1f}%"
        )

    print("\nTransformation Coverage \u00b7 uncovered transformations")
    print("-" * 90)
    uncovered = [r for r in dash["transformations"] if not r["covered"]]
    if not uncovered:
        print("(none \u2014 every registered transformation is exercised by at least one corpus sample)")
    else:
        for r in uncovered:
            print(f"  \u00b7 {r['name']:<45}  ({r['category']:<10} \u00b7 {r['language']})")

    print()


def main(argv: list[str] | None = None) -> int:
    args = list(argv or sys.argv[1:])
    dash = build_dashboard()
    DASHBOARD_JSON.write_text(json.dumps(dash, indent=2) + "\n", encoding="utf-8")
    if "--json" in args:
        print(json.dumps(dash, indent=2))
    else:
        _print_dashboard(dash)
        print(f"Machine-readable artifact: {DASHBOARD_JSON}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
