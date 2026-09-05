"""Strict regression suite for SocGholish."""
from __future__ import annotations

import hashlib

import pytest

from workspace.convergence import Artifact, converge
from workspace_recovery.phase_r.r1_loader import load_all_families, load_samples


_SG = load_samples(["socgholish"])
_SG_IDS = [s["id"] for s in _SG]


@pytest.fixture(scope="module")
def sg_map() -> dict[str, dict]:
    return {s["id"]: s for s in _SG}


def test_socgholish_corpus_size_at_least_10():
    assert len(_SG) >= 10


def test_socgholish_declares_coverage_gaps():
    fam = next(f for f in load_all_families() if f["family_id"] == "socgholish")
    gaps = set(fam.get("coverage_gap_techniques") or [])
    assert {"wscript_shell_exec", "javascript_eval_chain"} <= gaps


@pytest.mark.parametrize("sample_id", _SG_IDS)
def test_socgholish_sample_converges_and_locks(sg_map, sample_id):
    s = sg_map[sample_id]
    r = converge(Artifact.from_input(s["input"]))
    assert r.canonical, f"{sample_id} non-canonical: {r.terminated_reason}"
    out = r.final_artifact.content
    expected = s.get("expected") or {}
    for sub in expected.get("final_output_contains") or []:
        assert sub.lower() in out.lower(), f"{sample_id} missing {sub!r}"
    for ioc in expected.get("iocs_contains") or []:
        assert ioc.lower() in out.lower(), f"{sample_id} missing IOC {ioc!r}"
    fp = expected.get("fingerprint") or {}
    assert fp, f"{sample_id} has no fingerprint"
    out_hash = hashlib.sha256(out.encode("utf-8")).hexdigest()
    assert fp["canonical_output_sha256"] == out_hash
    assert fp["certificate_fingerprint"] == r.certificate.fingerprint
    assert fp["expected_iterations"] == r.certificate.iterations_executed


def test_socgholish_deterministic_repeatability():
    for s in _SG:
        r1 = converge(Artifact.from_input(s["input"]))
        r2 = converge(Artifact.from_input(s["input"]))
        assert r1.final_artifact.content == r2.final_artifact.content
        assert r1.certificate.fingerprint == r2.certificate.fingerprint


def test_dashboard_kpi_panel_reports_six_family_metrics():
    """The Coverage Dashboard KPI Panel MUST expose the 7 top-line
    metrics: families, capabilities, sample DCS, technique coverage,
    transformation coverage, R1 regression status, and M8 cert corpus
    status."""
    from workspace_recovery.phase_r.coverage_dashboard import build_dashboard

    dash = build_dashboard()
    kp = dash["kpi_panel"]
    assert "families_covered" in kp
    assert "capabilities_exercised" in kp
    assert "sample_dcs_pct" in kp
    assert "technique_coverage_pct" in kp
    assert "transformation_coverage_pct" in kp
    assert "regression_status" in kp
    assert "certification_corpus_status" in kp

    # Invariants that must hold after Phase R1 v2.4:
    assert kp["families_covered"] >= 6
    assert kp["sample_dcs_pct"] == 100.0
    assert kp["transformation_coverage_pct"] == 100.0
    assert kp["regression_status"] == "PASS"
    assert kp["certification_corpus_status"] == "PASS"
