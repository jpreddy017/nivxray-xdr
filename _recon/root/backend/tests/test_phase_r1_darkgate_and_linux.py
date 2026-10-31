"""Strict regression suite for the DarkGate + Linux-Droppers R1 families."""
from __future__ import annotations

import hashlib

import pytest

from workspace.convergence import Artifact, converge
from workspace_recovery.phase_r.r1_loader import load_all_families, load_samples


_DG = load_samples(["darkgate"])
_LD = load_samples(["linux_droppers"])
_DG_IDS = [s["id"] for s in _DG]
_LD_IDS = [s["id"] for s in _LD]


@pytest.fixture(scope="module")
def dg_map() -> dict[str, dict]:
    return {s["id"]: s for s in _DG}


@pytest.fixture(scope="module")
def ld_map() -> dict[str, dict]:
    return {s["id"]: s for s in _LD}


def test_darkgate_corpus_size_at_least_10():
    assert len(_DG) >= 10


def test_linux_droppers_corpus_size_at_least_3():
    assert len(_LD) >= 3


def test_darkgate_declares_coverage_gaps():
    """DarkGate carries AutoIT / AutoHotkey / VBScript gaps that need a
    future script-language decoder \u2014 declared honestly."""
    fam = next(f for f in load_all_families() if f["family_id"] == "darkgate")
    gaps = set(fam.get("coverage_gap_techniques") or [])
    assert {"autoit_script_extraction", "autohotkey_script_launcher", "vbscript_wrapper"} <= gaps


def _assert_sample(sample: dict):
    art = Artifact.from_input(sample["input"])
    r = converge(art)
    assert r.canonical, f"{sample['id']} did not converge canonically"
    out = r.final_artifact.content
    expected = sample.get("expected") or {}
    for sub in expected.get("final_output_contains") or []:
        assert sub.lower() in out.lower(), f"{sample['id']} missing {sub!r}"
    for ioc in expected.get("iocs_contains") or []:
        assert ioc.lower() in out.lower(), f"{sample['id']} missing IOC {ioc!r}"
    fp = expected.get("fingerprint") or {}
    assert fp, f"{sample['id']} has no fingerprint"
    out_hash = hashlib.sha256(out.encode("utf-8")).hexdigest()
    assert fp["canonical_output_sha256"] == out_hash
    assert fp["certificate_fingerprint"] == r.certificate.fingerprint
    assert fp["expected_iterations"] == r.certificate.iterations_executed
    assert fp["expected_canonical_state"] == r.certificate.canonical_state
    assert fp["expected_terminated_reason"] == r.terminated_reason


@pytest.mark.parametrize("sample_id", _DG_IDS)
def test_darkgate_sample_converges_and_locks(dg_map, sample_id):
    _assert_sample(dg_map[sample_id])


@pytest.mark.parametrize("sample_id", _LD_IDS)
def test_linux_droppers_sample_converges_and_locks(ld_map, sample_id):
    _assert_sample(ld_map[sample_id])


def test_darkgate_deterministic_repeatability():
    for s in _DG:
        r1 = converge(Artifact.from_input(s["input"]))
        r2 = converge(Artifact.from_input(s["input"]))
        assert r1.final_artifact.content == r2.final_artifact.content
        assert r1.certificate.fingerprint == r2.certificate.fingerprint


def test_linux_droppers_deterministic_repeatability():
    for s in _LD:
        r1 = converge(Artifact.from_input(s["input"]))
        r2 = converge(Artifact.from_input(s["input"]))
        assert r1.final_artifact.content == r2.final_artifact.content
        assert r1.certificate.fingerprint == r2.certificate.fingerprint


def test_transformation_coverage_is_100_percent():
    """After Phase R1 v2.2 all 24 registered transformations must be
    exercised by at least one sample in the R1 corpus."""
    from workspace_recovery.phase_r.coverage_dashboard import build_dashboard

    dash = build_dashboard()
    xo = dash["transformation_overall"]
    assert xo["overall_coverage_pct"] == 100.0, (
        f"Transformation coverage regressed to {xo['overall_coverage_pct']:.1f}% "
        f"({xo['covered_transformations']}/{xo['total_transformations']})"
    )
