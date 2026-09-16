"""Strict regression suite for Emotet."""
from __future__ import annotations

import hashlib

import pytest

from workspace.convergence import Artifact, converge
from workspace_recovery.phase_r.r1_loader import load_all_families, load_samples


_EM = load_samples(["emotet"])
_EM_IDS = [s["id"] for s in _EM]


@pytest.fixture(scope="module")
def em_map() -> dict[str, dict]:
    return {s["id"]: s for s in _EM}


def test_emotet_corpus_size_at_least_10():
    assert len(_EM) >= 10


def test_emotet_declares_coverage_gaps():
    fam = next(f for f in load_all_families() if f["family_id"] == "emotet")
    gaps = set(fam.get("coverage_gap_techniques") or [])
    assert {"excel4_macro_extraction", "wmic_process_create_launcher", "emotet_native_config_decrypt"} <= gaps


@pytest.mark.parametrize("sample_id", _EM_IDS)
def test_emotet_sample_converges_and_locks(em_map, sample_id):
    s = em_map[sample_id]
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


def test_emotet_deterministic_repeatability():
    for s in _EM:
        r1 = converge(Artifact.from_input(s["input"]))
        r2 = converge(Artifact.from_input(s["input"]))
        assert r1.final_artifact.content == r2.final_artifact.content
        assert r1.certificate.fingerprint == r2.certificate.fingerprint


def test_emotet_rides_on_existing_transformations_only():
    """Emotet MUST be delivered with zero new transformations \u2014
    it rides entirely on the passes already shipped (cmd-caret-strip,
    powershell-encoded-command, base64, utf-16le, alias-expand,
    variable-propagate, string-concat-fold, backtick-strip,
    frombase64string, xor-byte-array). This proves the
    cross-family amortization thesis on a 7th family."""
    from workspace.convergence.registry import REGISTRY

    all_transformation_names = {xf.name for xf in REGISTRY}
    fired: set[str] = set()
    for s in _EM:
        r = converge(Artifact.from_input(s["input"]))
        for it in r.iterations:
            for pr in it.passes:
                for t in pr.transformations:
                    fired.add(t.split(" x")[0])
    # Every transformation that fired on Emotet must be a registered one.
    orphans = fired - all_transformation_names
    assert not orphans, f"Emotet fired unregistered transformations: {orphans}"
