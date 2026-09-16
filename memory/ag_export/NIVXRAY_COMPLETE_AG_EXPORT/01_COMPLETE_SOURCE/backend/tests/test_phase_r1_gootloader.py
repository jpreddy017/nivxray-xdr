"""
Phase R1 · GootLoader strict regression suite.

Mirrors the Cobalt Strike gate: canonical convergence, expected
substrings, IOCs, and byte-locked fingerprint per sample; plus
technique-taxonomy governance (universe + gap declaration).
"""
from __future__ import annotations

import hashlib

import pytest

from workspace.convergence import Artifact, converge
from workspace_recovery.phase_r.r1_loader import load_all_families, load_samples


_SAMPLES = load_samples(["gootloader"])
_IDS = [s["id"] for s in _SAMPLES]


@pytest.fixture(scope="module")
def gl_sample_map() -> dict[str, dict]:
    return {s["id"]: s for s in _SAMPLES}


@pytest.fixture(scope="module")
def gl_family() -> dict:
    return next(f for f in load_all_families() if f["family_id"] == "gootloader")


def test_gootloader_corpus_size_at_least_20():
    """R1 v2.0 \u00b7 GootLoader foundation must remain \u2265 20 samples."""
    assert len(_SAMPLES) >= 20, f"GL corpus shrank: only {len(_SAMPLES)} samples"


def test_gootloader_every_sample_has_technique_id():
    for s in _SAMPLES:
        assert s.get("technique_id"), f"Sample {s['id']} missing technique_id"


def test_gootloader_technique_universe_includes_coverage_gaps(gl_family):
    """Coverage gaps MUST be declared in ``known_technique_universe`` so
    the Coverage Matrix reports them as un-covered rather than hiding
    them. This is the "honest coverage" principle: gaps are surfaced,
    not silently omitted.

    NOTE (R1 v2.1): The 3 original JavaScript gaps have been closed by
    the new JS decoder pass (``decoder-js-unicode-escape``,
    ``decoder-js-atob``, ``structural-js-split-reverse-join``). The
    ``coverage_gap_techniques`` list is now allowed to be empty, but
    every corpus technique must still be present in the declared
    universe."""
    declared = set(gl_family.get("known_technique_universe") or [])
    gaps = set(gl_family.get("coverage_gap_techniques") or [])
    in_corpus = {t["id"] for t in (gl_family.get("techniques") or [])}
    # gaps (if any) must be subset of universe
    assert gaps.issubset(declared), f"Gaps not in universe: {gaps - declared}"
    # every corpus technique must appear in universe
    assert in_corpus.issubset(declared), (
        f"Corpus techniques missing from universe: {in_corpus - declared}"
    )
    # gaps and corpus must be disjoint
    assert not (gaps & in_corpus), (
        f"Technique declared as gap AND has samples: {gaps & in_corpus}"
    )


def test_gootloader_family_has_at_least_10_techniques(gl_family):
    """R1 v2.0 GL technique bucket floor."""
    assert len(gl_family.get("techniques") or []) >= 10


@pytest.mark.parametrize("sample_id", _IDS)
def test_gootloader_sample_converges_and_matches_fingerprint(gl_sample_map, sample_id):
    sample = gl_sample_map[sample_id]
    art = Artifact.from_input(sample["input"])
    result = converge(art)

    assert result.canonical, (
        f"{sample_id} did not reach canonical state "
        f"(terminated_reason={result.terminated_reason})"
    )
    out = result.final_artifact.content
    expected = sample.get("expected") or {}
    for sub in expected.get("final_output_contains") or []:
        assert sub.lower() in out.lower(), (
            f"{sample_id} \u00b7 missing final_output_contains substring: {sub!r}\n"
            f"OUTPUT: {out[:200]}"
        )
    for ioc in expected.get("iocs_contains") or []:
        assert ioc.lower() in out.lower(), (
            f"{sample_id} \u00b7 missing IOC in canonical output: {ioc!r}\n"
            f"OUTPUT: {out[:200]}"
        )

    fp = expected.get("fingerprint") or {}
    assert fp, f"{sample_id} has no fingerprint recorded"

    out_hash = hashlib.sha256(out.encode("utf-8")).hexdigest()
    assert fp["canonical_output_sha256"] == out_hash, (
        f"{sample_id} \u00b7 canonical_output_sha256 drift \u00b7 "
        f"expected {fp['canonical_output_sha256'][:16]}\u2026 got {out_hash[:16]}\u2026"
    )
    assert fp["certificate_fingerprint"] == result.certificate.fingerprint
    assert fp["expected_iterations"] == result.certificate.iterations_executed
    assert fp["expected_canonical_state"] == result.certificate.canonical_state
    assert fp["expected_terminated_reason"] == result.terminated_reason


@pytest.mark.parametrize("sample_id", _IDS)
def test_gootloader_sample_metadata_completeness(gl_sample_map, sample_id):
    sample = gl_sample_map[sample_id]
    expected = sample.get("expected") or {}
    for required_key in (
        "interpreter",
        "final_interpreter",
        "decoder_chain",
        "final_output_contains",
        "iocs_contains",
        "mitre_attack",
        "behaviors",
        "fingerprint",
    ):
        assert required_key in expected, f"{sample_id} missing expected.{required_key}"
    assert expected["mitre_attack"], f"{sample_id} has empty mitre_attack"
    assert expected["behaviors"], f"{sample_id} has empty behaviors"
    for tid in expected["mitre_attack"]:
        assert tid.startswith("T") and tid[1:].split(".")[0].isdigit(), (
            f"{sample_id} malformed MITRE id: {tid}"
        )


def test_gootloader_deterministic_repeatability():
    for sample in _SAMPLES:
        r1 = converge(Artifact.from_input(sample["input"]))
        r2 = converge(Artifact.from_input(sample["input"]))
        assert r1.final_artifact.content == r2.final_artifact.content
        assert r1.certificate.fingerprint == r2.certificate.fingerprint
