"""
Phase R1 · Cobalt Strike strict regression suite.

Enforces
--------
1. Every Cobalt Strike sample converges to canonical state.
2. Every ``expected.final_output_contains`` substring is present.
3. Every ``expected.iocs_contains`` IOC appears in the canonical output.
4. Every sample's convergence output is byte-identical to the
   recorded fingerprint (``canonical_output_sha256``,
   ``certificate_fingerprint``, ``expected_iterations``,
   ``expected_canonical_state``, ``expected_terminated_reason``).

Any drift in the underlying Convergence Engine that changes a locked
sample's output will fail the corresponding parametrized test — the
same guarantee the M8 fingerprint gate provides for the certification
corpus, extended to the Phase R malware family corpus.
"""
from __future__ import annotations

import hashlib

import pytest

from workspace.convergence import Artifact, converge
from workspace_recovery.phase_r.r1_loader import load_samples


def _cs_samples() -> list[dict]:
    return [s for s in load_samples(["cobalt_strike"])]


_SAMPLES = _cs_samples()
_IDS = [s["id"] for s in _SAMPLES]


@pytest.fixture(scope="module")
def cs_sample_map() -> dict[str, dict]:
    return {s["id"]: s for s in _SAMPLES}


def test_cobalt_strike_corpus_size_at_least_30():
    """R1 · Cobalt Strike foundation must remain \u2265 30 samples."""
    assert len(_SAMPLES) >= 30, f"CS corpus shrank: only {len(_SAMPLES)} samples"


@pytest.mark.parametrize("sample_id", _IDS)
def test_cobalt_strike_sample_converges_and_matches_fingerprint(cs_sample_map, sample_id):
    sample = cs_sample_map[sample_id]
    art = Artifact.from_input(sample["input"])
    result = converge(art)

    # 1) Canonical convergence
    assert result.canonical, (
        f"{sample_id} did not reach canonical state "
        f"(terminated_reason={result.terminated_reason})"
    )

    # 2) Expected substrings
    out = result.final_artifact.content
    expected = sample.get("expected") or {}
    for sub in expected.get("final_output_contains") or []:
        assert sub.lower() in out.lower(), (
            f"{sample_id} · missing final_output_contains substring: {sub!r}\n"
            f"OUTPUT: {out[:200]}"
        )
    # 3) IOC recovery
    for ioc in expected.get("iocs_contains") or []:
        assert ioc.lower() in out.lower(), (
            f"{sample_id} · missing IOC in canonical output: {ioc!r}\n"
            f"OUTPUT: {out[:200]}"
        )

    # 4) Fingerprint lock
    fp = expected.get("fingerprint") or {}
    assert fp, f"{sample_id} has no fingerprint recorded"

    out_hash = hashlib.sha256(out.encode("utf-8")).hexdigest()
    assert fp["canonical_output_sha256"] == out_hash, (
        f"{sample_id} · canonical_output_sha256 drift · "
        f"expected {fp['canonical_output_sha256'][:16]}\u2026 got {out_hash[:16]}\u2026"
    )
    assert fp["certificate_fingerprint"] == result.certificate.fingerprint, (
        f"{sample_id} · certificate_fingerprint drift"
    )
    assert fp["expected_iterations"] == result.certificate.iterations_executed, (
        f"{sample_id} · iterations drift: expected {fp['expected_iterations']}, "
        f"got {result.certificate.iterations_executed}"
    )
    assert fp["expected_canonical_state"] == result.certificate.canonical_state
    assert fp["expected_terminated_reason"] == result.terminated_reason


@pytest.mark.parametrize("sample_id", _IDS)
def test_cobalt_strike_sample_metadata_completeness(cs_sample_map, sample_id):
    """R1 governance: every sample carries the required intelligence fields."""
    sample = cs_sample_map[sample_id]
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
    # MITRE list must be non-empty (every CS technique maps to at least one)
    assert expected["mitre_attack"], f"{sample_id} has empty mitre_attack"
    # Behaviors list must be non-empty
    assert expected["behaviors"], f"{sample_id} has empty behaviors"
    # Every ATT&CK id must match the T-prefix pattern (deterministic guard)
    for tid in expected["mitre_attack"]:
        assert tid.startswith("T") and tid[1:].split(".")[0].isdigit(), (
            f"{sample_id} malformed MITRE id: {tid}"
        )


def test_cobalt_strike_deterministic_repeatability():
    """Two consecutive runs must produce byte-identical convergence outputs
    for every Cobalt Strike sample (baseline determinism check)."""
    for sample in _SAMPLES:
        r1 = converge(Artifact.from_input(sample["input"]))
        r2 = converge(Artifact.from_input(sample["input"]))
        assert r1.final_artifact.content == r2.final_artifact.content, (
            f"{sample['id']} produced non-deterministic output"
        )
        assert r1.certificate.fingerprint == r2.certificate.fingerprint
