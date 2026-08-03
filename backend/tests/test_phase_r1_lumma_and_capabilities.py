"""
Phase R1 \u00b7 Lumma Stealer + capability-vocabulary governance tests.
"""
from __future__ import annotations

import hashlib

import pytest

from workspace.convergence import Artifact, converge
from workspace_recovery.phase_r.capabilities import KNOWN_CAPABILITIES
from workspace_recovery.phase_r.r1_loader import load_all_families, load_samples


_LU = load_samples(["lumma_stealer"])
_LU_IDS = [s["id"] for s in _LU]
_ALL = load_samples()


@pytest.fixture(scope="module")
def lu_map() -> dict[str, dict]:
    return {s["id"]: s for s in _LU}


def test_lumma_corpus_size_at_least_10():
    assert len(_LU) >= 10


def test_lumma_declares_coverage_gaps():
    fam = next(f for f in load_all_families() if f["family_id"] == "lumma_stealer")
    gaps = set(fam.get("coverage_gap_techniques") or [])
    assert {"native_exe_unpacking", "lumma_rc4_string_decrypt"} <= gaps


@pytest.mark.parametrize("sample_id", _LU_IDS)
def test_lumma_sample_converges_and_locks(lu_map, sample_id):
    s = lu_map[sample_id]
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
    assert fp["expected_canonical_state"] == r.certificate.canonical_state
    assert fp["expected_terminated_reason"] == r.terminated_reason


def test_lumma_deterministic_repeatability():
    for s in _LU:
        r1 = converge(Artifact.from_input(s["input"]))
        r2 = converge(Artifact.from_input(s["input"]))
        assert r1.final_artifact.content == r2.final_artifact.content
        assert r1.certificate.fingerprint == r2.certificate.fingerprint


# ---------- Capability-vocabulary governance -------------------------------


def test_every_r1_sample_carries_capabilities():
    """Every R1 sample MUST carry ``expected.capabilities`` \u2014 the
    metadata that seeds the future Malware Capability Registry."""
    missing = []
    for s in _ALL:
        caps = (s.get("expected") or {}).get("capabilities")
        if not caps:
            missing.append(s["id"])
    assert not missing, f"Samples missing capabilities: {missing}"


def test_every_r1_capability_is_from_known_vocabulary():
    """Prevent capability-tag typos from silently entering the corpus."""
    offenders: list[tuple[str, str]] = []
    for s in _ALL:
        caps = (s.get("expected") or {}).get("capabilities") or []
        for c in caps:
            if c not in KNOWN_CAPABILITIES:
                offenders.append((s["id"], c))
    assert not offenders, (
        f"Unknown capabilities detected: {offenders}. "
        f"Either add them to KNOWN_CAPABILITIES or correct the typo."
    )


def test_capability_vocabulary_is_used():
    """Every capability declared in the vocabulary MUST be used by at
    least one sample \u2014 otherwise the vocabulary is stale. If a
    capability is aspirational (added in anticipation of a future
    family), it can be excluded from this test explicitly."""
    used: set[str] = set()
    for s in _ALL:
        for c in (s.get("expected") or {}).get("capabilities") or []:
            used.add(c)
    unused = KNOWN_CAPABILITIES - used
    assert not unused, (
        f"KNOWN_CAPABILITIES contains stale entries not used by any sample: "
        f"{sorted(unused)}"
    )
