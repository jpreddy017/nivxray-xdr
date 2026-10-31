"""
M8 · Corpus Fingerprint Fields — regression tests.

Every corpus sample now carries an ``expected.fingerprint`` block
recorded by the M8 generator. These tests verify that:

  * Every sample HAS a fingerprint block.
  * The current engine reproduces each recorded fingerprint
    byte-for-byte.
  * Every fingerprint field is well-formed.
  * The DCS runner's ``--strict`` mode correctly detects induced
    drift (i.e. it doesn't silently pass).
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from workspace.convergence import Artifact, converge
from workspace_recovery.corpus_loader import load_samples


CORPUS_PATH = Path(__file__).resolve().parent.parent / "workspace_recovery" / "corpus.json"


def _samples():
    return load_samples(CORPUS_PATH)


# ─── Fingerprint field presence & shape ─────────────────────────────


@pytest.mark.parametrize("sample_id", [s["id"] for s in _samples()])
def test_every_sample_has_a_fingerprint(sample_id: str) -> None:
    sample = next(s for s in _samples() if s["id"] == sample_id)
    fp = (sample.get("expected") or {}).get("fingerprint") or {}
    assert fp, f"{sample_id}: missing expected.fingerprint block"
    for key in (
        "canonical_output_sha256",
        "certificate_fingerprint",
        "expected_iterations",
        "expected_canonical_state",
        "expected_terminated_reason",
    ):
        assert key in fp, f"{sample_id}: missing fingerprint.{key}"
    # Hash fields must be 64-hex-char SHA-256.
    assert len(fp["canonical_output_sha256"]) == 64
    assert len(fp["certificate_fingerprint"]) == 64
    assert isinstance(fp["expected_iterations"], int)
    assert isinstance(fp["expected_canonical_state"], bool)


# ─── Engine output must reproduce recorded fingerprints ─────────────


@pytest.mark.parametrize("sample_id", [s["id"] for s in _samples()])
def test_current_engine_matches_recorded_fingerprint(sample_id: str) -> None:
    sample = next(s for s in _samples() if s["id"] == sample_id)
    fp = sample["expected"]["fingerprint"]
    result = converge(Artifact.from_input(sample["input"]))

    output_hash = hashlib.sha256(
        result.final_artifact.content.encode("utf-8"),
    ).hexdigest()

    assert output_hash == fp["canonical_output_sha256"], (
        f"{sample_id} · OUTPUT DRIFT · engine changed the final artifact"
    )
    assert result.certificate.fingerprint == fp["certificate_fingerprint"], (
        f"{sample_id} · CERTIFICATE DRIFT · engine changed the certificate"
    )
    assert result.certificate.iterations_executed == fp["expected_iterations"], (
        f"{sample_id} · ITERATIONS DRIFT · engine changed iteration count"
    )
    assert result.certificate.canonical_state == fp["expected_canonical_state"]
    assert result.terminated_reason == fp["expected_terminated_reason"]


# ─── DCS runner --strict mode correctness ───────────────────────────


def test_dcs_runner_strict_mode_passes_on_untouched_engine() -> None:
    """The `--strict` mode must exit 0 when no drift is present."""
    from workspace_recovery.dcs_runner import main
    rc = main(["--strict"])
    assert rc == 0


def test_dcs_runner_strict_mode_detects_synthetic_drift(monkeypatch, capsys) -> None:
    """Simulate a regression by monkey-patching `converge` to always
    add an extra character to the output. The `--strict` mode MUST
    detect this and return exit code 2."""
    from workspace_recovery import dcs_runner
    from workspace.convergence.engine import ConvergenceResult
    from workspace.convergence.artifact import Artifact

    real_converge = dcs_runner.converge

    def broken_converge(art):
        result: ConvergenceResult = real_converge(art)
        # Mutate the final artifact — synthetic drift.
        mutated = Artifact.from_input(result.final_artifact.content + "!DRIFT!")
        return ConvergenceResult(
            final_artifact=mutated,
            iterations=result.iterations,
            certificate=result.certificate,
            terminated_reason=result.terminated_reason,
        )

    monkeypatch.setattr(dcs_runner, "converge", broken_converge)
    rc = dcs_runner.main(["--strict"])
    captured = capsys.readouterr()
    assert rc == 2, "strict mode failed to detect synthetic drift"
    assert "FINGERPRINT DRIFT DETECTED" in captured.out
