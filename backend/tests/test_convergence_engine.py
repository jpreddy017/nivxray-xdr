"""
M1 · Convergence Loop Framework — regression tests.

Verifies ONLY the loop's own correctness. Transformation passes are
strict no-ops at M1, so:

  * Every corpus sample must converge in exactly 1 iteration.
  * The final artifact hash must equal the initial artifact hash.
  * `canonical_state` must be True on every sample.
  * The certificate must be fingerprint-stable across repeated runs
    (spec §"Convergence Certificate hash-stable across 3 repeated runs").
  * max_depth safeguard must trip when passes never converge (mocked).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from workspace.convergence import (
    MAX_ITERATION_DEPTH,
    Artifact,
    ConvergenceResult,
    converge,
)
from workspace.convergence import engine as engine_mod
from workspace.convergence.provenance import PassRecord
from workspace_recovery.corpus_loader import load_samples


CORPUS_PATH = Path(__file__).resolve().parent.parent / "workspace_recovery" / "corpus.json"


# ─── Loop-correctness invariants (transformation-free) ──────────────


def _sample_matrix() -> list[tuple[str, str]]:
    return [(s["id"], s["input"]) for s in load_samples(CORPUS_PATH)]


@pytest.mark.parametrize("sample_id,payload", _sample_matrix())
def test_m1_converges_in_one_iteration(sample_id: str, payload: str) -> None:
    art = Artifact.from_input(payload)
    result = converge(art)

    assert isinstance(result, ConvergenceResult)
    assert result.terminated_reason == "canonical_state", (
        f"{sample_id}: expected canonical_state, got {result.terminated_reason}"
    )
    assert result.canonical is True
    assert result.certificate.iterations_executed == 1, (
        f"{sample_id}: M1 no-ops must converge in exactly 1 iteration"
    )
    # Content must be untouched under M1.
    assert result.final_artifact.content == payload
    # Zero changes on every axis.
    assert result.certificate.structural_changes == 0
    assert result.certificate.content_changes == 0
    assert result.certificate.decoder_changes == 0
    assert result.certificate.semantic_changes == 0


@pytest.mark.parametrize("sample_id,payload", _sample_matrix())
def test_m1_hash_stable(sample_id: str, payload: str) -> None:
    art = Artifact.from_input(payload)
    result = converge(art)
    assert result.certificate.initial_artifact_hash_sha256 == art.content_hash
    assert result.certificate.final_artifact_hash_sha256 == art.content_hash


def test_m1_certificate_fingerprint_repeatable() -> None:
    """Spec §M7 requires the certificate be hash-stable across 3 runs."""
    payload = "Write-Host \"tweet, tweet!\""
    art = Artifact.from_input(payload, interpreter="powershell")
    fingerprints = {converge(art).certificate.fingerprint for _ in range(3)}
    assert len(fingerprints) == 1, f"Non-deterministic certificate: {fingerprints}"


def test_m1_certificate_json_serializable() -> None:
    result = converge(Artifact.from_input("noop"))
    d = result.certificate.to_dict()
    assert d["engine_version"].startswith("M1")
    assert d["canonical_state"] is True
    assert d["ready_for_behavioral_analysis"] is True
    # Round-trip through JSON.
    import json
    reparsed = json.loads(result.certificate.to_json())
    assert reparsed["final_artifact_hash_sha256"] == art_hash("noop")


def art_hash(s: str) -> str:
    import hashlib
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# ─── max_depth safeguard (uses monkey-patched churning pass) ─────────


def test_m1_max_depth_safeguard(monkeypatch: pytest.MonkeyPatch) -> None:
    """A pass that always mutates content must trip the max-depth
    safeguard, and the certificate must clearly report the trip."""
    calls = {"n": 0}

    def churning_run(artifact: Artifact) -> tuple[Artifact, PassRecord]:
        calls["n"] += 1
        # Append a marker so the content hash keeps changing forever.
        mutated = artifact.replace(content=artifact.content + "X")
        return mutated, PassRecord(
            name="structural",
            changed=True,
            transformations=("mock-churn",),
        )

    monkeypatch.setattr(
        engine_mod,
        "_PASS_PIPELINE",
        (("structural", churning_run),),
    )

    result = converge(Artifact.from_input("seed"))

    assert result.terminated_reason == "max_depth"
    assert result.canonical is False
    assert result.certificate.max_depth_reached is True
    assert result.certificate.iterations_executed == MAX_ITERATION_DEPTH
    assert calls["n"] == MAX_ITERATION_DEPTH


def test_m1_rejects_non_artifact_input() -> None:
    with pytest.raises(TypeError):
        converge("raw string")  # type: ignore[arg-type]


def test_m1_rejects_max_depth_less_than_one() -> None:
    with pytest.raises(ValueError):
        converge(Artifact.from_input("x"), max_depth=0)


# ─── Iteration-record shape (protects downstream consumers) ──────────


def test_m1_iteration_record_shape() -> None:
    result = converge(Artifact.from_input("hello"))
    assert len(result.iterations) == 1
    it = result.iterations[0]
    assert it.iteration == 1
    assert [p.name for p in it.passes] == ["structural", "content", "decoder", "semantic"]
    for p in it.passes:
        assert p.changed is False
        assert p.transformations == ()
    assert it.any_change is False
    assert it.content_hash_before == it.content_hash_after
