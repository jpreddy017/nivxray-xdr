"""
M1 · Convergence Loop Framework — regression tests.

Verifies the loop's own correctness. As of M2, some passes now perform
real transformations, so the "must converge in 1 iteration" invariant
no longer holds for every sample. What still holds:

  * Every corpus sample must reach `canonical_state=YES`.
  * Every corpus sample must terminate before `max_depth`.
  * Certificates must be fingerprint-stable across repeated runs.
  * `max_depth` safeguard must trip when passes never converge (mocked).
  * The pass ORDER must be Structural → Content → Decoder → Semantic.

M2-specific transformation assertions live in
``test_structural_pass.py``.
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


def _sample_matrix() -> list[tuple[str, str]]:
    return [(s["id"], s["input"]) for s in load_samples(CORPUS_PATH)]


# ─── Loop-correctness invariants ────────────────────────────────────


@pytest.mark.parametrize("sample_id,payload", _sample_matrix())
def test_every_corpus_sample_reaches_canonical_state(sample_id: str, payload: str) -> None:
    result = converge(Artifact.from_input(payload))
    assert isinstance(result, ConvergenceResult)
    assert result.terminated_reason == "canonical_state", (
        f"{sample_id}: expected canonical_state, got {result.terminated_reason}"
    )
    assert result.canonical is True


@pytest.mark.parametrize("sample_id,payload", _sample_matrix())
def test_every_corpus_sample_terminates_before_max_depth(sample_id: str, payload: str) -> None:
    result = converge(Artifact.from_input(payload))
    assert result.certificate.max_depth_reached is False
    assert 1 <= result.certificate.iterations_executed < MAX_ITERATION_DEPTH


def test_certificate_fingerprint_repeatable() -> None:
    """Certificate must be hash-stable across repeated runs (M7 gate)."""
    payload = "Write-Host \"tweet, tweet!\""
    art = Artifact.from_input(payload, interpreter="powershell")
    fingerprints = {converge(art).certificate.fingerprint for _ in range(3)}
    assert len(fingerprints) == 1, f"Non-deterministic certificate: {fingerprints}"


def test_certificate_fingerprint_repeatable_after_transformation() -> None:
    """S04-style input triggers structural folds — must remain deterministic."""
    payload = "$a='ht'+'tp'+'://ex'+'ample.com/x'"
    art = Artifact.from_input(payload)
    fingerprints = {converge(art).certificate.fingerprint for _ in range(3)}
    assert len(fingerprints) == 1


def test_certificate_json_serializable() -> None:
    result = converge(Artifact.from_input("noop"))
    d = result.certificate.to_dict()
    assert d["engine_version"].startswith("M")
    assert d["canonical_state"] is True
    assert d["ready_for_behavioral_analysis"] is True
    import json
    reparsed = json.loads(result.certificate.to_json())
    assert reparsed["final_artifact_hash_sha256"] == d["final_artifact_hash_sha256"]


# ─── max_depth safeguard ────────────────────────────────────────────


def test_max_depth_safeguard(monkeypatch: pytest.MonkeyPatch) -> None:
    """A pass that always mutates content must trip the safeguard."""
    calls = {"n": 0}

    def churning_run(artifact: Artifact) -> tuple[Artifact, PassRecord]:
        calls["n"] += 1
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


def test_rejects_non_artifact_input() -> None:
    with pytest.raises(TypeError):
        converge("raw string")  # type: ignore[arg-type]


def test_rejects_max_depth_less_than_one() -> None:
    with pytest.raises(ValueError):
        converge(Artifact.from_input("x"), max_depth=0)


# ─── Iteration-record shape ─────────────────────────────────────────


def test_iteration_record_shape() -> None:
    result = converge(Artifact.from_input("hello"))
    assert len(result.iterations) >= 1
    it = result.iterations[0]
    assert it.iteration == 1
    # Canonical pass order MUST be enforced.
    assert [p.name for p in it.passes] == ["structural", "content", "decoder", "semantic"]
    assert it.content_hash_before == it.content_hash_after  # "hello" has nothing to fold


def test_final_iteration_is_a_no_op() -> None:
    """The last iteration of any convergence run is always a no-op —
    that is the exit condition."""
    result = converge(Artifact.from_input("$a='foo'+'bar'"))
    last = result.iterations[-1]
    assert last.any_change is False
    assert last.content_hash_before == last.content_hash_after


# ─── Zero-regression floor for M1/M2 idempotent samples ─────────────


_UNCHANGED_SAMPLES = [
    # Samples the current pipeline (M1–M5) intentionally does NOT
    # transform. As of M9, S02 was repaired and now decodes correctly.
    "S07_rc4_openssl",
    "S08_unicode_obfuscation",
    "S10_bash_with_powershell_comment",
    "S012_plaintext_anchor",
]


@pytest.mark.parametrize("sample_id", _UNCHANGED_SAMPLES)
def test_no_regression_on_unchanged_samples(sample_id: str) -> None:
    """These samples MUST remain byte-identical through the current
    pipeline. Every one contains encoded payloads, interpolated
    strings, or non-PowerShell text no pass is allowed to touch."""
    payload = next(s["input"] for s in load_samples(CORPUS_PATH) if s["id"] == sample_id)
    art = Artifact.from_input(payload)
    result = converge(art)
    assert result.final_artifact.content == payload, (
        f"{sample_id}: pipeline modified an encoded/interpolated payload"
    )
    assert result.certificate.structural_changes == 0
    assert result.certificate.content_changes == 0
    assert result.certificate.decoder_changes == 0
    assert result.certificate.semantic_changes == 0
