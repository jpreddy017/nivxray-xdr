"""Phase 3 · Batch 2 · Cluster G Regression Suite."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from v2.semantic.ps_deobfuscate import deobfuscate                          # noqa: E402
from tests.corpus.phase3_batch2_samples import (                            # noqa: E402
    all_phase3g_samples, Phase3GSample,
)


def _chain_ok(actual: list[str], expected: list[str]) -> bool:
    i = 0
    for want in expected:
        while i < len(actual) and not actual[i].startswith(want):
            i += 1
        if i >= len(actual):
            return False
        i += 1
    return True


@pytest.mark.parametrize("s", all_phase3g_samples(),
                          ids=lambda s: f"{s.category}:{s.id}")
def test_phase3_batch2_sample(s: Phase3GSample) -> None:
    r = deobfuscate(s.cmdline)
    actual = [st.technique for st in r.stages]
    assert _chain_ok(actual, s.expected_decode_chain), (
        f"[{s.id}] chain {s.expected_decode_chain!r} not in {actual!r}")

    if s.expected_final_payload is None:
        assert "Write-Host 'Hello, from PowerShell!'" not in r.final, \
            f"[{s.id}] canary plaintext must not appear"
    else:
        assert s.expected_final_payload.lower() in r.final.lower(), \
            f"[{s.id}] expected {s.expected_final_payload!r} in {r.final[:200]!r}"

    if s.expected_crypto_status:
        assert r.crypto_status == s.expected_crypto_status, \
            f"[{s.id}] crypto_status={r.crypto_status!r}"

    if s.expected_unsupported_reason:
        combined_reasons = {u["reason"] for u in r.unsupported_reasons} \
                            | {st.unsupported_reason for st in r.stages
                                if st.unsupported_reason}
        assert s.expected_unsupported_reason in combined_reasons, \
            f"[{s.id}] reason {s.expected_unsupported_reason!r} missing"

    if s.expected_unsupported_component:
        components = {u.get("component") for u in r.unsupported_reasons}
        assert s.expected_unsupported_component in components, \
            f"[{s.id}] component {s.expected_unsupported_component!r} not in {components!r}"


def test_phase3_batch2_env_var_never_substituted() -> None:
    """Environment variables MUST be surfaced, never substituted with
    real values. This is a permanent invariant."""
    import os
    fake_val = "__DEFINITELY_FAKE_ENV_VAR_VALUE_777__"
    os.environ["NVX_TEST_KEY"] = fake_val
    try:
        r = deobfuscate('$x=$env:NVX_TEST_KEY;Write-Host $x')
        assert fake_val not in r.final, \
            "env-var value MUST NEVER be substituted into the report"
        assert any(u.get("reason") == "environment_dependent"
                    for u in r.unsupported_reasons), \
            "env-var reference must be surfaced as environment_dependent"
    finally:
        os.environ.pop("NVX_TEST_KEY", None)


def test_phase3_batch2_deterministic_replay() -> None:
    for s in all_phase3g_samples():
        chains = [[st.technique for st in deobfuscate(s.cmdline).stages] for _ in range(3)]
        assert all(c == chains[0] for c in chains), \
            f"[{s.id}] chain drift across replays: {chains}"
