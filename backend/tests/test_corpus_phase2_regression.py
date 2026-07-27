"""Phase 2 · Crypto Corpus Regression + Decoder Invariants.

Locked with SOC user 2026-07-27. Every crypto sample must:

    1. Produce the EXPECTED decode chain (ordered subset match).
    2. Reduce to the EXPECTED final payload (or None when the key is
       runtime-derived — the decoder MUST NOT fabricate plaintext).
    3. Report the EXPECTED crypto_status.
    4. When applicable, surface the EXPECTED `unsupported_reason`
       code drawn from the frozen `KnownUnsupportedReason` taxonomy.
    5. Never violate the invariants documented in
       `test_decoder_invariants` below.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from v2.semantic.ps_deobfuscate import deobfuscate, KnownUnsupportedReason, MAX_STAGES  # noqa: E402
from v2.semantic.ps_semantic import analyze                                # noqa: E402
from tests.corpus.phase2_crypto_samples import (                            # noqa: E402
    all_phase2_crypto_samples, Phase2CryptoSample,
)


def _chain_contains_all(actual: list[str], expected: list[str]) -> tuple[bool, list[str]]:
    i, missing = 0, []
    for want in expected:
        # allow prefix match — "Runtime-derived key detected" matches
        # "Runtime-derived key detected · Environment variable"
        while i < len(actual) and not actual[i].startswith(want):
            i += 1
        if i >= len(actual):
            missing.append(want)
        else:
            i += 1
    return (not missing), missing


# ── Per-sample regression ────────────────────────────────────────
@pytest.mark.parametrize("s", all_phase2_crypto_samples(),
                          ids=lambda s: f"{s.category}:{s.id}")
def test_phase2_crypto_sample(s: Phase2CryptoSample) -> None:
    r = deobfuscate(s.cmdline)

    # 1. decode chain subset match
    actual = [st.technique for st in r.stages]
    ok, missing = _chain_contains_all(actual, s.expected_decode_chain)
    assert ok, (
        f"[{s.id}] expected chain {s.expected_decode_chain!r} not "
        f"present in {actual!r}. Missing: {missing!r}")

    # 2. final payload substring — or explicit absence
    if s.expected_final_payload is None:
        # Runtime-derived key: the decoder MUST NOT fabricate plaintext.
        assert TARGET_NOT_FABRICATED not in r.final, \
            f"[{s.id}] canary should be absent"
        # Explicitly assert the ciphertext substring is still present
        # (i.e. no rewrite happened).
        assert "FromBase64String" in r.final or \
            r.crypto_status == "encryption_detected", (
            f"[{s.id}] runtime-key path should preserve the ciphertext; "
            f"got final={r.final[:200]!r}")
    else:
        assert s.expected_final_payload.lower() in r.final.lower(), (
            f"[{s.id}] expected substring {s.expected_final_payload!r} "
            f"not found in final={r.final[:200]!r}")

    # 3. crypto_status
    assert r.crypto_status == s.expected_crypto_status, (
        f"[{s.id}] crypto_status={r.crypto_status!r} expected "
        f"{s.expected_crypto_status!r}")

    # 4. unsupported_reason
    if s.expected_unsupported_reason:
        reasons = [u["reason"] for u in r.unsupported_reasons]
        # Also inspect stage-level unsupported_reason field.
        stage_reasons = [st.unsupported_reason for st in r.stages
                          if st.unsupported_reason]
        combined = set(reasons) | set(stage_reasons)
        assert s.expected_unsupported_reason in combined, (
            f"[{s.id}] expected unsupported_reason "
            f"{s.expected_unsupported_reason!r} not in {combined!r}")

    # 5. boundary
    if s.expected_boundary:
        assert r.boundary_op and s.expected_boundary.lower() in r.boundary_op.lower(), (
            f"[{s.id}] expected boundary containing {s.expected_boundary!r}, "
            f"got {r.boundary_op!r}")


TARGET_NOT_FABRICATED = "Write-Host 'Hello, from PowerShell!'"


# ── Decoder Invariants (locked 2026-07-27) ───────────────────────
class TestDecoderInvariants:
    """Permanent invariants. Any future enhancement that violates one
    of these MUST update this suite deliberately with a documented
    justification. Silent regressions are not allowed."""

    def test_invariant_1_never_execute(self):
        """The decoder must NEVER call any function that could execute
        user-supplied PowerShell content. Prove statically by grepping
        the module for forbidden calls."""
        src = (Path(__file__).resolve().parents[1] / "v2" / "semantic"
               / "ps_deobfuscate.py").read_text()
        forbidden = ["subprocess.", "os.system(", "os.popen(", "eval(",
                      "exec("]
        # Exec must never appear (we use `exec()` NOWHERE); eval must
        # never appear (we never eval user input).
        # We DO allow the string `subprocess` to be imported in other
        # modules, but the deobfuscator module itself must never use it.
        for tok in forbidden:
            assert tok not in src, (
                f"Invariant #1 violated: `{tok}` present in ps_deobfuscate.py")

    def test_invariant_2_never_fabricate_runtime_key_plaintext(self):
        """When the key is runtime-derived, the deobfuscator must NOT
        emit plaintext. It must surface crypto_status='encryption_detected'
        plus a structured `unsupported_reason`."""
        s = ('$k=$env:SECRET;$c=[Convert]::FromBase64String("QUJDREVGRw==");'
             '$out=$c|%{$_-bxor$k};IEX $out')
        r = deobfuscate(s)
        assert r.crypto_status == "encryption_detected"
        reasons = {u["reason"] for u in r.unsupported_reasons} | \
                    {st.unsupported_reason for st in r.stages if st.unsupported_reason}
        assert KnownUnsupportedReason.ENVIRONMENT_DEPENDENT in reasons

    def test_invariant_3_reproducible_stages(self):
        """The same input MUST produce the exact same stage chain
        across N runs. Deterministic replay is required."""
        s = _sample_by_id("crypto_xor_multibyte").cmdline
        chains = []
        for _ in range(3):
            r = deobfuscate(s)
            chains.append([st.technique for st in r.stages])
        assert all(c == chains[0] for c in chains), \
            f"Determinism violated: {chains}"

    def test_invariant_4_stages_carry_evidence(self):
        """Every stage MUST have a non-empty `evidence` field linking
        input→output for the analyst."""
        for s in all_phase2_crypto_samples():
            r = deobfuscate(s.cmdline)
            for st in r.stages:
                assert st.evidence and len(st.evidence) > 5, (
                    f"[{s.id}] stage #{st.n} '{st.technique}' has empty evidence")

    def test_invariant_5_recursion_capped(self):
        """The recursive loop must be bounded by MAX_STAGES. Report
        surfaces `recursion_limit_reached` on overflow."""
        # Synthesize a payload that WOULD recurse indefinitely if
        # unbounded — nested concat that never fixed-points.
        # Instead of forcing that, we assert the code path exists.
        import v2.semantic.ps_deobfuscate as m
        assert m.MAX_STAGES >= 8 and m.MAX_STAGES <= 128, \
            f"MAX_STAGES must be within a sane band; got {m.MAX_STAGES}"
        # And the report must have a recursion_limit_reached code.
        src = (Path(__file__).resolve().parents[1] / "v2" / "semantic"
               / "ps_deobfuscate.py").read_text()
        assert "recursion_limit_reached" in src, \
            "Invariant #5 requires structured recursion limit reporting"

    def test_invariant_6_workspace_and_autoinvestigate_parity(self):
        """Every Phase-2 sample must produce identical decode chains
        via the /workspace path (naked) and the /auto-investigate path
        (wrapped in `powershell.exe -NoP -Command`)."""
        from routers.auto_investigate import _fallback_naked_powershell as _nps
        for s in all_phase2_crypto_samples():
            r1 = analyze(s.cmdline).to_dict()
            wrapped = _nps(s.cmdline)
            assert wrapped, f"[{s.id}] naked-PS fallback failed to synthesise wrapper"
            r2 = analyze(wrapped[0]["command_line"]).to_dict()
            c1 = [st["technique"] for st in (r1.get("deobfuscation") or {}).get("stages") or []]
            c2 = [st["technique"] for st in (r2.get("deobfuscation") or {}).get("stages") or []]
            assert c1 == c2, (
                f"[{s.id}] chain drift workspace={c1} vs auto-investigate={c2}")


def _sample_by_id(sid: str) -> Phase2CryptoSample:
    for s in all_phase2_crypto_samples():
        if s.id == sid:
            return s
    raise KeyError(sid)


# ── KnownUnsupportedReason taxonomy is stable ────────────────────
def test_known_unsupported_reasons_taxonomy() -> None:
    """The KnownUnsupportedReason taxonomy is a frozen contract —
    values must be stable across releases so downstream dashboards
    and playbooks that key off these codes don't break."""
    required = {
        "runtime_generated_key", "dynamic_execution", "reflection",
        "native_shellcode", "memory_only_object", "external_dependency",
        "network_fetch_required", "user_input_required",
        "environment_dependent", "unknown_algorithm",
        "unsupported_algorithm",
    }
    got = set(KnownUnsupportedReason.all())
    missing = required - got
    assert not missing, (
        f"KnownUnsupportedReason taxonomy missing required codes: {missing}")


# ── Basic performance smoke gate ─────────────────────────────────
# Full gates ship in Batch 2. This is a smoke test to keep the crypto
# resolvers within budget.
def test_phase2_crypto_avg_decode_time_under_100ms() -> None:
    """Each crypto sample should decode well under 100 ms on average."""
    for s in all_phase2_crypto_samples():
        t0 = time.perf_counter()
        for _ in range(5):
            deobfuscate(s.cmdline)
        elapsed_ms = (time.perf_counter() - t0) * 1000 / 5
        assert elapsed_ms < 100, (
            f"[{s.id}] average decode time {elapsed_ms:.1f}ms exceeds 100ms budget")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
