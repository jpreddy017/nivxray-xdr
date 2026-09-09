"""Phase 3 · Batch 1 · Multi-Stage Execution Regression Suite.

Locked with SOC user 2026-07-27. Enforces Cluster E + F acceptance
criteria:
    • Nested IEX (2-5 levels) fully peeled unless a boundary is hit.
    • ScriptBlock::Create literal resolved; dynamic argument surfaced
      as `dynamic_execution` boundary WITHOUT fabricating output.
    • Invoke-Command -ScriptBlock literal peeled.
    • Reflection / AppDomain / Activator classified as reflection
      boundary — NEVER loaded.
    • Workspace ↔ Auto-Investigate parity holds.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from v2.semantic.ps_deobfuscate import deobfuscate                          # noqa: E402
from v2.semantic.ps_semantic import analyze                                  # noqa: E402
from tests.corpus.phase3_exec_samples import (                               # noqa: E402
    all_phase3_exec_samples, Phase3ExecSample,
)


TARGET = "Write-Host 'Hello, from PowerShell!'"


def _chain_contains_all(actual: list[str], expected: list[str]) -> tuple[bool, list[str]]:
    i, missing = 0, []
    for want in expected:
        while i < len(actual) and not actual[i].startswith(want):
            i += 1
        if i >= len(actual):
            missing.append(want)
        else:
            i += 1
    return (not missing), missing


# ── Per-sample regression ────────────────────────────────────────
@pytest.mark.parametrize("s", all_phase3_exec_samples(),
                          ids=lambda s: f"{s.category}:{s.id}")
def test_phase3_batch1_sample(s: Phase3ExecSample) -> None:
    r = deobfuscate(s.cmdline)

    # 1. decode chain subset match
    actual = [st.technique for st in r.stages]
    ok, missing = _chain_contains_all(actual, s.expected_decode_chain)
    assert ok, (
        f"[{s.id}] expected chain {s.expected_decode_chain!r} not present in "
        f"{actual!r}. Missing: {missing!r}")

    # 2. final payload — present when statically decodable, ABSENT when
    #    the branch stops at a dynamic / reflection boundary.
    if s.expected_final_payload is None:
        assert TARGET not in r.final, (
            f"[{s.id}] target plaintext MUST NOT be fabricated at a "
            f"dynamic / reflection boundary. Got final: {r.final[:200]!r}")
    else:
        assert s.expected_final_payload.lower() in r.final.lower(), (
            f"[{s.id}] expected substring {s.expected_final_payload!r} "
            f"not found in final={r.final[:250]!r}")

    # 3. crypto_status
    assert r.crypto_status == s.expected_crypto_status, (
        f"[{s.id}] crypto_status={r.crypto_status!r} expected "
        f"{s.expected_crypto_status!r}")

    # 4. unsupported_reason
    if s.expected_unsupported_reason:
        combined = {u["reason"] for u in r.unsupported_reasons} \
                    | {st.unsupported_reason for st in r.stages
                        if st.unsupported_reason}
        assert s.expected_unsupported_reason in combined, (
            f"[{s.id}] expected unsupported_reason "
            f"{s.expected_unsupported_reason!r} not in {combined!r}")

    # 5. evidence preservation (Batch-2 contract still holds)
    for st in r.stages:
        assert st.input_hash and st.output_hash is not None, \
            f"[{s.id}] stage #{st.n} missing input/output hashes"

    # 6. boundary — when expected
    if s.expected_boundary:
        assert r.boundary_op and s.expected_boundary.lower() in r.boundary_op.lower(), (
            f"[{s.id}] expected boundary containing {s.expected_boundary!r}, "
            f"got {r.boundary_op!r}")


# ── Workspace ↔ Auto-Investigate parity ──────────────────────────
def test_phase3_batch1_parity() -> None:
    from routers.auto_investigate import _fallback_naked_powershell as _nps
    for s in all_phase3_exec_samples():
        wrapped = _nps(s.cmdline)
        # Some samples are short — the naked-PS fallback has a min-length
        # gate. Skip parity for those; the /decode/smart path still works.
        if not wrapped:
            continue
        r1 = analyze(s.cmdline).to_dict()
        r2 = analyze(wrapped[0]["command_line"]).to_dict()
        c1 = [st["technique"] for st in (r1.get("deobfuscation") or {}).get("stages") or []]
        c2 = [st["technique"] for st in (r2.get("deobfuscation") or {}).get("stages") or []]
        assert c1 == c2, (
            f"[{s.id}] chain drift workspace={c1} vs auto-investigate={c2}")


# ── Deterministic replay across all Phase 3 samples ──────────────
def test_phase3_batch1_deterministic_replay() -> None:
    for s in all_phase3_exec_samples():
        chains = []
        finals = []
        for _ in range(3):
            r = deobfuscate(s.cmdline)
            chains.append([st.technique for st in r.stages])
            finals.append(r.final)
        assert all(c == chains[0] for c in chains), \
            f"[{s.id}] chain drift across replays: {chains}"
        assert all(f == finals[0] for f in finals), \
            f"[{s.id}] final drift across replays"


# ── Invariant: Reflection is NEVER loaded ────────────────────────
def test_phase3_reflection_never_loaded() -> None:
    """No matter what the sample looks like, the deobfuscator must
    NEVER call any assembly-loading primitive at runtime. We prove
    this by static grep — the resolver's implementation must only
    emit metadata."""
    src = (Path(__file__).resolve().parents[1] / "v2" / "semantic"
           / "ps_deobfuscate.py").read_text()
    # Absolute prohibitions in the deobfuscator module.
    for tok in ("clr.AddReference", "importlib.import_module",
                 "System.Reflection.Assembly.Load", "load_source"):
        assert tok not in src, \
            f"Reflection-invariant violated: `{tok}` present in ps_deobfuscate.py"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
