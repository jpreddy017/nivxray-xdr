"""Phase 2 · Batch 2 · AES + Nested Chains + Performance Gates.

Locked with SOC user 2026-07-27. Success criteria:
    • 100% golden corpus pass rate
    • Deterministic replay (same output across multiple runs)
    • /workspace ↔ /auto-investigate parity
    • No fabricated plaintext when the key is not statically known
    • No recursion-limit regressions
    • Performance within: avg <100ms, p95 <500ms, max recursion depth
      ≤ MAX_STAGES, max_stages count ≤ MAX_STAGES

The suite also EMITS a performance-baseline JSON at
`/app/backend/tests/reports/phase2_batch2_perf.json` so future runs can
be compared over time.
"""
from __future__ import annotations

import json
import statistics
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from v2.semantic.ps_deobfuscate import (                                    # noqa: E402
    deobfuscate, KnownUnsupportedReason, MAX_STAGES,
)
from v2.semantic.ps_semantic import analyze                                  # noqa: E402
from tests.corpus.phase2_aes_samples import (                                # noqa: E402
    all_phase2_aes_samples, Phase2AesSample,
)
from tests.corpus.phase2_crypto_samples import all_phase2_crypto_samples     # noqa: E402


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


TARGET = "Write-Host 'Hello, from PowerShell!'"


# ── Per-sample regression ────────────────────────────────────────
@pytest.mark.parametrize("s", all_phase2_aes_samples(),
                          ids=lambda s: f"{s.category}:{s.id}")
def test_phase2_batch2_sample(s: Phase2AesSample) -> None:
    r = deobfuscate(s.cmdline)

    # 1. decode chain subset match
    actual = [st.technique for st in r.stages]
    ok, missing = _chain_contains_all(actual, s.expected_decode_chain)
    assert ok, (
        f"[{s.id}] expected chain {s.expected_decode_chain!r} not present in "
        f"{actual!r}. Missing: {missing!r}")

    # 2. final payload — must be present when statically decryptable;
    #    must be ABSENT when we should not fabricate.
    if s.expected_final_payload is None:
        assert TARGET not in r.final, (
            f"[{s.id}] target plaintext MUST NOT be fabricated when the "
            f"key is unavailable. Got final: {r.final[:200]!r}")
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
        combined = {u["reason"] for u in r.unsupported_reasons} \
                    | {st.unsupported_reason for st in r.stages
                        if st.unsupported_reason}
        assert s.expected_unsupported_reason in combined, (
            f"[{s.id}] expected unsupported_reason "
            f"{s.expected_unsupported_reason!r} not in {combined!r}")

    # 5. Evidence preservation — every stage carries input_hash, output_hash,
    # lengths, elapsed_ms.
    for st in r.stages:
        assert st.input_hash and len(st.input_hash) == 16, \
            f"[{s.id}] stage #{st.n} missing input_hash"
        assert st.output_hash and len(st.output_hash) == 16, \
            f"[{s.id}] stage #{st.n} missing output_hash"
        assert st.input_length >= 0 and st.output_length >= 0, \
            f"[{s.id}] stage #{st.n} has negative length"
        assert st.elapsed_ms >= 0, \
            f"[{s.id}] stage #{st.n} has negative elapsed_ms"


# ── Deterministic replay across the full Batch 1 + 2 corpus ──────
def test_phase2_deterministic_replay_batch1_and_batch2() -> None:
    """Every crypto sample must produce IDENTICAL stage chains + final +
    crypto_status across 3 successive runs. Any drift is a regression."""
    all_samples = list(all_phase2_crypto_samples()) + list(all_phase2_aes_samples())
    for s in all_samples:
        chains = []
        finals = []
        statuses = []
        for _ in range(3):
            r = deobfuscate(s.cmdline)
            chains.append([st.technique for st in r.stages])
            finals.append(r.final)
            statuses.append(r.crypto_status)
        assert all(c == chains[0] for c in chains), \
            f"[{s.id}] chain drift across replays: {chains}"
        assert all(f == finals[0] for f in finals), \
            f"[{s.id}] final drift across replays"
        assert all(st == statuses[0] for st in statuses), \
            f"[{s.id}] crypto_status drift across replays"


# ── Workspace ↔ Auto-Investigate parity across Batch 2 ───────────
def test_phase2_batch2_workspace_autoinvestigate_parity() -> None:
    from routers.auto_investigate import _fallback_naked_powershell as _nps
    for s in all_phase2_aes_samples():
        wrapped = _nps(s.cmdline)
        assert wrapped, f"[{s.id}] naked-PS fallback failed"
        r1 = analyze(s.cmdline).to_dict()
        r2 = analyze(wrapped[0]["command_line"]).to_dict()
        c1 = [st["technique"] for st in (r1.get("deobfuscation") or {}).get("stages") or []]
        c2 = [st["technique"] for st in (r2.get("deobfuscation") or {}).get("stages") or []]
        assert c1 == c2, (
            f"[{s.id}] chain drift workspace={c1} vs auto-investigate={c2}")


# ── Performance gates ────────────────────────────────────────────
def test_phase2_performance_gates() -> None:
    """Full performance gate suite. Records avg/p50/p95/max latency,
    max recursion depth, max stages per sample, and stores the
    baseline JSON at `tests/reports/phase2_batch2_perf.json`.
    """
    all_samples = list(all_phase2_crypto_samples()) + list(all_phase2_aes_samples())
    per_sample: dict[str, dict] = {}
    for s in all_samples:
        latencies_ms = []
        stage_counts = []
        for _ in range(11):    # 11 runs → p95 = index 10
            t0 = time.perf_counter()
            r = deobfuscate(s.cmdline)
            latencies_ms.append((time.perf_counter() - t0) * 1000.0)
            stage_counts.append(len(r.stages))
        latencies_ms.sort()
        per_sample[s.id] = {
            "avg_ms":         round(statistics.mean(latencies_ms), 3),
            "p50_ms":         round(latencies_ms[5], 3),
            "p95_ms":         round(latencies_ms[10], 3),
            "max_ms":         round(max(latencies_ms), 3),
            "stages_min":     min(stage_counts),
            "stages_max":     max(stage_counts),
        }

    # Overall gates
    overall_avg = statistics.mean(v["avg_ms"] for v in per_sample.values())
    overall_p95 = max(v["p95_ms"] for v in per_sample.values())
    overall_max_stages = max(v["stages_max"] for v in per_sample.values())

    # Persist perf baseline for trending
    reports_dir = Path(__file__).resolve().parents[0].parent / "tests" / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    (reports_dir / "phase2_batch2_perf.json").write_text(json.dumps({
        "generated_at": time.time(),
        "gates": {
            "avg_ms":            overall_avg,
            "p95_ms":            overall_p95,
            "max_stages":        overall_max_stages,
            "max_stages_limit":  MAX_STAGES,
        },
        "per_sample":            per_sample,
    }, indent=2))

    # Hard gates
    assert overall_avg  < 100, f"average decode latency {overall_avg:.1f}ms exceeds 100ms"
    assert overall_p95  < 500, f"p95 decode latency {overall_p95:.1f}ms exceeds 500ms"
    assert overall_max_stages <= MAX_STAGES, (
        f"max stages {overall_max_stages} exceeded MAX_STAGES={MAX_STAGES}")


# ── AES detection matrix — deterministic per-scenario contract ───
@pytest.mark.parametrize("sample_id,expected_status,expected_reason", [
    ("crypto_aes_cbc_static",           "fully_decrypted",     None),
    ("crypto_aes_ecb_static",           "fully_decrypted",     None),
    ("crypto_aes_cbc_missing_iv",       "encryption_detected", "unsupported_algorithm"),
    ("crypto_aes_runtime_env_key",      "encryption_detected", "environment_dependent"),
    ("crypto_aes_runtime_random_key",   "encryption_detected", "runtime_generated_key"),
    ("crypto_aes_corrupted_ct",         "partially_decrypted", "unsupported_algorithm"),
])
def test_aes_detection_matrix(sample_id: str, expected_status: str,
                                 expected_reason: str | None) -> None:
    """Every row of the acceptance matrix must produce the expected
    status + reason. This is the contract analysts rely on."""
    s = next(x for x in all_phase2_aes_samples() if x.id == sample_id)
    r = deobfuscate(s.cmdline)
    assert r.crypto_status == expected_status, (
        f"[{sample_id}] crypto_status={r.crypto_status!r} expected "
        f"{expected_status!r}")
    if expected_reason:
        combined = {u["reason"] for u in r.unsupported_reasons} \
                    | {st.unsupported_reason for st in r.stages
                        if st.unsupported_reason}
        assert expected_reason in combined, \
            f"[{sample_id}] reason {expected_reason!r} missing from {combined!r}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
