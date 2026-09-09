"""Test Runner for NivXRay Phase 5: Platform Shadow Integration & Analyst Cockpit."""
from __future__ import annotations

import sys
import time

from security_state.tests.phase5_shadow_tests import (
    test_p5_01_real_case_hydration,
    test_p5_02_to_04_authoritative_pipeline_unaltered,
    test_p5_05_and_06_persistence_and_ledger,
    test_p5_07_async_non_blocking,
    test_p5_08_tenant_isolation,
    test_p5_09_deterministic_replay,
    test_p5_10_and_11_provenance_and_epistemic_separation,
    test_p5_12_deterministic_counterfactuals,
    test_p5_13_non_executing_intervention_staging,
    test_p5_14_backend_ui_state_consistency,
    test_p5_15_disabled_flag_zero_work,
    test_p5_16_shadow_no_authoritative_mutation,
)


def run_phase_5_shadow_suite():
    tests = [
        ("P5-01: Real Case Telemetry -> Security State Hydration", test_p5_01_real_case_hydration),
        ("P5-02..04: Authoritative Pipeline Unegotiable Invariance (Verdict, Story, IKG)", test_p5_02_to_04_authoritative_pipeline_unaltered),
        ("P5-05..06: Persistent State Versioning & Cryptographic Ledger Integrity", test_p5_05_and_06_persistence_and_ledger),
        ("P5-07: Async / Non-Blocking Dispatch Execution (<15ms)", test_p5_07_async_non_blocking),
        ("P5-08: Multi-Tenant Case Isolation (Distinct Hashes & Ledgers)", test_p5_08_tenant_isolation),
        ("P5-09: Deterministic Replay Bit-Identical Hash Verification", test_p5_09_deterministic_replay),
        ("P5-10..11: Evidence-Level Provenance DAG & 10-Term Epistemic Vocabulary", test_p5_10_and_11_provenance_and_epistemic_separation),
        ("P5-12: Deterministic Counterfactual Parallel Projections (Worlds A..D)", test_p5_12_deterministic_counterfactuals),
        ("P5-13: Human-in-the-Loop Intervention Staging & Execute Lock Safety Gate", test_p5_13_non_executing_intervention_staging),
        ("P5-14: Backend / Cockpit UI API Contract Consistency", test_p5_14_backend_ui_state_consistency),
        ("P5-15: Disabled Feature Flag Zero Work / Zero Side-Effect Guarantee", test_p5_15_disabled_flag_zero_work),
        ("P5-16: Shadow Mode Read-Only Purity (Zero Mutation to Authoritative Data)", test_p5_16_shadow_no_authoritative_mutation),
    ]

    print("\n" + "=" * 90)
    print("NIVXRAY PHASE 5: PLATFORM SHADOW INTEGRATION & ANALYST COCKPIT SUITE")
    print("=" * 90)

    passed = 0
    t_start = time.time()

    for name, test_fn in tests:
        t0 = time.time()
        try:
            test_fn()
            dt = (time.time() - t0) * 1000.0
            print(f"  [PASS] {name:<70} ({dt:7.2f} ms)")
            passed += 1
        except Exception as e:
            dt = (time.time() - t0) * 1000.0
            print(f"  [FAIL] {name:<70} ({dt:7.2f} ms)")
            print(f"         Error: {e}")
            import traceback
            traceback.print_exc()

    total_dt = time.time() - t_start
    print("=" * 90)
    print(f"Phase 5 Results: {passed}/{len(tests)} test gates passed in {total_dt:.3f}s")
    print("=" * 90)

    if passed != len(tests):
        raise RuntimeError(f"Phase 5 Shadow Verification Failed: {len(tests) - passed} failures")


if __name__ == "__main__":
    run_phase_5_shadow_suite()
