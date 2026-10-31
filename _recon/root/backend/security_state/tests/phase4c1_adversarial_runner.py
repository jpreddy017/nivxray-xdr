"""Test Runner for NivXRay Phase 4C.1: Independent Adversarial Streaming Audit."""
from __future__ import annotations

import sys
import time

from security_state.tests.phase4c1_adversarial_tests import (
    audit_tenant_authentication_boundary,
    audit_multiprocess_persistent_dedup_race,
    audit_corpus_wide_replay_equivalence,
    audit_coalescer_pure_scheduling_boundary,
    audit_adversarial_deep_late_event_reconciliation,
    audit_dlq_replay_idempotency,
    audit_backpressure_and_bounded_memory,
    audit_feature_flag_safety_invariant,
)


def run_phase_4c1_adversarial_suite():
    tests = [
        ("Tenant Authentication Boundary Proof (Credential -> Principal -> Tenant)", audit_tenant_authentication_boundary),
        ("Multi-Process DB Concurrent Dedup Race (10 OS Processes Simultaneous)", audit_multiprocess_persistent_dedup_race),
        ("Corpus-Wide Replay Equivalence (17 Scenarios: 10 Archetypes + 7 Edge Cases)", audit_corpus_wide_replay_equivalence),
        ("Coalescer Pure Scheduling Audit (Zero Independent Detection Logic)", audit_coalescer_pure_scheduling_boundary),
        ("Adversarial Deep Late-Event Reconciliation (v1 -> v2 -> v3 -> late -> v4)", audit_adversarial_deep_late_event_reconciliation),
        ("Dead-Letter Queue (DLQ) Replay Idempotency & Remediation", audit_dlq_replay_idempotency),
        ("Backpressure & Bounded Memory Behavior (Queue Overflow Isolation)", audit_backpressure_and_bounded_memory),
        ("Feature Flag Safety Invariant (NIVX_FLAG_SECURITY_STATE=disabled)", audit_feature_flag_safety_invariant),
    ]

    print("\n" + "=" * 90)
    print("NIVXRAY PHASE 4C.1: INDEPENDENT ADVERSARIAL STREAMING AUDIT SUITE")
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
    print(f"Phase 4C.1 Audit Results: {passed}/{len(tests)} audits passed in {total_dt:.3f}s")
    print("=" * 90)

    if passed != len(tests):
        raise RuntimeError(f"Phase 4C.1 Adversarial Audit Failed: {len(tests) - passed} failures")


if __name__ == "__main__":
    run_phase_4c1_adversarial_suite()
