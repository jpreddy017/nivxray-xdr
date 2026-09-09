"""Deterministic test runner for Security State test suite without third-party dependencies."""
import sys
import time

# Ensure backend directory is in sys.path
import os
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from security_state.tests.test_security_state_suite import (
    test_security_state_determinism_and_replay,
    test_causal_engine_separates_correlation,
    test_trusted_capability_abuse_evaluation,
    test_attack_state_machine_advancement,
    test_reachability_and_decoupled_impact,
    test_counterfactual_and_intervention_optimization,
    test_response_safety_and_verification,
    test_security_state_ledger_cryptographic_integrity,
)

def run_all():
    tests = [
        ("Determinism & Hash Replayability", test_security_state_determinism_and_replay),
        ("Causal Separation from Correlation", test_causal_engine_separates_correlation),
        ("Trusted Capability Abuse (Dual-Use)", test_trusted_capability_abuse_evaluation),
        ("Attack State Machine Progression", test_attack_state_machine_advancement),
        ("Reachability & Decoupled Impact", test_reachability_and_decoupled_impact),
        ("Counterfactuals & Intervention Optimization", test_counterfactual_and_intervention_optimization),
        ("Response Safety Gate & Closed-Loop Verification", test_response_safety_and_verification),
        ("Security State Ledger Cryptographic Integrity", test_security_state_ledger_cryptographic_integrity),
    ]

    print("=" * 70)
    print("NivXRay Security State Core — Comprehensive Test Suite")
    print("=" * 70)

    passed = 0
    start = time.time()
    for name, test_fn in tests:
        t0 = time.time()
        try:
            test_fn()
            dt = (time.time() - t0) * 1000
            print(f"  PASS: {name:<50} ({dt:6.2f} ms)")
            passed += 1
        except Exception as e:
            dt = (time.time() - t0) * 1000
            print(f"  FAIL: {name:<50} ({dt:6.2f} ms)")
            print(f"        Error: {e}")
            import traceback
            traceback.print_exc()

    total_dt = time.time() - start
    print("=" * 70)
    print(f"Summary: {passed}/{len(tests)} tests passed in {total_dt:.3f}s")
    print("=" * 70)

    # Invoke Phase 2C Real Investigation Replay + Adversarial Suite
    from security_state.tests.phase2c_real_replay_runner import run_phase_2c_adversarial_suite
    run_phase_2c_adversarial_suite()

    # Invoke Phase 3 Persistent Security State & Ledger Suite
    from security_state.tests.phase3_persistence_runner import run_phase_3_persistence_suite
    run_phase_3_persistence_suite()

    # Invoke Phase 3B Distributed Persistence & Atomicity Challenge Suite
    from security_state.tests.phase3b_distributed_runner import run_phase_3b_distributed_suite
    run_phase_3b_distributed_suite()

    # Invoke Phase 4C Streaming Adapter & Shadow Replay Suite
    from security_state.tests.phase4c_streaming_runner import run_phase_4c_streaming_suite
    run_phase_4c_streaming_suite()

    # Invoke Phase 4C.1 Independent Adversarial Streaming Audit Suite
    from security_state.tests.phase4c1_adversarial_runner import run_phase_4c1_adversarial_suite
    run_phase_4c1_adversarial_suite()

    # Invoke Phase 5 Platform Shadow Integration & Analyst Cockpit Suite
    from security_state.tests.phase5_shadow_runner import run_phase_5_shadow_suite
    run_phase_5_shadow_suite()

    # Invoke Phase 6B Extended Causal Rule Engine & Dual-Use Behavioral Library Suite
    from security_state.tests.phase6b_causal_rules_runner import run_phase_6b_causal_rules_suite
    run_phase_6b_causal_rules_suite()

    # Invoke Phase 7 Enterprise Security Intelligence & Temporal Progression Suite
    from security_state.tests.phase7_enterprise_intelligence_runner import run_phase_7_enterprise_suite
    run_phase_7_enterprise_suite()

    # Invoke Phase 8 Dynamic Reachability & Counterfactual Simulation Suite
    from security_state.tests.phase8_counterfactual_reachability_runner import run_phase_8_counterfactual_suite
    p8_success = run_phase_8_counterfactual_suite()

    if passed != len(tests) or not p8_success:
        sys.exit(1)
    else:
        print("ALL VERIFICATION GATES PASSED DETERMINISTICALLY.")

if __name__ == '__main__':
    run_all()
