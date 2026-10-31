"""Test Runner for NivXRay Phase 6B: Extended Causal Rule Engine & Dual-Use Behavioral Library."""
from __future__ import annotations

import os
import sys
import time

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from security_state.tests.phase6b_causal_rules_tests import (
    test_p6b_01_lolbas_contextual_discrimination,
    test_p6b_02_kerberoasting_causal_chain,
    test_p6b_03_dcsync_replication_chain,
    test_p6b_04_multi_host_traversal_modeling,
    test_p6b_05_competing_hypotheses_rigor,
    test_p6b_06_epistemic_separation_preserved,
    test_p6b_07_evidence_provenance_unbroken,
    test_p6b_08_authoritative_pipeline_invariance,
    test_p6b_09_execution_safety_gate_intact,
    test_p6b_10_state_and_attack_advancement,
)


def run_phase_6b_causal_rules_suite():
    tests = [
        ("P6B-01: LOLBAS Contextual Discrimination (Benign Admin vs Weaponized Proxy)", test_p6b_01_lolbas_contextual_discrimination),
        ("P6B-02: Kerberoasting Deterministic Causal Chain (SPN -> TGS-REQ -> Crack)", test_p6b_02_kerberoasting_causal_chain),
        ("P6B-03: DCSync Active Directory Replication Chain (Non-DC DRSUAPI Stream)", test_p6b_03_dcsync_replication_chain),
        ("P6B-04: Multi-Host Lateral Traversal Modeling (Zero IKG Duplication)", test_p6b_04_multi_host_traversal_modeling),
        ("P6B-05: Competing Hypotheses Rigor (Legit DC-to-DC Replication Validated)", test_p6b_05_competing_hypotheses_rigor),
        ("P6B-06: 10-Term Formal Epistemic Separation Preserved (Discrete Status)", test_p6b_06_epistemic_separation_preserved),
        ("P6B-07: Unbroken Evidence Provenance DAG (Full Sensor Frame Trace)", test_p6b_07_evidence_provenance_unbroken),
        ("P6B-08: Authoritative Pipeline Invariance (Zero Verdict/Story/IKG Mutation)", test_p6b_08_authoritative_pipeline_invariance),
        ("P6B-09: Execution Safety Gate Intact (Hard-Locked Response Execution)", test_p6b_09_execution_safety_gate_intact),
        ("P6B-10: State Engine Advancement (Multi-Host Attack State Escalation)", test_p6b_10_state_and_attack_advancement),
    ]

    print("\n" + "=" * 90)
    print("NIVXRAY PHASE 6B: EXTENDED CAUSAL RULE ENGINE & DUAL-USE BEHAVIORAL LIBRARY SUITE")
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
    print(f"Phase 6B Summary: {passed}/{len(tests)} tests passed in {total_dt:.3f}s")
    print("=" * 90)

    if passed != len(tests):
        print("PHASE 6B VERIFICATION FAILED.")
        sys.exit(1)
    else:
        print("PHASE 6B: ALL 10 ACCEPTANCE GATES PASSED DETERMINISTICALLY.")


if __name__ == "__main__":
    import os
    backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    if backend_dir not in sys.path:
        sys.path.insert(0, backend_dir)
    run_phase_6b_causal_rules_suite()
