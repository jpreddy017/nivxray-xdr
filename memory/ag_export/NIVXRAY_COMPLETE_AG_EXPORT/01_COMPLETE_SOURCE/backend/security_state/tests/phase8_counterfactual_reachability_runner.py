"""Standalone test runner for NivXRay Phase 8: Dynamic Enterprise Reachability & Counterfactual Simulation Suite."""
import os
import sys
import time
import unittest
from typing import List, Tuple

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from security_state.tests.phase8_counterfactual_reachability_tests import Phase8CounterfactualReachabilityTestSuite


def run_phase_8_counterfactual_suite() -> bool:
    """Run all 12 Phase 8 acceptance gates + P8-13 Counterfactual Integrity."""
    print("=" * 90)
    print("NIVXRAY PHASE 8: ENTERPRISE REACHABILITY & COUNTERFACTUAL SIMULATION SUITE")
    print("=" * 90)

    suite = unittest.TestLoader().loadTestsFromTestCase(Phase8CounterfactualReachabilityTestSuite)
    results: List[Tuple[str, bool, float, str]] = []

    for test in suite:
        test_name = test._testMethodName
        test_desc = getattr(test, test_name).__doc__ or test_name
        test_desc = test_desc.strip().split("\n")[0]

        t0 = time.time()
        result = unittest.TestResult()
        test.run(result)
        dt_ms = (time.time() - t0) * 1000

        if result.wasSuccessful():
            print(f"  [PASS] {test_desc:<70} ({dt_ms:7.2f} ms)")
            results.append((test_desc, True, dt_ms, ""))
        else:
            err = ""
            if result.errors:
                err = result.errors[0][1]
            elif result.failures:
                err = result.failures[0][1]
            print(f"  [FAIL] {test_desc:<70} ({dt_ms:7.2f} ms)")
            print(f"         Error: {err.strip().splitlines()[-1] if err else 'Unknown error'}")
            results.append((test_desc, False, dt_ms, err))

    passed = sum(1 for _, s, _, _ in results if s)
    total = len(results)
    total_time = sum(d for _, _, d, _ in results) / 1000.0

    print("=" * 90)
    print(f"Phase 8 Summary: {passed}/{total} tests passed in {total_time:.3f}s")
    print("=" * 90)

    if passed == total:
        print("PHASE 8: ALL 13 ACCEPTANCE GATES PASSED DETERMINISTICALLY.")
        return True
    else:
        print("PHASE 8: VERIFICATION GATES FAILED.")
        return False


if __name__ == "__main__":
    success = run_phase_8_counterfactual_suite()
    sys.exit(0 if success else 1)
