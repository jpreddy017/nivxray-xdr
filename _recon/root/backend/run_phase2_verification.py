"""
NivXRay XDR — Phase 2 Verification Runner.
Executes the Phase 2 test suite and outputs exact statistics and execution timings.
"""
import os
import sys
import pytest

def main():
    test_files = [
        "tests/test_phase2_telemetry_normalization.py",
        "tests/test_phase2_canonical_ir.py",
        "tests/test_phase2_translation.py",
        "tests/test_phase2_deduplication.py",
        "tests/test_phase2_validation_framework.py",
        "tests/test_phase2_lifecycle.py",
        "tests/test_phase2_engine_binding.py",
    ]

    args = ["-v", "--tb=short"] + test_files
    print("Running Phase 2 Verification Suite with args:", args)
    ret = pytest.main(args)
    print(f"\nPytest exited with code: {ret}")
    sys.exit(ret)

if __name__ == "__main__":
    main()
