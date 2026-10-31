"""
NivXRay XDR — Phase 2.1 Adversarial Foundation Audit Runner.
Executes:
1. NivXRay Existing Regression Suite (22 detections, 5 correlation scenarios, Sigma, ICE, IUE, Decoder, Security State)
2. Phase 2 Foundation Suite (29 tests)
3. Phase 2.1 Adversarial Foundation Suite (Translation, Field Normalization, Tenant Isolation, Deduplication, License Policy, Lifecycle, Engine Binding, Scale Microbenchmark, Security State Boundary)
Produces exact counts: collected / passed / failed / errors / skipped.
"""
from __future__ import annotations

import json
import os
import sys
import time
import pytest


class AuditTestPlugin:
    def __init__(self):
        self.collected = 0
        self.passed = 0
        self.failed = 0
        self.errors = 0
        self.skipped = 0
        self.results = []

    def pytest_collection_modifyitems(self, items):
        self.collected = len(items)

    def pytest_runtest_logreport(self, report):
        if report.when == "call":
            if report.passed:
                self.passed += 1
                self.results.append({"nodeid": report.nodeid, "outcome": "passed", "duration": report.duration})
            elif report.failed:
                self.failed += 1
                self.results.append({
                    "nodeid": report.nodeid,
                    "outcome": "failed",
                    "duration": report.duration,
                    "error": str(report.longrepr),
                })
            elif report.skipped:
                self.skipped += 1
                self.results.append({"nodeid": report.nodeid, "outcome": "skipped", "duration": report.duration})
        elif report.when in ("setup", "teardown") and report.failed:
            self.errors += 1
            self.results.append({
                "nodeid": report.nodeid,
                "outcome": "error",
                "stage": report.when,
                "error": str(report.longrepr),
            })


def run_suite(title: str, test_files: list[str]) -> dict:
    print(f"\n{'='*70}\nRUNNING: {title}\n{'='*70}")
    plugin = AuditTestPlugin()
    args = ["-v", "--tb=short", "-o", "asyncio_mode=auto"] + test_files
    t0 = time.perf_counter()
    exit_code = pytest.main(args, plugins=[plugin])
    elapsed = round(time.perf_counter() - t0, 3)

    summary = {
        "title": title,
        "files": test_files,
        "collected": plugin.collected,
        "passed": plugin.passed,
        "failed": plugin.failed,
        "errors": plugin.errors,
        "skipped": plugin.skipped,
        "exit_code": int(exit_code),
        "duration_seconds": elapsed,
        "results": plugin.results,
    }
    print(f"\n--- {title} Summary ---")
    print(f"Collected: {plugin.collected} | Passed: {plugin.passed} | Failed: {plugin.failed} | Errors: {plugin.errors} | Skipped: {plugin.skipped}")
    print(f"Elapsed: {elapsed}s | Exit Code: {exit_code}")
    return summary


def main():
    # 1. Existing NivXRay Regression Suite
    existing_regression_files = [
        "tests/test_rule_detection_playbook_expansion.py",
        "tests/test_sigma_strict.py",
        "tests/test_sigma_generator.py",
        "tests/test_rule_binding.py",
        "tests/test_ice_correlate.py",
        "tests/test_input_understanding.py",
        "tests/test_pr212_canonical_evidence_recovery.py",
        "tests/test_decoder_bridge.py",
        "tests/test_decoder_analyst_visibility.py",
        "tests/test_universal_content_analysis.py",
    ]

    # 2. Phase 2 Foundation Suite (29 tests)
    phase2_files = [
        "tests/test_phase2_telemetry_normalization.py",
        "tests/test_phase2_canonical_ir.py",
        "tests/test_phase2_translation.py",
        "tests/test_phase2_deduplication.py",
        "tests/test_phase2_validation_framework.py",
        "tests/test_phase2_lifecycle.py",
        "tests/test_phase2_engine_binding.py",
    ]

    # 3. Phase 2.1 Adversarial Foundation Suite
    phase2_1_files = [
        "tests/test_phase2_1_translation_adversarial.py",
        "tests/test_phase2_1_semantic_equivalence.py",
        "tests/test_phase2_1_field_normalization_adversarial.py",
        "tests/test_phase2_1_tenant_isolation.py",
        "tests/test_phase2_1_deduplication_adversarial.py",
        "tests/test_phase2_1_license_policy.py",
        "tests/test_phase2_1_lifecycle_adversarial.py",
        "tests/test_phase2_1_engine_binding_adversarial.py",
        "tests/test_phase2_1_security_state_boundary.py",
        "tests/test_phase2_1_scale_microbenchmark.py",
    ]

    total_t0 = time.perf_counter()

    reg_summary = run_suite("NivXRay XDR Existing Regression Suite", existing_regression_files)
    p2_summary = run_suite("Phase 2 Foundation Suite (Baseline)", phase2_files)
    p2_1_summary = run_suite("Phase 2.1 Adversarial Foundation Suite", phase2_1_files)

    total_elapsed = round(time.perf_counter() - total_t0, 3)

    grand_collected = reg_summary["collected"] + p2_summary["collected"] + p2_1_summary["collected"]
    grand_passed = reg_summary["passed"] + p2_summary["passed"] + p2_1_summary["passed"]
    grand_failed = reg_summary["failed"] + p2_summary["failed"] + p2_1_summary["failed"]
    grand_errors = reg_summary["errors"] + p2_summary["errors"] + p2_1_summary["errors"]
    grand_skipped = reg_summary["skipped"] + p2_summary["skipped"] + p2_1_summary["skipped"]

    full_report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_duration_seconds": total_elapsed,
        "grand_totals": {
            "collected": grand_collected,
            "passed": grand_passed,
            "failed": grand_failed,
            "errors": grand_errors,
            "skipped": grand_skipped,
        },
        "suites": {
            "existing_regression": reg_summary,
            "phase2_foundation": p2_summary,
            "phase2_1_adversarial": p2_1_summary,
        },
    }

    out_path = "tests/adversarial_phase2_1_results.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(full_report, f, indent=2)

    print(f"\n{'='*70}\nPHASE 2.1 AUDIT GRAND TOTALS\n{'='*70}")
    print(f"Total Collected: {grand_collected}")
    print(f"Total Passed:    {grand_passed}")
    print(f"Total Failed:    {grand_failed}")
    print(f"Total Errors:    {grand_errors}")
    print(f"Total Skipped:   {grand_skipped}")
    print(f"Total Time:      {total_elapsed}s")
    print(f"Saved full JSON audit report to: {out_path}")
    print("="*70)

    exit_status = 1 if (grand_failed > 0 or grand_errors > 0) else 0
    sys.exit(exit_status)


if __name__ == "__main__":
    main()
