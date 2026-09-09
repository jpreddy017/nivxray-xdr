# Forensic Truth Audits, Truth Contracts & Verification Proofs

**Category Directory**: `12_AUDITS_TRUTH/`  
**Authoritative Source Reference**: All source files referenced herein reside authoritatively in [`../01_COMPLETE_SOURCE/`](../01_COMPLETE_SOURCE/).  
**Total Associated Files**: 698 files  
**Total Category Size**: 3.19 MB  
**Total Lines of Code / Documentation**: 67,763 lines  

---

## Purpose & Scope

Rigorous audits certifying active codebase realities against documented claims.

## Truth Contract & Forensic Certification

This subsystem holds the permanent record of truth verifications conducted during the project:

### Key Audit Deliverables:
1. **Truth Contract**: `docs/truth-contract/` — Master contract establishing immutable ground truth.
2. **Enterprise Content Truth Audit**: `backend/run_content_truth_audit.py` & `test_reports/enterprise_content_truth_audit.json` — Certified 615 objects across 16 domains (100% pass, 0 quarantined).
3. **Decoder Truth Audit & Matrix**: `docs/security-state/DECODER_FINAL_TRUTH_MATRIX.md` & `backend/verify_decoder_truth_e2e.py` — Certified 47 codecs + 14 profilers across 10 operational cases.
4. **EDR Truth Audit**: `docs/security-state/NIVXFORGE_EDR_TRUTH_AUDIT.md` — Forensic boundary establishing what exists vs planned.
5. **Emergent Handoff Audit Report**: `docs/NIVXFORGE_EDR_EMERGENT_HANDOFF_PACKAGE_REPORT.md` — Checksum verification and packaging audit.


---

## Associated File Index (Authoritative Paths in `01_COMPLETE_SOURCE/`)

| Relative Source Path | Size (Bytes) | Lines | Type | Status |
| :--- | :---: | :---: | :---: | :---: |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr/docs/NIVXRAY_XDR_CAPABILITY_GAP_AUDIT.md`](../01_COMPLETE_SOURCE/apps/nivxray-xdr/docs/NIVXRAY_XDR_CAPABILITY_GAP_AUDIT.md) | 19,280 | 364 | `documentation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr/docs/NIVXRAY_XDR_ENTERPRISE_PRODUCT_GAP_AUDIT.md`](../01_COMPLETE_SOURCE/apps/nivxray-xdr/docs/NIVXRAY_XDR_ENTERPRISE_PRODUCT_GAP_AUDIT.md) | 24,118 | 379 | `documentation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr/src/xdr/admin/AuditLogBody.jsx`](../01_COMPLETE_SOURCE/apps/nivxray-xdr/src/xdr/admin/AuditLogBody.jsx) | 6,867 | 159 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/architecture_audit.py`](../01_COMPLETE_SOURCE/backend/detection_content/architecture_audit.py) | 9,506 | 228 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/telemetry/linux_auditd_dsm.py`](../01_COMPLETE_SOURCE/backend/detection_content/telemetry/linux_auditd_dsm.py) | 8,280 | 238 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/investigation/truth_model.py`](../01_COMPLETE_SOURCE/backend/nivxforge/investigation/truth_model.py) | 23,483 | 535 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/routers/audit_downloads.py`](../01_COMPLETE_SOURCE/backend/routers/audit_downloads.py) | 3,718 | 114 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/routers/benchmark.py`](../01_COMPLETE_SOURCE/backend/routers/benchmark.py) | 6,298 | 193 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/routers/xdr_audit_log.py`](../01_COMPLETE_SOURCE/backend/routers/xdr_audit_log.py) | 10,303 | 260 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/run_content_truth_audit.py`](../01_COMPLETE_SOURCE/backend/run_content_truth_audit.py) | 39,098 | 802 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/run_phase2_1_audit.py`](../01_COMPLETE_SOURCE/backend/run_phase2_1_audit.py) | 6,623 | 172 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/benchmarks/__init__.py`](../01_COMPLETE_SOURCE/backend/security_state/benchmarks/__init__.py) | 102 | 4 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/benchmarks/benchmark.py`](../01_COMPLETE_SOURCE/backend/security_state/benchmarks/benchmark.py) | 5,160 | 115 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/tests/api_endpoint_audit.py`](../01_COMPLETE_SOURCE/backend/security_state/tests/api_endpoint_audit.py) | 6,496 | 159 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/tests/phase2_audit_runner.py`](../01_COMPLETE_SOURCE/backend/security_state/tests/phase2_audit_runner.py) | 22,265 | 464 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/diagnostics/vendor_benchmark.py`](../01_COMPLETE_SOURCE/backend/services/diagnostics/vendor_benchmark.py) | 13,804 | 311 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/static_docs/audit_reconciliation.html`](../01_COMPLETE_SOURCE/backend/static_docs/audit_reconciliation.html) | 23,657 | 570 | `documentation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/static_docs/audit_reconciliation.md`](../01_COMPLETE_SOURCE/backend/static_docs/audit_reconciliation.md) | 14,705 | 155 | `documentation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/static_docs/current_state_audit.html`](../01_COMPLETE_SOURCE/backend/static_docs/current_state_audit.html) | 54,653 | 1,718 | `documentation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/static_docs/current_state_audit.md`](../01_COMPLETE_SOURCE/backend/static_docs/current_state_audit.md) | 37,338 | 605 | `documentation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/decoder_harness/test_b3_3_dependency_audit.py`](../01_COMPLETE_SOURCE/backend/tests/decoder_harness/test_b3_3_dependency_audit.py) | 9,239 | 240 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/decoder_migration/B3_3_DEPENDENCY_AUDIT_REPORT.md`](../01_COMPLETE_SOURCE/backend/tests/decoder_migration/B3_3_DEPENDENCY_AUDIT_REPORT.md) | 8,344 | 209 | `test_documentation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/decoder_migration/dependency_audit.py`](../01_COMPLETE_SOURCE/backend/tests/decoder_migration/dependency_audit.py) | 10,211 | 272 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/investigation/corpus/alien/saas_audit_log.json`](../01_COMPLETE_SOURCE/backend/tests/investigation/corpus/alien/saas_audit_log.json) | 582 | 16 | `generated_artifact` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/parity/test_truth_model.py`](../01_COMPLETE_SOURCE/backend/tests/parity/test_truth_model.py) | 3,847 | 106 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/quality/benchmark_corpus.py`](../01_COMPLETE_SOURCE/backend/tests/quality/benchmark_corpus.py) | 4,995 | 129 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/quality/test_investigation_benchmark.py`](../01_COMPLETE_SOURCE/backend/tests/quality/test_investigation_benchmark.py) | 8,558 | 219 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/rc23_benchmark/__init__.py`](../01_COMPLETE_SOURCE/backend/tests/rc23_benchmark/__init__.py) | 17,271 | 437 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/rc23_benchmark/ci_gate.py`](../01_COMPLETE_SOURCE/backend/tests/rc23_benchmark/ci_gate.py) | 5,394 | 127 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/rc23_benchmark/profile_latency.py`](../01_COMPLETE_SOURCE/backend/tests/rc23_benchmark/profile_latency.py) | 4,588 | 126 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/rc23_benchmark/run_benchmark.py`](../01_COMPLETE_SOURCE/backend/tests/rc23_benchmark/run_benchmark.py) | 8,599 | 223 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/reports/workspace_audit_report.json`](../01_COMPLETE_SOURCE/backend/tests/reports/workspace_audit_report.json) | 29,281 | 1,121 | `generated_artifact` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/test_compression_benchmark.py`](../01_COMPLETE_SOURCE/backend/tests/test_compression_benchmark.py) | 6,174 | 141 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/test_content_truth_audit.py`](../01_COMPLETE_SOURCE/backend/tests/test_content_truth_audit.py) | 8,754 | 203 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/test_phase2_1_scale_microbenchmark.py`](../01_COMPLETE_SOURCE/backend/tests/test_phase2_1_scale_microbenchmark.py) | 7,616 | 221 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/test_regression_benchmark.py`](../01_COMPLETE_SOURCE/backend/tests/test_regression_benchmark.py) | 8,328 | 229 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/test_vendor_benchmark_regression.py`](../01_COMPLETE_SOURCE/backend/tests/test_vendor_benchmark_regression.py) | 9,953 | 217 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/test_workspace_audit_gate.py`](../01_COMPLETE_SOURCE/backend/tests/test_workspace_audit_gate.py) | 3,105 | 76 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/test_xdr_audit_log.py`](../01_COMPLETE_SOURCE/backend/tests/test_xdr_audit_log.py) | 4,642 | 136 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/test_xdr_round44_cockpit_audit_lock.py`](../01_COMPLETE_SOURCE/backend/tests/test_xdr_round44_cockpit_audit_lock.py) | 10,742 | 252 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/workspace_audit.py`](../01_COMPLETE_SOURCE/backend/tests/workspace_audit.py) | 14,112 | 298 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/verify_decoder_truth_e2e.py`](../01_COMPLETE_SOURCE/backend/verify_decoder_truth_e2e.py) | 10,429 | 232 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/benchmarks/nivxray-open-benchmark/LICENSE.txt`](../01_COMPLETE_SOURCE/benchmarks/nivxray-open-benchmark/LICENSE.txt) | 720 | 14 | `documentation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/benchmarks/nivxray-open-benchmark/MANIFEST.md`](../01_COMPLETE_SOURCE/benchmarks/nivxray-open-benchmark/MANIFEST.md) | 383 | 12 | `documentation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/benchmarks/nivxray-open-benchmark/README.md`](../01_COMPLETE_SOURCE/benchmarks/nivxray-open-benchmark/README.md) | 3,215 | 81 | `documentation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/benchmarks/nivxray-open-benchmark/engines/cyberchef_adapter.py`](../01_COMPLETE_SOURCE/benchmarks/nivxray-open-benchmark/engines/cyberchef_adapter.py) | 774 | 20 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/benchmarks/nivxray-open-benchmark/engines/llm_adapter.py`](../01_COMPLETE_SOURCE/benchmarks/nivxray-open-benchmark/engines/llm_adapter.py) | 1,532 | 36 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/benchmarks/nivxray-open-benchmark/engines/nivxray_adapter.py`](../01_COMPLETE_SOURCE/benchmarks/nivxray-open-benchmark/engines/nivxray_adapter.py) | 728 | 18 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/benchmarks/nivxray-open-benchmark/expected/3des-inline-ps-1.json`](../01_COMPLETE_SOURCE/benchmarks/nivxray-open-benchmark/expected/3des-inline-ps-1.json) | 495 | 24 | `configuration` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/benchmarks/nivxray-open-benchmark/expected/3des-inline-ps-3.json`](../01_COMPLETE_SOURCE/benchmarks/nivxray-open-benchmark/expected/3des-inline-ps-3.json) | 495 | 24 | `configuration` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/benchmarks/nivxray-open-benchmark/expected/aes-cbc-inline-ps-0.json`](../01_COMPLETE_SOURCE/benchmarks/nivxray-open-benchmark/expected/aes-cbc-inline-ps-0.json) | 521 | 24 | `configuration` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/benchmarks/nivxray-open-benchmark/expected/aes-cbc-inline-ps-1.json`](../01_COMPLETE_SOURCE/benchmarks/nivxray-open-benchmark/expected/aes-cbc-inline-ps-1.json) | 521 | 24 | `configuration` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/benchmarks/nivxray-open-benchmark/expected/aes-cbc-inline-ps-2.json`](../01_COMPLETE_SOURCE/benchmarks/nivxray-open-benchmark/expected/aes-cbc-inline-ps-2.json) | 521 | 24 | `configuration` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/benchmarks/nivxray-open-benchmark/expected/aes-cbc-inline-ps-3.json`](../01_COMPLETE_SOURCE/benchmarks/nivxray-open-benchmark/expected/aes-cbc-inline-ps-3.json) | 521 | 24 | `configuration` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/benchmarks/nivxray-open-benchmark/expected/aes-cbc-inline-ps-4.json`](../01_COMPLETE_SOURCE/benchmarks/nivxray-open-benchmark/expected/aes-cbc-inline-ps-4.json) | 521 | 24 | `configuration` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/benchmarks/nivxray-open-benchmark/expected/aes-gcm-inline-ps-0.json`](../01_COMPLETE_SOURCE/benchmarks/nivxray-open-benchmark/expected/aes-gcm-inline-ps-0.json) | 524 | 24 | `configuration` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/benchmarks/nivxray-open-benchmark/expected/aes-gcm-inline-ps-1.json`](../01_COMPLETE_SOURCE/benchmarks/nivxray-open-benchmark/expected/aes-gcm-inline-ps-1.json) | 524 | 24 | `configuration` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/benchmarks/nivxray-open-benchmark/expected/aes-gcm-inline-ps-2.json`](../01_COMPLETE_SOURCE/benchmarks/nivxray-open-benchmark/expected/aes-gcm-inline-ps-2.json) | 524 | 24 | `configuration` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/benchmarks/nivxray-open-benchmark/expected/aes-gcm-inline-ps-3.json`](../01_COMPLETE_SOURCE/benchmarks/nivxray-open-benchmark/expected/aes-gcm-inline-ps-3.json) | 524 | 24 | `configuration` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/benchmarks/nivxray-open-benchmark/expected/aes-gcm-inline-ps-4.json`](../01_COMPLETE_SOURCE/benchmarks/nivxray-open-benchmark/expected/aes-gcm-inline-ps-4.json) | 524 | 24 | `configuration` | `PRE_EXISTING` |

*... and 638 more files. Refer to [`AUDITS_TRUTH_MANIFEST.json`](./AUDITS_TRUTH_MANIFEST.json) for the exhaustive JSON catalog.*
