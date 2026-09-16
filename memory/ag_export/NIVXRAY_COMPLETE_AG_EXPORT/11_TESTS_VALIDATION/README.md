# Automated Test Suites, Golden Corpora, Benchmarks & Test Reports

**Category Directory**: `11_TESTS_VALIDATION/`  
**Authoritative Source Reference**: All source files referenced herein reside authoritatively in [`../01_COMPLETE_SOURCE/`](../01_COMPLETE_SOURCE/).  
**Total Associated Files**: 2,082 files  
**Total Category Size**: 9.07 MB  
**Total Lines of Code / Documentation**: 224,225 lines  

---

## Purpose & Scope

Comprehensive regression suites, canonical test fixtures, performance benchmarks, and execution logs.

## Quality Gates & Verification Infrastructure

NivXRay maintains extensive automated verification across all layers:

### Test Suites:
1. **Backend Unit & Integration Tests**: `backend/tests/` (480 files) — Tests covering decoders, canonicalizer, normalizers, IKG, verdict, and routers.
2. **Security State Test Suite**: `backend/security_state/tests/` (21 files) — Rigorous tests for causal reachability, intervention safety, and ledger immutability.
3. **Golden Corpora & Fixtures**: `backend/tests/fixtures/` & `golden_corpus/` — Real-world adversary payloads, obfuscated scripts, and benign baselines.
4. **NivXRay Open Benchmark**: `benchmarks/nivxray-open-benchmark/` (609 files) — 300 expected detection outputs and comparative evaluation harnesses.
5. **Execution Reports**: `test_reports/` (104 files) — Historical test logs (`iteration_1.json` through `iteration_80.json`, `enterprise_content_truth_audit.json`).


---

## Associated File Index (Authoritative Paths in `01_COMPLETE_SOURCE/`)

| Relative Source Path | Size (Bytes) | Lines | Type | Status |
| :--- | :---: | :---: | :---: | :---: |
| [`01_COMPLETE_SOURCE/backend/tests/DECODER_BASELINE.md`](../01_COMPLETE_SOURCE/backend/tests/DECODER_BASELINE.md) | 2,553 | 52 | `test_documentation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/adversarial_phase2_1_results.json`](../01_COMPLETE_SOURCE/backend/tests/adversarial_phase2_1_results.json) | 49,334 | 1,182 | `generated_artifact` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/adversarial_regression_report.json`](../01_COMPLETE_SOURCE/backend/tests/adversarial_regression_report.json) | 31,961 | 996 | `generated_artifact` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/activity/__init__.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/activity/__init__.py) | 0 | 0 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/activity/test_activity_projector_contract.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/activity/test_activity_projector_contract.py) | 11,373 | 243 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/api/__init__.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/api/__init__.py) | 0 | 0 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/api/test_die_query_hunt.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/api/test_die_query_hunt.py) | 24,030 | 502 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/api/test_die_timeline.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/api/test_die_timeline.py) | 13,729 | 285 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/api/test_investigation_results_payload_shape.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/api/test_investigation_results_payload_shape.py) | 12,369 | 258 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/api/test_item5_ti_lookup_bounded.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/api/test_item5_ti_lookup_bounded.py) | 11,826 | 278 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/api/test_iue_lane_a_router.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/api/test_iue_lane_a_router.py) | 4,492 | 119 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/api/test_iue_lane_a_ui_contract.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/api/test_iue_lane_a_ui_contract.py) | 7,249 | 171 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/api/test_iue_security_regression.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/api/test_iue_security_regression.py) | 6,580 | 163 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/api/test_p02_evidence_chain.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/api/test_p02_evidence_chain.py) | 21,202 | 438 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/api/test_p0_security_hardening.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/api/test_p0_security_hardening.py) | 9,479 | 230 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/api/test_p11_retention_sweep.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/api/test_p11_retention_sweep.py) | 4,474 | 151 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/api/test_p11_upload_bridge.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/api/test_p11_upload_bridge.py) | 7,605 | 178 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/api/test_p1_server_side_files.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/api/test_p1_server_side_files.py) | 11,027 | 261 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/api/test_p2_slice1_no_corpus_impact.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/api/test_p2_slice1_no_corpus_impact.py) | 3,156 | 86 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/api/test_p2_slice2_extended_contract.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/api/test_p2_slice2_extended_contract.py) | 13,117 | 301 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/api/test_p2_slice2_sysmon_event3.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/api/test_p2_slice2_sysmon_event3.py) | 13,706 | 323 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/api/test_p2_slice3_evtx_transport.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/api/test_p2_slice3_evtx_transport.py) | 16,659 | 372 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/api/test_p2_sysmon_adapter.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/api/test_p2_sysmon_adapter.py) | 9,641 | 232 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/api/test_p2_uislice3_persistence.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/api/test_p2_uislice3_persistence.py) | 8,295 | 184 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/api/test_report_determinism.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/api/test_report_determinism.py) | 9,986 | 282 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/api/test_sample1_immutability_guard.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/api/test_sample1_immutability_guard.py) | 6,977 | 156 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/api/test_ui_def_02_convergence.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/api/test_ui_def_02_convergence.py) | 9,536 | 205 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/api/test_workspace_isolation_guard.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/api/test_workspace_isolation_guard.py) | 9,360 | 207 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/die/__init__.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/die/__init__.py) | 0 | 0 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/die/test_intent_objective_expansion.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/die/test_intent_objective_expansion.py) | 8,260 | 182 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/edr/test_edr_projections.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/edr/test_edr_projections.py) | 5,378 | 128 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/executor/test_executor_all.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/executor/test_executor_all.py) | 13,090 | 300 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/executor/test_mitre_narrative.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/executor/test_mitre_narrative.py) | 7,753 | 215 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/executor/test_text_extract_from_archive.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/executor/test_text_extract_from_archive.py) | 12,733 | 285 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/ida/__init__.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/ida/__init__.py) | 0 | 0 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/ida/test_threat_actor_deconflation.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/ida/test_threat_actor_deconflation.py) | 5,548 | 117 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/incidents/test_incident_summary.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/incidents/test_incident_summary.py) | 2,645 | 79 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/incidents/test_incidents_projection.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/incidents/test_incidents_projection.py) | 7,484 | 189 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/iue/__init__.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/iue/__init__.py) | 63 | 1 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/iue/_baseline/inputs.json`](../01_COMPLETE_SOURCE/backend/tests/canonical/iue/_baseline/inputs.json) | 762 | 34 | `configuration` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/iue/_baseline/response_hashes.json`](../01_COMPLETE_SOURCE/backend/tests/canonical/iue/_baseline/response_hashes.json) | 521 | 18 | `configuration` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/iue/harness/__init__.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/iue/harness/__init__.py) | 26 | 1 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/iue/harness/equivalence_harness.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/iue/harness/equivalence_harness.py) | 20,284 | 440 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/iue/lane_a/__init__.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/iue/lane_a/__init__.py) | 0 | 0 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/iue/lane_a/preview_wire_output.json`](../01_COMPLETE_SOURCE/backend/tests/canonical/iue/lane_a/preview_wire_output.json) | 19,543 | 584 | `configuration` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/iue/lane_a/test_iue_aggregator_semantics.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/iue/lane_a/test_iue_aggregator_semantics.py) | 6,864 | 184 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/iue/lane_a/test_iue_contracts.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/iue/lane_a/test_iue_contracts.py) | 7,247 | 176 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/iue/lane_a/test_iue_field_map_aliases.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/iue/lane_a/test_iue_field_map_aliases.py) | 2,654 | 79 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/iue/lane_a/test_iue_lane_a_e2e.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/iue/lane_a/test_iue_lane_a_e2e.py) | 2,322 | 60 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/iue/lane_a/test_iue_preview_ndjson_wire_shape.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/iue/lane_a/test_iue_preview_ndjson_wire_shape.py) | 6,816 | 134 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/iue/lane_a/test_iue_provenance_composition.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/iue/lane_a/test_iue_provenance_composition.py) | 4,597 | 111 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/iue/lane_a/test_iue_record_boundaries.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/iue/lane_a/test_iue_record_boundaries.py) | 2,624 | 73 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/iue/lane_b/__init__.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/iue/lane_b/__init__.py) | 0 | 0 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/iue/lane_b/test_lane_b_contract.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/iue/lane_b/test_lane_b_contract.py) | 11,866 | 285 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/iue/lane_c/__init__.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/iue/lane_c/__init__.py) | 0 | 0 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/iue/lane_c/test_lane_c_contract.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/iue/lane_c/test_lane_c_contract.py) | 18,660 | 392 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/iue/test_composer_amendment1_inputs.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/iue/test_composer_amendment1_inputs.py) | 7,342 | 155 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/iue/test_composer_composition.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/iue/test_composer_composition.py) | 2,366 | 53 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/iue/test_composer_contract.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/iue/test_composer_contract.py) | 3,504 | 105 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/iue/test_composer_determinism.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/iue/test_composer_determinism.py) | 2,297 | 59 | `test` | `PRE_EXISTING` |

*... and 2022 more files. Refer to [`TESTS_VALIDATION_MANIFEST.json`](./TESTS_VALIDATION_MANIFEST.json) for the exhaustive JSON catalog.*
