# Architectural Decision Records (ADRs) & Integration Contracts

**Category Directory**: `13_ARCHITECTURE_CONTRACTS/`  
**Authoritative Source Reference**: All source files referenced herein reside authoritatively in [`../01_COMPLETE_SOURCE/`](../01_COMPLETE_SOURCE/).  
**Total Associated Files**: 225 files  
**Total Category Size**: 2.81 MB  
**Total Lines of Code / Documentation**: 53,721 lines  

---

## Purpose & Scope

Formal design specifications, ADRs, interface definitions, and security tenancy contracts.

## Architectural Governance

1. **System Architecture**: `ARCHITECTURE.md` & `docs/architecture/`
2. **Architectural Decision Records**:
   - `docs/adr/` (ADR-001 Semantic Contracts, ADR-002 VEEE)
   - `memory/adr/` (89 historical ADR records covering incremental architectural decisions)
3. **Integration Contracts**:
   - `docs/handoff/NIVXFORGE_EDR_INTEGRATION_CONTRACT.md`
   - `docs/handoff/NIVXFORGE_EDR_CANONICAL_EVIDENCE_CONTRACT.md`
   - `docs/handoff/NIVXFORGE_EDR_SECURITY_TENANCY_CONTRACT.md`
   - `docs/handoff/NIVXFORGE_EDR_RESPONSE_INTEGRATION_CONTRACT.md`
   - `docs/P0.15C-RELEASE-CONTRACT.md`


---

## Associated File Index (Authoritative Paths in `01_COMPLETE_SOURCE/`)

| Relative Source Path | Size (Bytes) | Lines | Type | Status |
| :--- | :---: | :---: | :---: | :---: |
| [`01_COMPLETE_SOURCE/ARCHITECTURE.md`](../01_COMPLETE_SOURCE/ARCHITECTURE.md) | 22,924 | 413 | `documentation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/INGEST_CONTRACT.md`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/INGEST_CONTRACT.md) | 6,603 | 165 | `specification` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-response/RESPONSE_INGEST_CONTRACT.md`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-response/RESPONSE_INGEST_CONTRACT.md) | 5,428 | 138 | `specification` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr/docs/NIVXRAY_XDR_SHARED_ENGINE_ARCHITECTURE.md`](../01_COMPLETE_SOURCE/apps/nivxray-xdr/docs/NIVXRAY_XDR_SHARED_ENGINE_ARCHITECTURE.md) | 4,906 | 83 | `documentation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr/docs/RESPONSE_CONTRACT.md`](../01_COMPLETE_SOURCE/apps/nivxray-xdr/docs/RESPONSE_CONTRACT.md) | 5,698 | 136 | `specification` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr/src/xdr/extensions/extensionContract.js`](../01_COMPLETE_SOURCE/apps/nivxray-xdr/src/xdr/extensions/extensionContract.js) | 6,764 | 166 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/baselines/public_interface_contract.json`](../01_COMPLETE_SOURCE/backend/baselines/public_interface_contract.json) | 5,337 | 97 | `configuration` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/baselines/public_interface_contract_v2.json`](../01_COMPLETE_SOURCE/backend/baselines/public_interface_contract_v2.json) | 2,426 | 38 | `configuration` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/architecture_audit.py`](../01_COMPLETE_SOURCE/backend/detection_content/architecture_audit.py) | 9,506 | 228 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/capability_contract.py`](../01_COMPLETE_SOURCE/backend/detection_content/capability_contract.py) | 8,427 | 242 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/contract_registry.py`](../01_COMPLETE_SOURCE/backend/detection_content/contract_registry.py) | 6,235 | 177 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/engine_fabric_contracts.py`](../01_COMPLETE_SOURCE/backend/detection_content/engine_fabric_contracts.py) | 22,408 | 447 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/l1_evidence/ARCHITECTURE_COMPLIANCE.md`](../01_COMPLETE_SOURCE/backend/l1_evidence/ARCHITECTURE_COMPLIANCE.md) | 5,628 | 92 | `documentation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/l2_investigation/ARCHITECTURE_COMPLIANCE.md`](../01_COMPLETE_SOURCE/backend/l2_investigation/ARCHITECTURE_COMPLIANCE.md) | 4,354 | 89 | `documentation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/investigation/pipeline/contract_check.py`](../01_COMPLETE_SOURCE/backend/nivxforge/investigation/pipeline/contract_check.py) | 7,736 | 238 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/tests/test_adr0014_cio.py`](../01_COMPLETE_SOURCE/backend/nivxforge/tests/test_adr0014_cio.py) | 9,594 | 238 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/tests/test_adr0014_evidence_priority.py`](../01_COMPLETE_SOURCE/backend/nivxforge/tests/test_adr0014_evidence_priority.py) | 2,656 | 72 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/tests/test_adr0014_graph.py`](../01_COMPLETE_SOURCE/backend/nivxforge/tests/test_adr0014_graph.py) | 2,956 | 76 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/tests/test_adr0014_ingress_gate.py`](../01_COMPLETE_SOURCE/backend/nivxforge/tests/test_adr0014_ingress_gate.py) | 7,353 | 176 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/tests/test_adr0014_ioc_classifier.py`](../01_COMPLETE_SOURCE/backend/nivxforge/tests/test_adr0014_ioc_classifier.py) | 3,926 | 110 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/tests/test_adr0014_reasoning_steps.py`](../01_COMPLETE_SOURCE/backend/nivxforge/tests/test_adr0014_reasoning_steps.py) | 7,231 | 181 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/tests/test_adr0014_summary_composer.py`](../01_COMPLETE_SOURCE/backend/nivxforge/tests/test_adr0014_summary_composer.py) | 8,065 | 218 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/tests/test_adr0014_verdict_engine.py`](../01_COMPLETE_SOURCE/backend/nivxforge/tests/test_adr0014_verdict_engine.py) | 4,943 | 131 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/reasoning/plugin_contract.py`](../01_COMPLETE_SOURCE/backend/reasoning/plugin_contract.py) | 5,681 | 154 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/contracts.py`](../01_COMPLETE_SOURCE/backend/security_state/contracts.py) | 23,206 | 502 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/narration/contracts.py`](../01_COMPLETE_SOURCE/backend/services/narration/contracts.py) | 4,684 | 118 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/uaie/contract.py`](../01_COMPLETE_SOURCE/backend/services/uaie/contract.py) | 14,126 | 291 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/xdr_observation_contract.py`](../01_COMPLETE_SOURCE/backend/services/xdr_observation_contract.py) | 3,972 | 91 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/static_docs/adr_004_canonical_ledger.html`](../01_COMPLETE_SOURCE/backend/static_docs/adr_004_canonical_ledger.html) | 32,406 | 729 | `specification` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/static_docs/adr_004_canonical_ledger.md`](../01_COMPLETE_SOURCE/backend/static_docs/adr_004_canonical_ledger.md) | 22,411 | 327 | `specification` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/activity/test_activity_projector_contract.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/activity/test_activity_projector_contract.py) | 11,373 | 243 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/api/test_iue_lane_a_ui_contract.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/api/test_iue_lane_a_ui_contract.py) | 7,249 | 171 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/api/test_p2_slice2_extended_contract.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/api/test_p2_slice2_extended_contract.py) | 13,117 | 301 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/iue/lane_a/test_iue_contracts.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/iue/lane_a/test_iue_contracts.py) | 7,247 | 176 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/iue/lane_b/test_lane_b_contract.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/iue/lane_b/test_lane_b_contract.py) | 11,866 | 285 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/iue/lane_c/test_lane_c_contract.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/iue/lane_c/test_lane_c_contract.py) | 18,660 | 392 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/iue/test_composer_contract.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/iue/test_composer_contract.py) | 3,504 | 105 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/iue/test_m0a_iue_contract_freeze.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/iue/test_m0a_iue_contract_freeze.py) | 10,004 | 230 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/ssot/test_ssot_contract.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/ssot/test_ssot_contract.py) | 3,330 | 92 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/stage1_goldens/goldens/t2_lane_a_wire_contract.json`](../01_COMPLETE_SOURCE/backend/tests/canonical/stage1_goldens/goldens/t2_lane_a_wire_contract.json) | 16,845 | 584 | `configuration` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/stage1_goldens/test_t2_lane_a_wire_contract.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/stage1_goldens/test_t2_lane_a_wire_contract.py) | 5,546 | 109 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/canonical/verdict_stage2/test_stage2_engine_contract.py`](../01_COMPLETE_SOURCE/backend/tests/canonical/verdict_stage2/test_stage2_engine_contract.py) | 14,774 | 318 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/investigation/test_narrative_contract.py`](../01_COMPLETE_SOURCE/backend/tests/investigation/test_narrative_contract.py) | 15,930 | 410 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/l2_investigation/test_service_contracts.py`](../01_COMPLETE_SOURCE/backend/tests/l2_investigation/test_service_contracts.py) | 2,925 | 84 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/test_adr0007_verdict_evidence_gating.py`](../01_COMPLETE_SOURCE/backend/tests/test_adr0007_verdict_evidence_gating.py) | 13,658 | 319 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/test_adr0008_ioc_extraction_validation.py`](../01_COMPLETE_SOURCE/backend/tests/test_adr0008_ioc_extraction_validation.py) | 8,061 | 185 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/test_adr0009_cim.py`](../01_COMPLETE_SOURCE/backend/tests/test_adr0009_cim.py) | 15,332 | 357 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/test_adr0012_progressive_partial_recovery.py`](../01_COMPLETE_SOURCE/backend/tests/test_adr0012_progressive_partial_recovery.py) | 7,635 | 197 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/test_adr0014_endpoints.py`](../01_COMPLETE_SOURCE/backend/tests/test_adr0014_endpoints.py) | 6,524 | 180 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/test_capability_contract.py`](../01_COMPLETE_SOURCE/backend/tests/test_capability_contract.py) | 11,210 | 248 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/test_capability_contracts.py`](../01_COMPLETE_SOURCE/backend/tests/test_capability_contracts.py) | 3,733 | 102 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/test_e2e_decode_smart_http_contract.py`](../01_COMPLETE_SOURCE/backend/tests/test_e2e_decode_smart_http_contract.py) | 17,072 | 369 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/test_iep_contract.py`](../01_COMPLETE_SOURCE/backend/tests/test_iep_contract.py) | 11,497 | 289 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/test_iter43_decode_api_contract.py`](../01_COMPLETE_SOURCE/backend/tests/test_iter43_decode_api_contract.py) | 4,565 | 121 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/test_phase94_api_contract.py`](../01_COMPLETE_SOURCE/backend/tests/test_phase94_api_contract.py) | 5,937 | 136 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/test_pr211_canonical_response_contract.py`](../01_COMPLETE_SOURCE/backend/tests/test_pr211_canonical_response_contract.py) | 5,642 | 153 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/test_ps_decode_error_contract.py`](../01_COMPLETE_SOURCE/backend/tests/test_ps_decode_error_contract.py) | 9,523 | 207 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/test_qa_layer_contracts.py`](../01_COMPLETE_SOURCE/backend/tests/test_qa_layer_contracts.py) | 5,609 | 128 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/test_s4_architecture_freeze.py`](../01_COMPLETE_SOURCE/backend/tests/test_s4_architecture_freeze.py) | 8,732 | 177 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/test_uaie_phase1_contracts.py`](../01_COMPLETE_SOURCE/backend/tests/test_uaie_phase1_contracts.py) | 6,332 | 141 | `test` | `PRE_EXISTING` |

*... and 165 more files. Refer to [`ARCHITECTURE_CONTRACTS_MANIFEST.json`](./ARCHITECTURE_CONTRACTS_MANIFEST.json) for the exhaustive JSON catalog.*
