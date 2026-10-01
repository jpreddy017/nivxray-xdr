# Frozen 615-Object Content Fabric across 16 Security Domains

**Category Directory**: `04_CONTENT_FABRIC/`  
**Authoritative Source Reference**: All source files referenced herein reside authoritatively in [`../01_COMPLETE_SOURCE/`](../01_COMPLETE_SOURCE/).  
**Total Associated Files**: 114 files  
**Total Category Size**: 2.40 MB  
**Total Lines of Code / Documentation**: 51,812 lines  

---

## Purpose & Scope

Complete implementation of the production 615-object detection content fabric, audited with zero duplicates and zero quarantined rules.

## Forensic Truth Audit & Domain Breakdown

The Content Fabric is strictly frozen at **615 canonical objects** across 16 security domains, fully certified via `backend/run_content_truth_audit.py` (emitting `test_reports/enterprise_content_truth_audit.json`):

| Domain | Objects | Engine / Evaluator | Provenance Classification |
| :--- | :---: | :--- | :--- |
| **Sigma** | 165 | `SigmaEngine` (`nivxray_native_sigma.py`) | ORIGINAL_PUBLIC (SigmaHQ) |
| **YARA / YARA-L** | 50 | `YARARuntimeEngine` (`yara_engine.py`) | ORIGINAL_PUBLIC (Open Source YARA) |
| **EQL** | 40 | `EQLSequenceEngine` (`canonical_ir/evaluator.py`) | ORIGINAL_PUBLIC (Elastic Security) |
| **SPL** | 35 | `SPLEvaluationRuntime` (`canonical_ir/evaluator.py`) | ORIGINAL_PUBLIC (Splunk ESCU) |
| **KQL** | 35 | `KQLEvaluationRuntime` (`canonical_ir/evaluator.py`) | ORIGINAL_PUBLIC (Microsoft Sentinel) |
| **IOC Rules** | 50 | `IOCMatcherRuntime` (`canonical_ir/evaluator.py`) | DERIVED_FROM_PUBLIC_RESEARCH |
| **Behavioral Lineage** | 30 | `BehavioralLineageEngine` (`canonical_ir/evaluator.py`) | NATIVE_NIVXRAY |
| **ICE Correlation** | 25 | `ICECorrelationRuntime` (`xdr_ice.py`) | NATIVE_NIVXRAY |
| **Threat Hunting** | 30 | `HuntingHypothesisRuntime` (`routers/hunting.py`) | NATIVE_NIVXRAY |
| **Baseline Anomaly** | 25 | `AnomalyBaselineRuntime` (`canonical_ir/evaluator.py`) | NATIVE_NIVXRAY |
| **MITRE ATT&CK Crosswalk** | 25 | `ATT&CKCrosswalkEngine` (`canonical_ir/evaluator.py`) | NATIVE_NIVXRAY |
| **Security State Mapping** | 25 | `SecurityStateTransitionEngine` (`ledger.py`) | NATIVE_NIVXRAY |
| **Response Mapping** | 25 | `ActionRegistryPlaybookEngine` (`xdr_action_registry.py`)| NATIVE_NIVXRAY |
| **OT / ICS Protocols** | 20 | `OTProtocolEngine` (`canonical_ir/evaluator.py`) | DERIVED_FROM_PUBLIC_RESEARCH |
| **RMM Dual-Use** | 20 | `RMMCapabilityEvaluator` (`rmm_model.py`) | NATIVE_NIVXRAY |
| **Adversarial Simulation** | 15 | `AdversarialSimulationEngine` (`simulation/runner.py`) | SYNTHETIC_VALIDATION_ONLY |
| **TOTAL** | **615** | **16 Authoritative Runtimes** | **100% Certified / 0 Quarantined** |


---

## Associated File Index (Authoritative Paths in `01_COMPLETE_SOURCE/`)

| Relative Source Path | Size (Bytes) | Lines | Type | Status |
| :--- | :---: | :---: | :---: | :---: |
| [`01_COMPLETE_SOURCE/backend/detection_content/__init__.py`](../01_COMPLETE_SOURCE/backend/detection_content/__init__.py) | 69 | 3 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/architecture_audit.py`](../01_COMPLETE_SOURCE/backend/detection_content/architecture_audit.py) | 9,506 | 228 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/artifact_router.py`](../01_COMPLETE_SOURCE/backend/detection_content/artifact_router.py) | 10,775 | 255 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/canonical_content_model.py`](../01_COMPLETE_SOURCE/backend/detection_content/canonical_content_model.py) | 13,250 | 366 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/canonical_ir/__init__.py`](../01_COMPLETE_SOURCE/backend/detection_content/canonical_ir/__init__.py) | 787 | 39 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/canonical_ir/evaluator.py`](../01_COMPLETE_SOURCE/backend/detection_content/canonical_ir/evaluator.py) | 2,311 | 69 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/canonical_ir/models.py`](../01_COMPLETE_SOURCE/backend/detection_content/canonical_ir/models.py) | 4,126 | 112 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/canonical_ir/nodes.py`](../01_COMPLETE_SOURCE/backend/detection_content/canonical_ir/nodes.py) | 10,041 | 296 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/capability_contract.py`](../01_COMPLETE_SOURCE/backend/detection_content/capability_contract.py) | 8,427 | 242 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/collector_runtime.py`](../01_COMPLETE_SOURCE/backend/detection_content/collector_runtime.py) | 12,147 | 317 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/contract_registry.py`](../01_COMPLETE_SOURCE/backend/detection_content/contract_registry.py) | 6,235 | 177 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/corpus/__init__.py`](../01_COMPLETE_SOURCE/backend/detection_content/corpus/__init__.py) | 2,981 | 57 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/corpus/adversarial_corpus.py`](../01_COMPLETE_SOURCE/backend/detection_content/corpus/adversarial_corpus.py) | 11,793 | 127 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/corpus/behavioral_correlation_corpus.py`](../01_COMPLETE_SOURCE/backend/detection_content/corpus/behavioral_correlation_corpus.py) | 12,883 | 215 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/corpus/eql_corpus.py`](../01_COMPLETE_SOURCE/backend/detection_content/corpus/eql_corpus.py) | 7,922 | 114 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/corpus/hunting_anomaly_corpus.py`](../01_COMPLETE_SOURCE/backend/detection_content/corpus/hunting_anomaly_corpus.py) | 14,416 | 215 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/corpus/ioc_threat_intel_corpus.py`](../01_COMPLETE_SOURCE/backend/detection_content/corpus/ioc_threat_intel_corpus.py) | 11,369 | 170 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/corpus/mapping_response_corpus.py`](../01_COMPLETE_SOURCE/backend/detection_content/corpus/mapping_response_corpus.py) | 17,158 | 301 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/corpus/ot_ics_rmm_corpus.py`](../01_COMPLETE_SOURCE/backend/detection_content/corpus/ot_ics_rmm_corpus.py) | 9,659 | 193 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/corpus/sigma_corpus.py`](../01_COMPLETE_SOURCE/backend/detection_content/corpus/sigma_corpus.py) | 41,133 | 257 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/corpus/spl_kql_corpus.py`](../01_COMPLETE_SOURCE/backend/detection_content/corpus/spl_kql_corpus.py) | 13,893 | 216 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/corpus/yara_corpus.py`](../01_COMPLETE_SOURCE/backend/detection_content/corpus/yara_corpus.py) | 13,088 | 138 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/corpus_expansion.py`](../01_COMPLETE_SOURCE/backend/detection_content/corpus_expansion.py) | 36,258 | 829 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/correlation_library.py`](../01_COMPLETE_SOURCE/backend/detection_content/correlation_library.py) | 7,935 | 197 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/deduplication/__init__.py`](../01_COMPLETE_SOURCE/backend/detection_content/deduplication/__init__.py) | 334 | 12 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/deduplication/engine.py`](../01_COMPLETE_SOURCE/backend/detection_content/deduplication/engine.py) | 7,259 | 156 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/deduplication/fingerprint.py`](../01_COMPLETE_SOURCE/backend/detection_content/deduplication/fingerprint.py) | 3,866 | 102 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/detection_harness.py`](../01_COMPLETE_SOURCE/backend/detection_content/detection_harness.py) | 7,082 | 176 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/engine_classifier.py`](../01_COMPLETE_SOURCE/backend/detection_content/engine_classifier.py) | 7,070 | 179 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/engine_control_plane.py`](../01_COMPLETE_SOURCE/backend/detection_content/engine_control_plane.py) | 13,432 | 319 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/engine_fabric_contracts.py`](../01_COMPLETE_SOURCE/backend/detection_content/engine_fabric_contracts.py) | 22,408 | 447 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/engine_registry.py`](../01_COMPLETE_SOURCE/backend/detection_content/engine_registry.py) | 1,519 | 45 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/library/__init__.py`](../01_COMPLETE_SOURCE/backend/detection_content/library/__init__.py) | 491 | 23 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/library/models.py`](../01_COMPLETE_SOURCE/backend/detection_content/library/models.py) | 2,999 | 96 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/library/registry.py`](../01_COMPLETE_SOURCE/backend/detection_content/library/registry.py) | 3,226 | 85 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/library/rules_enterprise.py`](../01_COMPLETE_SOURCE/backend/detection_content/library/rules_enterprise.py) | 46,944 | 936 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/model.py`](../01_COMPLETE_SOURCE/backend/detection_content/model.py) | 5,496 | 162 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/nivxray_native_sigma.py`](../01_COMPLETE_SOURCE/backend/detection_content/nivxray_native_sigma.py) | 9,417 | 245 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/rmm_model.py`](../01_COMPLETE_SOURCE/backend/detection_content/rmm_model.py) | 12,701 | 274 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/rule_binding.py`](../01_COMPLETE_SOURCE/backend/detection_content/rule_binding.py) | 9,828 | 245 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/sigma_ingest.py`](../01_COMPLETE_SOURCE/backend/detection_content/sigma_ingest.py) | 12,488 | 341 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/sigma_strict.py`](../01_COMPLETE_SOURCE/backend/detection_content/sigma_strict.py) | 8,010 | 226 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/telemetry/__init__.py`](../01_COMPLETE_SOURCE/backend/detection_content/telemetry/__init__.py) | 1,135 | 41 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/telemetry/aws_cloudtrail_dsm.py`](../01_COMPLETE_SOURCE/backend/detection_content/telemetry/aws_cloudtrail_dsm.py) | 7,130 | 207 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/telemetry/linux_auditd_dsm.py`](../01_COMPLETE_SOURCE/backend/detection_content/telemetry/linux_auditd_dsm.py) | 8,280 | 238 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/telemetry/models.py`](../01_COMPLETE_SOURCE/backend/detection_content/telemetry/models.py) | 4,273 | 135 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/telemetry/registry.py`](../01_COMPLETE_SOURCE/backend/detection_content/telemetry/registry.py) | 1,089 | 39 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/telemetry/windows_security_dsm.py`](../01_COMPLETE_SOURCE/backend/detection_content/telemetry/windows_security_dsm.py) | 11,920 | 316 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/translation/__init__.py`](../01_COMPLETE_SOURCE/backend/detection_content/translation/__init__.py) | 545 | 20 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/translation/anomaly_translator.py`](../01_COMPLETE_SOURCE/backend/detection_content/translation/anomaly_translator.py) | 3,306 | 81 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/translation/base.py`](../01_COMPLETE_SOURCE/backend/detection_content/translation/base.py) | 1,888 | 55 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/translation/behavioral_translator.py`](../01_COMPLETE_SOURCE/backend/detection_content/translation/behavioral_translator.py) | 4,701 | 118 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/translation/correlation_translator.py`](../01_COMPLETE_SOURCE/backend/detection_content/translation/correlation_translator.py) | 3,881 | 99 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/translation/eql_translator.py`](../01_COMPLETE_SOURCE/backend/detection_content/translation/eql_translator.py) | 11,934 | 298 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/translation/hunting_translator.py`](../01_COMPLETE_SOURCE/backend/detection_content/translation/hunting_translator.py) | 2,899 | 74 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/translation/ioc_translator.py`](../01_COMPLETE_SOURCE/backend/detection_content/translation/ioc_translator.py) | 4,523 | 116 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/translation/kql_translator.py`](../01_COMPLETE_SOURCE/backend/detection_content/translation/kql_translator.py) | 10,281 | 273 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/translation/manager.py`](../01_COMPLETE_SOURCE/backend/detection_content/translation/manager.py) | 4,869 | 123 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/translation/mapping_translator.py`](../01_COMPLETE_SOURCE/backend/detection_content/translation/mapping_translator.py) | 3,042 | 80 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/translation/sigma_translator.py`](../01_COMPLETE_SOURCE/backend/detection_content/translation/sigma_translator.py) | 13,885 | 337 | `implementation` | `PRE_EXISTING` |

*... and 54 more files. Refer to [`CONTENT_FABRIC_MANIFEST.json`](./CONTENT_FABRIC_MANIFEST.json) for the exhaustive JSON catalog.*
