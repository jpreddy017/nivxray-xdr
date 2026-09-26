# NivXForge EDR Target Architecture, 37-Surface IA & Operational Prototype

**Category Directory**: `07_EDR/`  
**Authoritative Source Reference**: All source files referenced herein reside authoritatively in [`../01_COMPLETE_SOURCE/`](../01_COMPLETE_SOURCE/).  
**Total Associated Files**: 199 files  
**Total Category Size**: 2.26 MB  
**Total Lines of Code / Documentation**: 45,998 lines  

---

## Purpose & Scope

Complete operational blueprint, industry benchmark, UI/UX parity matrix, and Emergent handoff package for NivXForge EDR.

## Implementation Status: Specification & Prototype (Phase 1 Ready)

All deliverables in this category represent **approved specifications, integration contracts, architectural blueprints, and interactive prototypes**. Production kernel drivers and sensor agents are slated for Phase 1.

### Master Deliverables:
1. **12-Platform Industry Benchmark**: `docs/security-state/NIVXFORGE_EDR_SANDBOX_INDUSTRY_BENCHMARK.md` — Parity analysis against CrowdStrike Falcon, SentinelOne Singularity, Microsoft Defender for Endpoint, etc.
2. **EDR Forensic Truth Audit**: `docs/security-state/NIVXFORGE_EDR_TRUTH_AUDIT.md` — Authoritative audit establishing true code boundaries.
3. **Target Architecture & Plan**: `docs/security-state/NIVXFORGE_EDR_TARGET_ARCHITECTURE_AND_IMPLEMENTATION_PLAN.md` — 5-phase engineering roadmap.
4. **37-Surface Information Architecture**: `docs/uiux/NIVXFORGE_EDR_INFORMATION_ARCHITECTURE.md` — Complete EDR navigation and screen taxonomy.
5. **UI/UX Parity Matrix**: `docs/uiux/NIVXFORGE_EDR_EXHAUSTIVE_UIUX_PARITY_MATRIX.md` — Field-by-field feature comparison.
6. **Attack-Chain UX Matrix**: `docs/uiux/NIVXFORGE_EDR_ATTACK_CHAIN_UX_MATRIX.md` — 20-step traversal and 11 specialized investigation pivots.
7. **Interactive Operational Prototype**: `docs/uiux/NIVXFORGE_EDR_SANDBOX_OPERATIONAL_PROTOTYPE.html` — Single-file interactive HTML prototype (zero external dependencies, 0 console errors).
8. **Emergent Integration Contracts**: `docs/handoff/` (10 contract documents) & `docs/emergent-handoff-package/` (25 structured files).


---

## Associated File Index (Authoritative Paths in `01_COMPLETE_SOURCE/`)

| Relative Source Path | Size (Bytes) | Lines | Type | Status |
| :--- | :---: | :---: | :---: | :---: |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr/src/nivxforge/NivXForgeConsole.jsx`](../01_COMPLETE_SOURCE/apps/nivxray-xdr/src/nivxforge/NivXForgeConsole.jsx) | 6,233 | 153 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr/src/nivxforge/edrApi.js`](../01_COMPLETE_SOURCE/apps/nivxray-xdr/src/nivxforge/edrApi.js) | 1,058 | 29 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr/src/nivxforge/nivxforge.css`](../01_COMPLETE_SOURCE/apps/nivxray-xdr/src/nivxforge/nivxforge.css) | 8,776 | 200 | `other` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr/src/nivxforge/pages/EdrDetectionsPage.jsx`](../01_COMPLETE_SOURCE/apps/nivxray-xdr/src/nivxforge/pages/EdrDetectionsPage.jsx) | 6,945 | 170 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr/src/nivxforge/pages/EdrOverviewPage.jsx`](../01_COMPLETE_SOURCE/apps/nivxray-xdr/src/nivxforge/pages/EdrOverviewPage.jsx) | 5,187 | 115 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr/src/nivxforge/pages/EdrProcessTreePage.jsx`](../01_COMPLETE_SOURCE/apps/nivxray-xdr/src/nivxforge/pages/EdrProcessTreePage.jsx) | 7,306 | 197 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr/src/nivxforge/pages/EdrReservedPages.jsx`](../01_COMPLETE_SOURCE/apps/nivxray-xdr/src/nivxforge/pages/EdrReservedPages.jsx) | 2,500 | 66 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr/src/xdr/respond/AnalystResponseDrawer.jsx`](../01_COMPLETE_SOURCE/apps/nivxray-xdr/src/xdr/respond/AnalystResponseDrawer.jsx) | 16,358 | 391 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/xdr_edr_adapter.py`](../01_COMPLETE_SOURCE/backend/detection_content/xdr_edr_adapter.py) | 5,187 | 125 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/README.md`](../01_COMPLETE_SOURCE/backend/nivxforge/README.md) | 1,795 | 52 | `documentation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/__init__.py`](../01_COMPLETE_SOURCE/backend/nivxforge/__init__.py) | 1,030 | 23 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/attribution/__init__.py`](../01_COMPLETE_SOURCE/backend/nivxforge/attribution/__init__.py) | 70 | 1 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/attribution/mitre_shape.py`](../01_COMPLETE_SOURCE/backend/nivxforge/attribution/mitre_shape.py) | 3,820 | 97 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/cim/__init__.py`](../01_COMPLETE_SOURCE/backend/nivxforge/cim/__init__.py) | 868 | 43 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/cim/compose.py`](../01_COMPLETE_SOURCE/backend/nivxforge/cim/compose.py) | 16,898 | 415 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/cim/fact_substrate.py`](../01_COMPLETE_SOURCE/backend/nivxforge/cim/fact_substrate.py) | 20,859 | 423 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/cim/models.py`](../01_COMPLETE_SOURCE/backend/nivxforge/cim/models.py) | 9,662 | 243 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/cim/unknowns.py`](../01_COMPLETE_SOURCE/backend/nivxforge/cim/unknowns.py) | 5,229 | 152 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/cim/validators.py`](../01_COMPLETE_SOURCE/backend/nivxforge/cim/validators.py) | 4,832 | 118 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/config.py`](../01_COMPLETE_SOURCE/backend/nivxforge/config.py) | 988 | 33 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/core/__init__.py`](../01_COMPLETE_SOURCE/backend/nivxforge/core/__init__.py) | 308 | 7 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/core/cio.py`](../01_COMPLETE_SOURCE/backend/nivxforge/core/cio.py) | 3,674 | 94 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/core/evidence.py`](../01_COMPLETE_SOURCE/backend/nivxforge/core/evidence.py) | 2,020 | 63 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/engines/README.md`](../01_COMPLETE_SOURCE/backend/nivxforge/engines/README.md) | 461 | 12 | `documentation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/engines/__init__.py`](../01_COMPLETE_SOURCE/backend/nivxforge/engines/__init__.py) | 133 | 4 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/engines/base.py`](../01_COMPLETE_SOURCE/backend/nivxforge/engines/base.py) | 1,016 | 34 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/framework/__init__.py`](../01_COMPLETE_SOURCE/backend/nivxforge/framework/__init__.py) | 581 | 15 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/framework/classifier.py`](../01_COMPLETE_SOURCE/backend/nivxforge/framework/classifier.py) | 2,166 | 66 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/framework/coverage.py`](../01_COMPLETE_SOURCE/backend/nivxforge/framework/coverage.py) | 2,548 | 78 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/framework/protocol.py`](../01_COMPLETE_SOURCE/backend/nivxforge/framework/protocol.py) | 2,028 | 57 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/framework/registry.py`](../01_COMPLETE_SOURCE/backend/nivxforge/framework/registry.py) | 1,309 | 45 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/investigation/__init__.py`](../01_COMPLETE_SOURCE/backend/nivxforge/investigation/__init__.py) | 1,318 | 48 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/investigation/analyst_narrative.py`](../01_COMPLETE_SOURCE/backend/nivxforge/investigation/analyst_narrative.py) | 33,349 | 795 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/investigation/artifact_discovery.py`](../01_COMPLETE_SOURCE/backend/nivxforge/investigation/artifact_discovery.py) | 11,871 | 285 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/investigation/builder.py`](../01_COMPLETE_SOURCE/backend/nivxforge/investigation/builder.py) | 21,660 | 560 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/investigation/cem.py`](../01_COMPLETE_SOURCE/backend/nivxforge/investigation/cem.py) | 8,221 | 248 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/investigation/correlation_signals.py`](../01_COMPLETE_SOURCE/backend/nivxforge/investigation/correlation_signals.py) | 6,840 | 187 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/investigation/customer_report.py`](../01_COMPLETE_SOURCE/backend/nivxforge/investigation/customer_report.py) | 30,880 | 749 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/investigation/evidence_classes.py`](../01_COMPLETE_SOURCE/backend/nivxforge/investigation/evidence_classes.py) | 11,411 | 248 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/investigation/evidence_priority.py`](../01_COMPLETE_SOURCE/backend/nivxforge/investigation/evidence_priority.py) | 3,407 | 83 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/investigation/graph.py`](../01_COMPLETE_SOURCE/backend/nivxforge/investigation/graph.py) | 5,754 | 119 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/investigation/incident_narrative_override.py`](../01_COMPLETE_SOURCE/backend/nivxforge/investigation/incident_narrative_override.py) | 3,781 | 112 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/investigation/ingress_gate.py`](../01_COMPLETE_SOURCE/backend/nivxforge/investigation/ingress_gate.py) | 8,950 | 208 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/investigation/input_understanding.py`](../01_COMPLETE_SOURCE/backend/nivxforge/investigation/input_understanding.py) | 12,133 | 291 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/investigation/ioc_classifier.py`](../01_COMPLETE_SOURCE/backend/nivxforge/investigation/ioc_classifier.py) | 6,689 | 214 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/investigation/models.py`](../01_COMPLETE_SOURCE/backend/nivxforge/investigation/models.py) | 5,991 | 115 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/investigation/narrative_lexicon_gate.py`](../01_COMPLETE_SOURCE/backend/nivxforge/investigation/narrative_lexicon_gate.py) | 7,406 | 178 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/investigation/osint_enricher.py`](../01_COMPLETE_SOURCE/backend/nivxforge/investigation/osint_enricher.py) | 19,589 | 491 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/investigation/pipeline/__init__.py`](../01_COMPLETE_SOURCE/backend/nivxforge/investigation/pipeline/__init__.py) | 475 | 11 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/investigation/pipeline/artifact_discovery.py`](../01_COMPLETE_SOURCE/backend/nivxforge/investigation/pipeline/artifact_discovery.py) | 3,876 | 99 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/investigation/pipeline/attack_chain_builder.py`](../01_COMPLETE_SOURCE/backend/nivxforge/investigation/pipeline/attack_chain_builder.py) | 20,724 | 518 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/investigation/pipeline/cem_parity.py`](../01_COMPLETE_SOURCE/backend/nivxforge/investigation/pipeline/cem_parity.py) | 20,218 | 505 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/investigation/pipeline/composite_extractor.py`](../01_COMPLETE_SOURCE/backend/nivxforge/investigation/pipeline/composite_extractor.py) | 5,939 | 173 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/investigation/pipeline/contract_check.py`](../01_COMPLETE_SOURCE/backend/nivxforge/investigation/pipeline/contract_check.py) | 7,736 | 238 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/investigation/pipeline/correlation_engine.py`](../01_COMPLETE_SOURCE/backend/nivxforge/investigation/pipeline/correlation_engine.py) | 14,035 | 378 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/investigation/pipeline/entity_resolution.py`](../01_COMPLETE_SOURCE/backend/nivxforge/investigation/pipeline/entity_resolution.py) | 14,019 | 365 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/investigation/pipeline/evidence_extraction.py`](../01_COMPLETE_SOURCE/backend/nivxforge/investigation/pipeline/evidence_extraction.py) | 8,683 | 216 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/investigation/pipeline/evidence_validation.py`](../01_COMPLETE_SOURCE/backend/nivxforge/investigation/pipeline/evidence_validation.py) | 6,160 | 165 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/investigation/pipeline/graph_builder.py`](../01_COMPLETE_SOURCE/backend/nivxforge/investigation/pipeline/graph_builder.py) | 13,728 | 352 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/investigation/pipeline/graph_visualise.py`](../01_COMPLETE_SOURCE/backend/nivxforge/investigation/pipeline/graph_visualise.py) | 8,193 | 222 | `implementation` | `PRE_EXISTING` |

*... and 139 more files. Refer to [`EDR_MANIFEST.json`](./EDR_MANIFEST.json) for the exhaustive JSON catalog.*
