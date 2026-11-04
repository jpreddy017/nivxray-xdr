# Investigation Workspace, Evidence Explorer, IKG & Deterministic Verdict

**Category Directory**: `06_INVESTIGATION_IKG_VERDICT/`  
**Authoritative Source Reference**: All source files referenced herein reside authoritatively in [`../01_COMPLETE_SOURCE/`](../01_COMPLETE_SOURCE/).  
**Total Associated Files**: 351 files  
**Total Category Size**: 3.49 MB  
**Total Lines of Code / Documentation**: 86,898 lines  

---

## Purpose & Scope

Analyst operational interfaces, dynamic investigation tabs 1-8, graph traversal, and two-stage deterministic verdict generation.

## Investigation Architecture & Phase 0 Hardening

NivXRay provides analysts with high-fidelity, fail-closed incident triage and deep causal investigation:

### Key Components:
1. **Investigation Workspace UI**: `apps/nivxray-xdr/src/xdr/pages/XdrInvestigationWorkspacePage.jsx` — 8 dynamically wired tabs:
   - Tab 1: Incident Overview & Deep Link Context
   - Tab 2: Threat Detection & IOC Correlation
   - Tab 3: Investigation Knowledge Graph (IKG) Interactive Graph
   - Tab 4: Canonical Timeline & Process Lineage
   - Tab 5: Authoritative Security State (fails closed when unrecorded)
   - Tab 6: Entity 360 & Blast Radius
   - Tab 7: Deterministic Verdict & Proof Tree (true evidence weights only)
   - Tab 8: Containment Playbooks & Response Safety Receipts
2. **Evidence Explorer UI**: `apps/nivxray-xdr/src/xdr/pages/XdrEvidenceExplorerPage.jsx` — Fast search, filtering, and inspection of raw and derived canonical artifacts.
3. **Investigation Backend**: `backend/v2/investigation/` — Case management, evidence hydration, and analyst notes.
4. **Investigation Knowledge Graph (IKG)**: `backend/v2/ikb/` & `services/attack_graph/` — Entity-relationship graph linking hosts, users, processes, network connections, and security states.
5. **Deterministic Verdict Engine**: `backend/v2/verdict/` & `services/verdict_stage2/` — Generates explainable verdict bands (`BENIGN`, `SUSPICIOUS`, `MALICIOUS`, `CRITICAL`) with mathematical proofs.


---

## Associated File Index (Authoritative Paths in `01_COMPLETE_SOURCE/`)

| Relative Source Path | Size (Bytes) | Lines | Type | Status |
| :--- | :---: | :---: | :---: | :---: |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr/src/components/incidents/tabs/InvestigationTab.jsx`](../01_COMPLETE_SOURCE/apps/nivxray-xdr/src/components/incidents/tabs/InvestigationTab.jsx) | 5,665 | 150 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr/src/xdr/admin/InvestigationLanes.jsx`](../01_COMPLETE_SOURCE/apps/nivxray-xdr/src/xdr/admin/InvestigationLanes.jsx) | 8,444 | 242 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr/src/xdr/investigation/AttackChainPanel.jsx`](../01_COMPLETE_SOURCE/apps/nivxray-xdr/src/xdr/investigation/AttackChainPanel.jsx) | 40,177 | 944 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr/src/xdr/investigation/EvidenceFirstInvestigationWorkspace.jsx`](../01_COMPLETE_SOURCE/apps/nivxray-xdr/src/xdr/investigation/EvidenceFirstInvestigationWorkspace.jsx) | 93,836 | 2,128 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr/src/xdr/investigation/InvestigationReportShell.jsx`](../01_COMPLETE_SOURCE/apps/nivxray-xdr/src/xdr/investigation/InvestigationReportShell.jsx) | 9,723 | 181 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr/src/xdr/investigation/ProcessTreePanel.jsx`](../01_COMPLETE_SOURCE/apps/nivxray-xdr/src/xdr/investigation/ProcessTreePanel.jsx) | 31,278 | 773 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr/src/xdr/investigation/ScenarioIntelligencePanel.jsx`](../01_COMPLETE_SOURCE/apps/nivxray-xdr/src/xdr/investigation/ScenarioIntelligencePanel.jsx) | 13,267 | 291 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr/src/xdr/investigation/WorkspaceSelectionContext.jsx`](../01_COMPLETE_SOURCE/apps/nivxray-xdr/src/xdr/investigation/WorkspaceSelectionContext.jsx) | 4,438 | 124 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr/src/xdr/investigation/XdrCompletenessPanel.jsx`](../01_COMPLETE_SOURCE/apps/nivxray-xdr/src/xdr/investigation/XdrCompletenessPanel.jsx) | 5,557 | 138 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr/src/xdr/investigation/completeness.js`](../01_COMPLETE_SOURCE/apps/nivxray-xdr/src/xdr/investigation/completeness.js) | 5,333 | 132 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr/src/xdr/pages/XdrInvestigationWorkspacePage.jsx`](../01_COMPLETE_SOURCE/apps/nivxray-xdr/src/xdr/pages/XdrInvestigationWorkspacePage.jsx) | 58,988 | 1,104 | `implementation` | `MODIFIED_BY_AG` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr/src/xdr/pages/XdrInvestigationsListPage.jsx`](../01_COMPLETE_SOURCE/apps/nivxray-xdr/src/xdr/pages/XdrInvestigationsListPage.jsx) | 18,708 | 423 | `implementation` | `MODIFIED_BY_AG` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr/src/xdr/pages/incidents/record/tabs/AutoInvestigationTab.jsx`](../01_COMPLETE_SOURCE/apps/nivxray-xdr/src/xdr/pages/incidents/record/tabs/AutoInvestigationTab.jsx) | 14,014 | 311 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/xdr_investigation.py`](../01_COMPLETE_SOURCE/backend/detection_content/xdr_investigation.py) | 16,167 | 376 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/docs/features/auto_investigate.yaml`](../01_COMPLETE_SOURCE/backend/docs/features/auto_investigate.yaml) | 1,173 | 31 | `configuration` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/docs/features/investigation_timeline.yaml`](../01_COMPLETE_SOURCE/backend/docs/features/investigation_timeline.yaml) | 1,161 | 31 | `configuration` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/investigation_report.py`](../01_COMPLETE_SOURCE/backend/investigation_report.py) | 10,259 | 297 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/l2_investigation/ARCHITECTURE_COMPLIANCE.md`](../01_COMPLETE_SOURCE/backend/l2_investigation/ARCHITECTURE_COMPLIANCE.md) | 4,354 | 89 | `documentation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/l2_investigation/__init__.py`](../01_COMPLETE_SOURCE/backend/l2_investigation/__init__.py) | 1,944 | 70 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/l2_investigation/schemas.py`](../01_COMPLETE_SOURCE/backend/l2_investigation/schemas.py) | 7,893 | 234 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/l2_investigation/services/__init__.py`](../01_COMPLETE_SOURCE/backend/l2_investigation/services/__init__.py) | 1,398 | 45 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/l2_investigation/services/attack_story.py`](../01_COMPLETE_SOURCE/backend/l2_investigation/services/attack_story.py) | 4,834 | 147 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/l2_investigation/services/base.py`](../01_COMPLETE_SOURCE/backend/l2_investigation/services/base.py) | 1,462 | 54 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/l2_investigation/services/capability_explorer.py`](../01_COMPLETE_SOURCE/backend/l2_investigation/services/capability_explorer.py) | 1,401 | 48 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/l2_investigation/services/detection_rules.py`](../01_COMPLETE_SOURCE/backend/l2_investigation/services/detection_rules.py) | 1,010 | 36 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/l2_investigation/services/executive_summary.py`](../01_COMPLETE_SOURCE/backend/l2_investigation/services/executive_summary.py) | 9,217 | 276 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/l2_investigation/services/hunting_queries.py`](../01_COMPLETE_SOURCE/backend/l2_investigation/services/hunting_queries.py) | 942 | 35 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/l2_investigation/services/ioc_intelligence.py`](../01_COMPLETE_SOURCE/backend/l2_investigation/services/ioc_intelligence.py) | 1,150 | 37 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/l2_investigation/services/threat_assessment.py`](../01_COMPLETE_SOURCE/backend/l2_investigation/services/threat_assessment.py) | 1,484 | 51 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/l2_investigation/services/workspace_bundle.py`](../01_COMPLETE_SOURCE/backend/l2_investigation/services/workspace_bundle.py) | 2,005 | 53 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/l2_investigation/state.py`](../01_COMPLETE_SOURCE/backend/l2_investigation/state.py) | 4,850 | 149 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/l2_investigation/workspace_state.py`](../01_COMPLETE_SOURCE/backend/l2_investigation/workspace_state.py) | 4,475 | 130 | `implementation` | `PRE_EXISTING` |
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

*... and 291 more files. Refer to [`INVESTIGATION_IKG_VERDICT_MANIFEST.json`](./INVESTIGATION_IKG_VERDICT_MANIFEST.json) for the exhaustive JSON catalog.*
