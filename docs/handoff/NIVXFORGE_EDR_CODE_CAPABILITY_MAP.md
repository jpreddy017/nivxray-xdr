# NIVXFORGE EDR: CODE-TO-CAPABILITY REPOSITORY MAP
**Authoritative Directory Grounding, File Paths, Module Mappings, and Emergent Action Directives**  
**Document ID:** `NIVXFORGE-CODE-MAP-2026-09-05`  
**Classification:** Governing Engineering Handoff Pack  
**Handoff Status:** 🟢 APPROVED & READY FOR EMERGENT INTEGRATION REVIEW  

---

## 1. Executive Statement

To prevent duplicate engineering or accidental re-implementation of **NivXRay Core**, this document maps every functional capability to its exact repository location, Python/JavaScript module, API route, and frontend component, establishing the explicit action directive for **Emergent**:

* **REUSE AS-IS**: Mature, verified production components that must not be altered.
* **INTEGRATE**: Existing backend engines or scaffolds that require direct wiring to incoming EDR/Sandbox telemetry.
* **EXTEND STREAMING**: Real-time streaming extensions to existing historical analysis components.
* **BUILD**: New operational components (Sensors, Drivers, Hypervisor Runners) to be implemented in Phases 1–4.

---

## 2. Master Code-to-Capability Truth Table

| Capability Area | Exact Repository File Path | Module / Symbol / Class | Primary API Route | Frontend Component | Current Truth | Emergent Action Directive |
|---|---|---|---|---|---|---|
| **Incremental Knowledge Graph (IKG)** | `backend/routers/attack_graph.py`<br>`backend/routers/attack_story.py` | `router`<br>`get_attack_graph`<br>`get_attack_story` | `GET /api/v2/attack-graph/:caseId`<br>`GET /api/v2/attack-story/:caseId` | `apps/nivxray-xdr/src/xdr/investigation/EvidenceFirstInvestigationWorkspace.jsx` (Tab 6) | `IMPLEMENTED` | **REUSE AS-IS**<br>Do not build parallel graph engine. |
| **Deterministic Verdict Engine** | `backend/routers/verdict_stage2.py`<br>`backend/reasoning/engine.py` | `compute_stage2_verdict`<br>`ReasoningEngine` | `GET /api/v2/verdict/:caseId`<br>`POST /api/v2/analyze` | `apps/nivxray-xdr/src/xdr/pages/XdrInvestigationWorkspacePage.jsx` (Tab 7) | `IMPLEMENTED` | **REUSE AS-IS**<br>Preserve deterministic calculation. |
| **Authoritative Security State** | `backend/security_state/contracts.py`<br>`backend/security_state/detection_bridge.py` | `SecurityState`<br>`evaluate_security_state` | `GET /v2/security-state/:id`<br>`POST /v2/security-state/evaluate` | `apps/nivxray-xdr/src/xdr/pages/XdrInvestigationWorkspacePage.jsx` (Tab 5) | `IMPLEMENTED` | **REUSE & INTEGRATE**<br>Wire directly to telemetry events. |
| **59-Decoder Deobfuscator** | `backend/decoders/`<br>`backend/routers/analyze.py` | `DecoderRegistry`<br>`CanonicalRecoveryPipeline` | `POST /api/decode/smart`<br>`POST /api/v2/analyze` | `frontend/src/pages/AnalystWorkspacePage.jsx`<br>`DecodingTracePanel.jsx` | `IMPLEMENTED` (59 active codecs) | **REUSE AS-IS**<br>Consume dropped sandbox files. |
| **615 Content Fabric** | `backend/detection_content/`<br>`backend/routers/xdr_detection_content.py` | `ContentRegistry`<br>`RuleStudioEngine` | `GET /api/v2/detection-content/rules`<br>`POST /api/v2/rules/test` | `frontend/src/pages/ModelStudioPage.jsx` | `IMPLEMENTED` (615 active-certified) | **REUSE AS-IS**<br>Target rules against EDR events. |
| **Evidence Explorer** | `apps/nivxray-xdr/src/xdr/pages/XdrEvidenceExplorerPage.jsx`<br>`backend/routers/artifacts.py` | `XdrEvidenceExplorerPage`<br>`artifacts_router` | `GET /api/v2/artifacts`<br>`GET /api/v2/artifacts/:id` | `apps/nivxray-xdr/src/xdr/pages/XdrEvidenceExplorerPage.jsx` | `IMPLEMENTED` (Truth Audited) | **REUSE AS-IS**<br>Bind EDR/Sandbox evidence. |
| **Investigation Workspace** | `apps/nivxray-xdr/src/xdr/pages/XdrInvestigationWorkspacePage.jsx`<br>`backend/routers/investigations.py` | `XdrInvestigationWorkspacePage`<br>`investigations_router` | `GET /api/v2/investigations/:caseId`<br>`POST /api/v2/investigations` | `apps/nivxray-xdr/src/xdr/pages/XdrInvestigationWorkspacePage.jsx` | `IMPLEMENTED` (Truth Audited) | **REUSE AS-IS**<br>Preserve 8-stage causal tabs. |
| **Identity Understanding (IUE)** | `backend/routers/iue_lane_a.py`<br>`backend/routers/iue_lane_b.py`<br>`backend/routers/iue_lane_c.py` | `iue_lane_a_router`<br>`iue_lane_b_router`<br>`iue_lane_c_router` | `GET /api/v2/iue/lanes/a`<br>`GET /api/v2/iue/timeline` | `frontend/src/pages/IEDDETracePage.jsx` | `IMPLEMENTED` | **REUSE AS-IS**<br>Feed endpoint identity tokens. |
| **Correlation Engine (ICE)** | `backend/routers/correlations.py`<br>`backend/routers/xdr_correlation.py` | `correlations_router`<br>`CorrelationEngine` | `GET /api/v2/correlations`<br>`POST /api/v2/correlate` | `apps/nivxray-xdr/src/components/incidents/` | `IMPLEMENTED` | **REUSE AS-IS**<br>Correlate multi-host EDR signals. |
| **Device Trajectory** | `backend/routers/timeline.py`<br>`frontend/src/pages/DeviceTrajectoryPage.jsx` | `timeline_router`<br>`DeviceTrajectoryPage` | `GET /api/v2/endpoints/:id/timeline`<br>`GET /api/v2/trajectory` | `docs/uiux/NIVXFORGE_EDR_SANDBOX_OPERATIONAL_PROTOTYPE.html` (Surface 8) | `PARTIAL` | **EXTEND STREAMING**<br>Build 5-lane microsecond replay. |
| **Process Tree / Ancestry** | `backend/routers/process_tree.py` | `process_tree_router`<br>`build_ancestry_graph` | `GET /api/v2/endpoints/:id/process-tree` | `docs/uiux/NIVXFORGE_EDR_SANDBOX_OPERATIONAL_PROTOTYPE.html` (Surface 9) | `SCAFFOLD` | **EXTEND STREAMING**<br>Add real-time parent-child links. |
| **Response Framework** | `apps/nivxray-xdr-response/main.py`<br>`backend/routers/xdr_cortex_actions.py` | `ResponseManager`<br>`xdr_cortex_router` | `POST /api/v2/response/actions`<br>`GET /api/v2/response/ledger` | `docs/uiux/NIVXFORGE_EDR_SANDBOX_OPERATIONAL_PROTOTYPE.html` (Surface 25) | `PARTIAL` | **INTEGRATE DRIVERS**<br>Connect to kernel isolation. |
| **NivXForge EDR Console** | `apps/nivxray-xdr/src/nivxforge/NivXForgeConsole.jsx`<br>`apps/nivxray-xdr/src/nivxforge/edrApi.js` | `NivXForgeConsole`<br>`edrApi` | `GET /api/v2/edr/endpoints`<br>`POST /api/v2/edr/commands` | `apps/nivxray-xdr/src/nivxforge/NivXForgeConsole.jsx` | `SCAFFOLD` | **REUSE & EXPAND**<br>Upgrade to full 37 surfaces. |
| **XDR Shell Navigation** | `apps/nivxray-xdr/src/xdr/XdrShell.jsx`<br>`apps/nivxray-xdr/src/xdr/capabilityRegistry.js` | `XdrShell`<br>`CAPABILITIES` | App Root Shell | `apps/nivxray-xdr/src/xdr/XdrShell.jsx` | `IMPLEMENTED` | **EXTEND ROUTES**<br>Register `/edr/*` and `/sandbox/*`. |
| **EDR Sensor Agent** | `[NEW] src/sensor/` (Rust/C++) | `NivXSensorDaemon`<br>`DriverMinifilter` | `POST /api/v2/edr/telemetry/stream` | N/A (Endpoint Binary) | `MISSING` | **BUILD (Phase 1)**<br>Cross-platform telemetry daemon. |
| **Dynamic Sandbox Host** | `[NEW] src/sandbox_runner/` (Python/Rust) | `SandboxOrchestrator`<br>`MicroVMLauncher` | `POST /api/v2/sandbox/detonate`<br>`GET /api/v2/sandbox/jobs/:id/trace` | `docs/uiux/NIVXFORGE_EDR_SANDBOX_OPERATIONAL_PROTOTYPE.html` (Group 7) | `MISSING` | **BUILD (Phase 4)**<br>Hardware-accelerated runner. |
| **Distributed Live Query** | `[NEW] backend/routers/edr_live_query.py` | `LiveQueryDispatcher`<br>`OsqueryManager` | `POST /api/v2/edr/fleet/live-query`<br>`GET /api/v2/edr/fleet/live-query/:id` | `docs/uiux/NIVXFORGE_EDR_SANDBOX_OPERATIONAL_PROTOTYPE.html` (Surface 20) | `MOCK` (Prototype) | **BUILD (Phase 3)**<br>Distributed SQL fleet dispatch. |
| **Host Isolation Driver** | `[NEW] src/sensor/isolation/` | `NdisPacketFilter`<br>`EbpfFirewall` | `POST /api/v2/edr/actions/isolate` | `docs/uiux/NIVXFORGE_EDR_SANDBOX_OPERATIONAL_PROTOTYPE.html` (Surface 26) | `MOCK` (Prototype) | **BUILD (Phase 1-4)**<br>Safety-gated network filter. |
| **Volatile Memory Dump** | `[NEW] src/sensor/memory/` | `PhysicalMemoryAcquirer` | `POST /api/v2/edr/actions/memory-dump` | `docs/uiux/NIVXFORGE_EDR_SANDBOX_OPERATIONAL_PROTOTYPE.html` (Surface 22) | `MISSING` | **BUILD (Phase 4)**<br>Kernel memory acquisition. |
| **Quarantine Vault** | `[NEW] src/sensor/quarantine/` | `EncryptedVaultDriver` | `POST /api/v2/edr/actions/quarantine` | `docs/uiux/NIVXFORGE_EDR_SANDBOX_OPERATIONAL_PROTOTYPE.html` (Surface 27) | `MISSING` | **BUILD (Phase 4)**<br>Encrypted `.nvxvault` storage. |

---

## 3. Implementation Guardrails for Emergent

1. **Strict Non-Interference**: Files under `backend/detection_content/` and `backend/decoders/` are strictly frozen. Emergent must not edit, rename, or delete existing rules or codecs.
2. **Deterministic Contract Preservation**: When ingesting new EDR telemetry or sandbox execution traces, data must be normalized to `backend/canonical/` schemas before passing to `backend/reasoning/`.
3. **Fail-Closed Verification**: The frontend components in `apps/nivxray-xdr/` must continue to display `NO AUTHORITATIVE EVIDENCE RECORDED` whenever backend evidence is empty or unreachable.
