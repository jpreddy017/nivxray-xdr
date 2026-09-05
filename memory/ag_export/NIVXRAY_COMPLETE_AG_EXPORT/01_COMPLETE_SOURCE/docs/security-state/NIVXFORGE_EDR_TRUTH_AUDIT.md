# NIVXFORGE EDR TRUTH AUDIT
**Forensic Technical Audit of Existing Endpoint Detection & Response Capabilities**
**Document ID:** `NIVXFORGE-EDR-TRUTH-AUDIT-2026-09-05`
**Status:** Canonical Reference · Read-Only Audit · Enterprise Baseline
**Rule:** NO EVIDENCE → NO CLAIM

---

## 1. Executive Summary & Forensic Scope

This document provides a forensic, read-only audit of the **NivXForge EDR** layer within the NivXRay XDR platform. It inspects all backend services, FastAPI routers, data models, transport connectors, response engines, and frontend console pages in `apps/nivxray-xdr/src/nivxforge/`.

### Core Architectural Finding
**NivXForge EDR is currently an Incident-Derived Analytical Projection & Response Orchestrator, not an autonomous host-agent EDR platform.**
1. **No Resident Host Agent**: There is no endpoint agent daemon, kernel driver (eBPF/minifilter), or local telemetry collector running on endpoints.
2. **Read-Only Case Projections**: Detections, Process Trees, and Device Trajectories are projected from saved incident cases (`workspace_cases.verdict_stage2.evidence[]` and `workspace_cases.ssot.timeline`), as confirmed by explicit backend comments in `backend/routers/edr.py`.
3. **Scaffolded Console Surfaces**: 6 of the 10 EDR console tabs (`files`, `network`, `hunting`, `forensics`, `live-query`, `response`) render reserved lock banners without backend data binding.
4. **Deterministic Simulation Stubs**: Response actions (endpoint isolation, process termination, file quarantine) run through an enterprise-grade orchestration pipeline (`apps/nivxray-xdr-response`) with real idempotency, audit logging, and authorization, but invoke deterministic simulation stubs (`_stub_ok`) or vendor API stubs with `real_vendor_call=False`.
5. **Solid Core Reasoning Assets**: The causal reasoning, process graph projection, 59-codec multi-stage decoder pipeline, 615-object Content Fabric, and Security State FSM are authoritative, deterministic, and 100% production-grade.

---

## 2. 23-Capability Forensic Audit

Each capability is classified into one of five forensic statuses:
* **`IMPLEMENTED`**: Production-backed code, active data source, real runtime execution, and verified UI binding.
* **`PARTIAL`**: Real logic or projection exists, but lacks live endpoint telemetry, agent execution, or complete sub-domain wiring.
* **`SCAFFOLD`**: UI shell or API contract exists, but explicitly renders a reserved placeholder or returns not-implemented.
* **`MOCK`**: Hardcoded sample data, fallback mock datasets, or synthetic arrays surfaced to the user.
* **`MISSING`**: No code, route, schema, or agent implementation exists in the codebase.

---

### 1. EDR Agent
* **Status:** `MISSING`
* **File / Module:** [adminMeta.js](file:///d:/Projects/apps/nivxray-xdr/src/xdr/admin/adminMeta.js#L88-L92), [EdrOverviewPage.jsx](file:///d:/Projects/apps/nivxray-xdr/src/nivxforge/pages/EdrOverviewPage.jsx#L43)
* **Route / API:** None (`api: null, connected: false`, integration: `"Agent management plane"`)
* **Authoritative Data Source:** None
* **Runtime-backed:** No
* **UI Binding:** `EdrOverviewPage.jsx` renders `<Stat label="Agent Status" value="Reserved · later slice" tone="faint" />`.
* **Evidence:** No agent binary, no service installer (MSI/deb/rpm), no Windows Service/systemd daemon, and no kernel telemetry hook (eBPF, Sysmon, ELAM) exists anywhere in the repository.

---

### 2. Endpoint Registration & Health
* **Status:** `PARTIAL`
* **File / Module:** [backend/routers/edr.py](file:///d:/Projects/backend/routers/edr.py#L198-L265), [apps/nivxray-xdr/src/xdr/pages/XdrEndpointsPage.jsx](file:///d:/Projects/apps/nivxray-xdr/src/xdr/pages/XdrEndpointsPage.jsx)
* **Route / API:** `GET /api/edr/endpoints`
* **Authoritative Data Source:** `workspace_cases.ssot.investigation_object`
* **Runtime-backed:** Yes (read-only query over MongoDB `workspace_cases`)
* **UI Binding:** Bound in `XdrEndpointsPage.jsx` via `listEndpoints()`
* **Evidence:** `edr.py` extracts hosts dynamically from saved cases:
  ```python
  # edr.py:262
  "note": "Read-only projection · endpoints are extracted from saved cases."
  ```
  There is no live agent enrollment handshake, mutual TLS authentication, or periodic endpoint heartbeat table.

---

### 3. Telemetry Ingestion
* **Status:** `PARTIAL`
* **File / Module:** [backend/routers/xdr_ingest.py](file:///d:/Projects/backend/routers/xdr_ingest.py#L41-L98), [backend/v2/routers/ingest.py](file:///d:/Projects/backend/v2/routers/ingest.py#L4-L23), [apps/nivxray-xdr-collector/main.py](file:///d:/Projects/apps/nivxray-xdr-collector/main.py)
* **Route / API:** `POST /api/xdr/ingest/telemetry`, `POST /api/v2/ingest/{format}`
* **Authoritative Data Source:** `xdr_canonical_events`, `xdr_collectors`, `xdr_data_sources`
* **Runtime-backed:** Yes (Collector service runs Syslog, Webhook, and REST pollers; ingest route enforces atomic counter gates)
* **UI Binding:** Wired to Admin Collectors & Ingestion Metrics.
* **Evidence:**
  - `POST /api/xdr/ingest/telemetry` receives `CanonicalEnvelope` from `nivxray-xdr-collector`.
  - `POST /api/v2/ingest/{format}` ingests JSON, NDJSON, Syslog, CSV, Webhook and extracts command lines into `v2.shadow`. Windows EVTX returns `501 Not Implemented` ([v2/routers/ingest.py:15](file:///d:/Projects/backend/v2/routers/ingest.py#L15)).
  - Generic transport exists, but continuous endpoint telemetry streaming (Process, File, Registry, Network, Memory) from an agent is absent.

---

### 4. Endpoint Detections
* **Status:** `PARTIAL`
* **File / Module:** [backend/routers/edr.py](file:///d:/Projects/backend/routers/edr.py#L48-L106,L176-L190), [EdrDetectionsPage.jsx](file:///d:/Projects/apps/nivxray-xdr/src/nivxforge/pages/EdrDetectionsPage.jsx#L44-L65)
* **Route / API:** `GET /api/edr/detections?incident_id=...`
* **Authoritative Data Source:** `workspace_cases.verdict_stage2.evidence[]`
* **Runtime-backed:** Yes (read-only projection of fired Stage-2 rules for an incident)
* **UI Binding:** Bound in `EdrDetectionsPage.jsx` via `listEdrDetections(incidentId)`
* **Evidence:** Confirmed in `backend/routers/edr.py`:
  ```python
  # edr.py:4
  "No native detections collection exists in the repository — we verified this by inspection.
   Therefore Detections is a READ-ONLY projection derived from workspace_cases.verdict_stage2.evidence[]."
  ```
  It projects rule hits from cases, but has no live endpoint event stream detection queue.

---

### 5. Process Tree
* **Status:** `IMPLEMENTED`
* **File / Module:** [backend/routers/edr.py](file:///d:/Projects/backend/routers/edr.py#L110-L165,L191-L196), [backend/v2/routers/ancestry.py](file:///d:/Projects/backend/v2/routers/ancestry.py), [EdrProcessTreePage.jsx](file:///d:/Projects/apps/nivxray-xdr/src/nivxforge/pages/EdrProcessTreePage.jsx#L20-L42), [ProcessTreeView.jsx](file:///d:/Projects/apps/nivxray-xdr/src/xdr/pages/incidents/record/tabs/attack_graph/ProcessTreeView.jsx)
* **Route / API:** `GET /api/edr/process-tree?incident_id=...`, `GET /api/v2/cases/{case_id}/ancestry`
* **Authoritative Data Source:** `services.activity.ActivityInventory` (via `workspace_cases.ssot.timeline`)
* **Runtime-backed:** Yes (constructs parent-to-child process hierarchy with deterministic entity IDs)
* **UI Binding:** Bound in `EdrProcessTreePage.jsx` and Incident `ProcessTreeView.jsx` with active pivots to `/edr/trajectory` and `/analyze`.
* **Evidence:** Traverses `parent_entity_id` and `child_entity_ids` without AI hallucination. In `XdrInvestigationWorkspacePage.jsx` Tab 3, static sample HTML was used, but the underlying engine and `EdrProcessTreePage` are fully functional and live-bound.

---

### 6. Device Trajectory
* **Status:** `IMPLEMENTED`
* **File / Module:** [backend/routers/edr.py](file:///d:/Projects/backend/routers/edr.py#L267-L435), [backend/v2/routers/trajectory.py](file:///d:/Projects/backend/v2/routers/trajectory.py), [XdrDeviceTrajectoryPage.jsx](file:///d:/Projects/apps/nivxray-xdr/src/xdr/pages/XdrDeviceTrajectoryPage.jsx#L74-L92)
* **Route / API:** `GET /api/edr/device-trajectory?device=...&hours=...`, `GET /api/v2/cases/{case_id}/trajectory/device`
* **Authoritative Data Source:** `workspace_cases` + `services.activity.ActivityInventory`
* **Runtime-backed:** Yes (aggregates detection markers and activity across 5 chronological lanes: system, process, file, network, registry)
* **UI Binding:** Fully bound in `XdrDeviceTrajectoryPage.jsx` with interactive 3-pane SVG canvas (`TrajectoryTimelineCanvas.jsx`), lane filters, and time windows (1h, 6h, 12h, 24h, 3d, 7d).
* **Evidence:** Real timeline event generation and lane counts. Note: It aggregates events from saved incident cases; it is not a streaming live endpoint ring buffer.

---

### 7. Files (Endpoint Filesystem Monitoring)
* **Status:** `SCAFFOLD`
* **File / Module:** [EdrReservedPages.jsx](file:///d:/Projects/apps/nivxray-xdr/src/nivxforge/pages/EdrReservedPages.jsx#L25-L31), [EdrOverviewPage.jsx](file:///d:/Projects/apps/nivxray-xdr/src/nivxforge/pages/EdrOverviewPage.jsx#L22)
* **Route / API:** None (`GET /edr/files` is frontend-only)
* **Authoritative Data Source:** None
* **Runtime-backed:** No
* **UI Binding:** Renders `EdrFilesPage` with:
  ```jsx
  <ReservedPage tabKey="files" heading="Files" body="File-system evidence observed by the endpoint agent: writes, drops, signers, hashes... Arrives in a later slice." />
  ```
* **Evidence:** No endpoint file inventory, file change journal, or remote directory browsing API exists.

---

### 8. Network Connections (Endpoint Sockets / DNS)
* **Status:** `SCAFFOLD`
* **File / Module:** [EdrReservedPages.jsx](file:///d:/Projects/apps/nivxray-xdr/src/nivxforge/pages/EdrReservedPages.jsx#L32-L38), [EdrOverviewPage.jsx](file:///d:/Projects/apps/nivxray-xdr/src/nivxforge/pages/EdrOverviewPage.jsx#L24)
* **Route / API:** None (`GET /edr/network` is frontend-only)
* **Authoritative Data Source:** None
* **Runtime-backed:** No
* **UI Binding:** Renders `EdrNetworkPage` with:
  ```jsx
  <ReservedPage tabKey="network" heading="Network" body="Endpoint-observed connections + DNS, with process attribution... Arrives in a later slice." />
  ```
* **Evidence:** Network IOCs exist only as extracted artifacts from case decoders; live endpoint socket tables (`netstat`/eBPF sockstat) are absent.

---

### 9. Threat Hunting
* **Status:** `SCAFFOLD`
* **File / Module:** [EdrReservedPages.jsx](file:///d:/Projects/apps/nivxray-xdr/src/nivxforge/pages/EdrReservedPages.jsx#L39-L45)
* **Route / API:** None (`GET /edr/hunting` is frontend-only)
* **Authoritative Data Source:** None
* **Runtime-backed:** No
* **UI Binding:** Renders `EdrHuntingPage` ("Reserved · later slice").
* **Evidence:** XDR Rule Studio (`/xdr/admin/rule-studio`) searches detection rules and historical cases, but there is no distributed endpoint fleet query engine.

---

### 10. Forensics (Remote Host Acquisition)
* **Status:** `SCAFFOLD`
* **File / Module:** [EdrReservedPages.jsx](file:///d:/Projects/apps/nivxray-xdr/src/nivxforge/pages/EdrReservedPages.jsx#L46-L52), [apps/nivxray-xdr-response/framework/adapters.py](file:///d:/Projects/apps/nivxray-xdr-response/framework/adapters.py#L35,L83-L87)
* **Route / API:** `ActionSpec("endpoint.collect_forensics", ...)`
* **Authoritative Data Source:** None
* **Runtime-backed:** No (`endpoint_collect_forensics` invokes `_stub_ok`)
* **UI Binding:** Renders `EdrForensicsPage` ("Reserved · later slice").
* **Evidence:** No live forensic disk/registry triage collector exists.

---

### 11. Live Query (osquery / Scheduled Queries)
* **Status:** `SCAFFOLD`
* **File / Module:** [EdrReservedPages.jsx](file:///d:/Projects/apps/nivxray-xdr/src/nivxforge/pages/EdrReservedPages.jsx#L53-L59), [apps/nivxray-xdr-response/framework/adapters.py](file:///d:/Projects/apps/nivxray-xdr-response/framework/adapters.py#L36,L88-L93)
* **Route / API:** `ActionSpec("endpoint.live_query", ...)`
* **Authoritative Data Source:** None
* **Runtime-backed:** No (`endpoint_live_query` invokes `_stub_ok`)
* **UI Binding:** Renders `EdrLiveQueryPage` ("Reserved · later slice").
* **Evidence:** osquery fleet manager / TLS endpoint live-query daemon is absent.

---

### 12. Response Actions Framework
* **Status:** `IMPLEMENTED`
* **File / Module:** [apps/nivxray-xdr-response/framework/executor.py](file:///d:/Projects/apps/nivxray-xdr-response/framework/executor.py), [apps/nivxray-xdr-response/framework/registry.py](file:///d:/Projects/apps/nivxray-xdr-response/framework/registry.py), [backend/routers/xdr_response_evidence.py](file:///d:/Projects/backend/routers/xdr_response_evidence.py), [apps/nivxray-xdr/src/xdr/respond/AnalystResponseDrawer.jsx](file:///d:/Projects/apps/nivxray-xdr/src/xdr/respond/AnalystResponseDrawer.jsx)
* **Route / API:** `POST /api/respond/execute`, `GET /api/respond/actions`, `POST /api/xdr/response/evidence`
* **Authoritative Data Source:** SQLite `executions.db` + MongoDB `xdr_response_evidence`
* **Runtime-backed:** Yes (full lifecycle engine: `REQUESTED → APPROVED → EXECUTING → SUCCEEDED/FAILED → VERIFIED`)
* **UI Binding:** Fully bound in `AnalystResponseDrawer.jsx` and Incident Record header `Respond` action button.
* **Evidence:** Idempotency enforcement, RBAC permission checking (`endpoint:isolate`, `endpoint:kill`), audit forwarding, and timeline integration are fully operational. However, the adapters executing underneath are stubs.

---

### 13. Endpoint Isolation
* **Status:** `PARTIAL`
* **File / Module:** [apps/nivxray-xdr-response/framework/adapters.py](file:///d:/Projects/apps/nivxray-xdr-response/framework/adapters.py#L32,L66-L70), [apps/nivxray-xdr-response/framework/vendor_adapters.py](file:///d:/Projects/apps/nivxray-xdr-response/framework/vendor_adapters.py#L217-L238), [AnalystResponseDrawer.jsx](file:///d:/Projects/apps/nivxray-xdr/src/xdr/respond/AnalystResponseDrawer.jsx)
* **Route / API:** `POST /api/respond/execute` with `action_id: "endpoint.isolate"`
* **Authoritative Data Source:** Response Execution Store
* **Runtime-backed:** Partial (orchestration, approval flow, and audit trail are real; endpoint action is simulation stub)
* **UI Binding:** Selectable in `AnalystResponseDrawer.jsx`. `EdrOverviewPage.jsx` hardcodes `<Stat label="Isolation" value="Not isolated" tone="mint" />`.
* **Evidence:**
  - `endpoint_isolate()` returns `_stub_ok()` with `simulation_only: True`.
  - `CrowdStrikeAdapter._do_isolate_endpoint` has `real_vendor_call=False`; when set to True, returns `not_wired_yet`.
  - No native host isolation driver (WFP/iptables) exists.

---

### 14. File Quarantine
* **Status:** `SCAFFOLD / MOCK`
* **File / Module:** [apps/nivxray-xdr-response/framework/adapters.py](file:///d:/Projects/apps/nivxray-xdr-response/framework/adapters.py#L34,L77-L82)
* **Route / API:** `POST /api/respond/execute` with `action_id: "endpoint.quarantine_file"`
* **Authoritative Data Source:** None
* **Runtime-backed:** No (`endpoint_quarantine_file` invokes `_stub_ok`)
* **UI Binding:** Registered in response action registry; no agent quarantine vault on disk.
* **Evidence:** Simulation stub only.

---

### 15. Evidence Collection
* **Status:** `PARTIAL`
* **File / Module:** [backend/v2/routers/artifacts.py](file:///d:/Projects/backend/v2/routers/artifacts.py#L1-L100), [backend/routers/artifacts.py](file:///d:/Projects/backend/routers/artifacts.py), [EvidenceTab.jsx](file:///d:/Projects/apps/nivxray-xdr/src/xdr/pages/incidents/record/tabs/EvidenceTab.jsx), [XdrEvidenceExplorerPage.jsx](file:///d:/Projects/apps/nivxray-xdr/src/xdr/pages/XdrEvidenceExplorerPage.jsx)
* **Route / API:** `GET /api/v2/cases/{case_id}/artifacts`, `GET /artifacts`
* **Authoritative Data Source:** `v2_cases` artifact sub-documents, `workspace_cases.ssot`
* **Runtime-backed:** Yes (retrieves artifacts parsed during case ingestion)
* **UI Binding:** Bound in Incident `EvidenceTab.jsx`. In `XdrEvidenceExplorerPage.jsx`, falls back to `SAMPLE_ARTIFACTS` when cases have no dynamic artifacts.
* **Evidence:** Extracts artifacts from submitted case payloads; does not perform remote live endpoint pulling.

---

### 16. Memory / Volatile Evidence
* **Status:** `MISSING`
* **File / Module:** None
* **Route / API:** None
* **Authoritative Data Source:** None
* **Runtime-backed:** No
* **UI Binding:** None
* **Evidence:** Detection rules detect LSASS dump attempts from event logs (Sysmon 10 / Security 4663), but zero volatile memory capture or RAM analysis tools exist.

---

### 17. Artifact Collection & Intermediate Payload Retention
* **Status:** `IMPLEMENTED`
* **File / Module:** [backend/v2/investigation/rte/](file:///d:/Projects/backend/v2/investigation/rte/), [backend/v2/routers/artifacts.py](file:///d:/Projects/backend/v2/routers/artifacts.py#L30-L80)
* **Route / API:** `GET /api/v2/cases/{case_id}/artifacts`
* **Authoritative Data Source:** Runtime Transformation Engine (RTE)
* **Runtime-backed:** Yes (retains intermediate decoded payloads up to 64KB per transformation stage with SHA-256 hashes and stop reasons)
* **UI Binding:** Displayed in `XdrEvidenceExplorerPage.jsx` drawer and Investigation Workspace Tab 6.
* **Evidence:** Cryptographic hash chains are computed and persisted across all deobfuscation stages.

---

### 18. Hash & Reputation Intelligence
* **Status:** `PARTIAL`
* **File / Module:** [backend/routers/ioc_intelligence.py](file:///d:/Projects/backend/routers/ioc_intelligence.py), [backend/routers/threat_intel.py](file:///d:/Projects/backend/routers/threat_intel.py), [backend/services/die](file:///d:/Projects/backend/services/die)
* **Route / API:** `GET /api/ioc/...`, `GET /api/threat-intel/...`
* **Authoritative Data Source:** Local IOC database, CISA KEV feeds, VirusTotal/OSINT integration in `services/die`
* **Runtime-backed:** Yes
* **UI Binding:** Bound in `XdrRecommendationsPanel.jsx` and Incident metadata. Main sidebar items (`Threat Intelligence`, `IOC Intelligence`) are reserved in `XdrShell.jsx`.
* **Evidence:** Backend IOC evaluation exists, but dedicated XDR Threat Intelligence planes are marked reserved.

---

### 19. Existing Static Malware Analysis
* **Status:** `IMPLEMENTED`
* **File / Module:** [backend/services/ida/artifact_splitter.py](file:///d:/Projects/backend/services/ida/artifact_splitter.py), [backend/services/uaie](file:///d:/Projects/backend/services/uaie), [backend/v2/semantic/ps_deobfuscate.py](file:///d:/Projects/backend/v2/semantic/ps_deobfuscate.py), [backend/decoders/](file:///d:/Projects/backend/decoders/)
* **Route / API:** `POST /api/v2/semantic/deobfuscate`, `GET /api/uaie/catalog`
* **Authoritative Data Source:** UAIE catalog, IDA artifact splitter, semantic AST engines
* **Runtime-backed:** Yes (extracts PE headers, magic bytes `MZ/ELF/PK/PDF`, PowerShell AST deobfuscation, batch concat unpackers, malware family decoders)
* **UI Binding:** Bound in `XdrEvidenceRefPage.jsx` and Evidence Tab.
* **Evidence:** Fully deterministic static extraction with zero AI guessing.

---

### 20. Existing Decoder Integration
* **Status:** `IMPLEMENTED`
* **File / Module:** [backend/decoders/registry.py](file:///d:/Projects/backend/decoders/registry.py), [backend/decoders/](file:///d:/Projects/backend/decoders/)
* **Route / API:** `POST /api/decode`, `GET /api/decode/guidance`
* **Authoritative Data Source:** `DecoderRegistry` (59 active registered codecs)
* **Runtime-backed:** Yes (48 logical codecs + 14 family profilers; 59/59 test pass in audit)
* **UI Binding:** Verified in decoder UI tests and Evidence Explorer.
* **Evidence:** Audited and reconciled in `ENTERPRISE_CONTENT_TRUTH_AUDIT.md` with zero contradictions.

---

### 21. Existing YARA & Content Engine Integration
* **Status:** `IMPLEMENTED`
* **File / Module:** [backend/detection_content/yara_engine.py](file:///d:/Projects/backend/detection_content/yara_engine.py), [backend/yara_export.py](file:///d:/Projects/backend/yara_export.py), [backend/detection_content/corpus/](file:///d:/Projects/backend/detection_content/corpus/)
* **Route / API:** `GET /cases/{id}/yara`, Content Fabric evaluation harness
* **Authoritative Data Source:** 615-object Content Fabric (600 active certified + 15 synthetic validation scenarios)
* **Runtime-backed:** Yes (evaluates content signature rules across corpus; exports valid YARA rules from case evidence)
* **UI Binding:** Bound in Case export and Rule Studio.
* **Evidence:** Confirmed across 16 native content runtimes.

---

### 22. Existing IKG / Investigation Integration
* **Status:** `IMPLEMENTED`
* **File / Module:** [backend/services/ikg/](file:///d:/Projects/backend/services/ikg/), [backend/v2/routers/investigation.py](file:///d:/Projects/backend/v2/routers/investigation.py), [XdrInvestigationsListPage.jsx](file:///d:/Projects/apps/nivxray-xdr/src/xdr/pages/XdrInvestigationsListPage.jsx), [XdrInvestigationWorkspacePage.jsx](file:///d:/Projects/apps/nivxray-xdr/src/xdr/pages/XdrInvestigationWorkspacePage.jsx)
* **Route / API:** `GET /api/v2/cases/{case_id}/investigation?profile=soc_balanced`
* **Authoritative Data Source:** Investigation Knowledge Graph (IKG)
* **Runtime-backed:** Yes (constructs node-link causal graph linking host, user, process, file, socket, and MITRE techniques)
* **UI Binding:** Fully bound to `/xdr/investigations` and `/xdr/investigations/:caseId`.
* **Evidence:** Validated in P0 routes.

---

### 23. Existing Security State Integration
* **Status:** `IMPLEMENTED`
* **File / Module:** [backend/routers/rc5_entities.py](file:///d:/Projects/backend/routers/rc5_entities.py), [backend/routers/rc5_diag.py](file:///d:/Projects/backend/routers/rc5_diag.py), [backend/routers/xdr_audit_log.py](file:///d:/Projects/backend/routers/xdr_audit_log.py), [backend/routers/verdict_stage2.py](file:///d:/Projects/backend/routers/verdict_stage2.py)
* **Route / API:** `GET /api/rc5/entities`, `GET /api/v2/verdicts/{case_id}`
* **Authoritative Data Source:** Security State Computing FSM & Cryptographic Audit Ledger
* **Runtime-backed:** Yes (computes deterministic state transitions: `AUTHORIZED_ADMIN → SUSPICIOUS_UNMANAGED → ABUSED_CAPABILITY → CONFIRMED_ATTACK`)
* **UI Binding:** Rendered in Investigation Workspace Tab 5 and incident headers.
* **Evidence:** Authoritative engine core without AI hallucination.

---

## 3. Comprehensive Capability Matrix

| # | Capability | Current Status | Evidence / Code Location | Reusable | Extension Required | Missing Elements | Priority |
|---|---|---|---|---|---|---|---|
| 1 | **EDR Agent** | `MISSING` | `adminMeta.js:88`, `EdrOverviewPage.jsx:43` | No | None | Agent daemon, kernel hooks, TLS enrollment | **P0** |
| 2 | **Endpoint Registration/Health** | `PARTIAL` | `backend/routers/edr.py:198` (`GET /edr/endpoints`) | Yes (query) | Dynamic registration API | Heartbeat table, enrollment token, health daemon | **P1** |
| 3 | **Telemetry Ingestion** | `PARTIAL` | `xdr_ingest.py`, `v2/routers/ingest.py`, `nivxray-xdr-collector` | Yes (collectors) | Real-time endpoint event schemas | Process/file/net streaming adapters | **P0** |
| 4 | **Endpoint Detections** | `PARTIAL` | `backend/routers/edr.py:48` (`GET /edr/detections`) | Yes (projection) | Real-time streaming evaluation | Agent detection loop, live event alerting | **P1** |
| 5 | **Process Tree** | `IMPLEMENTED` | `backend/routers/edr.py:110`, `v2/ancestry.py`, `EdrProcessTreePage.jsx` | Yes (100%) | None | Live real-time process monitoring | **P2** |
| 6 | **Device Trajectory** | `IMPLEMENTED` | `backend/routers/edr.py:267`, `XdrDeviceTrajectoryPage.jsx` | Yes (100%) | None | Live endpoint event streaming | **P2** |
| 7 | **Files Monitoring** | `SCAFFOLD` | `EdrReservedPages.jsx:25` (`EdrFilesPage`) | No | Full backend file API | FIM engine, remote file reader | **P1** |
| 8 | **Network Connections** | `SCAFFOLD` | `EdrReservedPages.jsx:32` (`EdrNetworkPage`) | No | Full socket API | Live socket table, endpoint DNS resolution | **P1** |
| 9 | **Threat Hunting** | `SCAFFOLD` | `EdrReservedPages.jsx:39` (`EdrHuntingPage`) | No | Fleet query coordinator | Distributed query engine (osquery/eBPF) | **P2** |
| 10 | **Forensics Acquisition** | `SCAFFOLD` | `EdrReservedPages.jsx:46`, `response/adapters.py:35` | No | Forensic capture service | Disk snapshot, MFT/prefetch acquisition | **P2** |
| 11 | **Live Query** | `SCAFFOLD` | `EdrReservedPages.jsx:53`, `response/adapters.py:36` | No | Live query coordinator | osquery agent integration | **P2** |
| 12 | **Response Framework** | `IMPLEMENTED` | `apps/nivxray-xdr-response/`, `AnalystResponseDrawer.jsx` | Yes (100%) | Real endpoint drivers | Replaces simulation stubs | **P0** |
| 13 | **Endpoint Isolation** | `PARTIAL` | `response/adapters.py:32`, `vendor_adapters.py:217` | Yes (orchestration) | Real network isolation driver | WFP/iptables driver or vendor live call | **P0** |
| 14 | **File Quarantine** | `SCAFFOLD` | `response/adapters.py:34` (`_stub_ok`) | Yes (orchestration) | Local quarantine vault | Agent file isolator & hash catalog | **P1** |
| 15 | **Evidence Collection** | `PARTIAL` | `backend/v2/routers/artifacts.py`, `EvidenceTab.jsx` | Yes (case store) | Endpoint file retrieval | Live remote artifact fetch | **P1** |
| 16 | **Memory / Volatile Evidence** | `MISSING` | No files | No | Complete acquisition plane | RAM acquisition driver (procdump/WinPmem) | **P2** |
| 17 | **Artifact Retention (64KB)** | `IMPLEMENTED` | `backend/v2/investigation/rte/`, `v2/artifacts.py` | Yes (100%) | None | None | **Done** |
| 18 | **Hash / Reputation Intel** | `PARTIAL` | `backend/routers/ioc_intelligence.py`, `services/die` | Yes (core) | Dedicated XDR UI pages | Real-time hash lookup streaming | **P1** |
| 19 | **Static Malware Analysis** | `IMPLEMENTED` | `backend/services/ida/`, `backend/services/uaie/` | Yes (100%) | None | None | **Done** |
| 20 | **Decoder Integration (59)** | `IMPLEMENTED` | `backend/decoders/registry.py` (59 codecs) | Yes (100%) | None | None | **Done** |
| 21 | **YARA / Content Engine** | `IMPLEMENTED` | `yara_engine.py`, `yara_export.py`, 615 corpus | Yes (100%) | None | None | **Done** |
| 22 | **IKG / Investigation** | `IMPLEMENTED` | `backend/services/ikg/`, `v2/investigation.py` | Yes (100%) | Sub-tab dynamic binding | None | **Done** |
| 23 | **Security State FSM** | `IMPLEMENTED` | `backend/routers/rc5_entities.py`, `verdict_stage2.py` | Yes (100%) | None | None | **Done** |

---

## 4. Explicit Findings: Mock, Fallback & Simulated Implementations

1. **`SAMPLE_ARTIFACTS` Fallback in Evidence Explorer**:
   - In `apps/nivxray-xdr/src/xdr/pages/XdrEvidenceExplorerPage.jsx` lines 27–113:
     5 hardcoded sample artifacts are embedded in the code.
     Lines 116, 166: If `/api/v2/cases` has no dynamic artifacts, the UI falls back to `SAMPLE_ARTIFACTS` instead of rendering an honest empty state.
2. **Hardcoded Fallbacks in Investigation Workspace**:
   - In `apps/nivxray-xdr/src/xdr/pages/XdrInvestigationWorkspacePage.jsx` lines 104–126:
     When falling back to `/api/incidents/:id`, 3 hardcoded attack story steps and 3 explainability reasons are injected.
   - Tabs 2, 3, 5, 6, 7, 8 contain hardcoded structural demonstration data rather than dynamic API binding.
3. **Deterministic Simulation Stubs in Response Engine**:
   - In `apps/nivxray-xdr-response/framework/adapters.py` lines 20–28:
     Every endpoint response action (`endpoint.isolate`, `endpoint.kill_process`, `endpoint.quarantine_file`, `endpoint.collect_forensics`, `endpoint.live_query`) returns:
     ```python
     {"ok": True, "result": {"stub": True, "params": params, "adapter_version": "phase1.1"}}
     ```
4. **`real_vendor_call = False` on Vendor Adapters**:
   - In `apps/nivxray-xdr-response/framework/vendor_adapters.py` lines 209, 231:
     CrowdStrike, Defender, SentinelOne, and Cisco SEP adapters have `real_vendor_call=False` and return `not_wired_yet` when called.
5. **UI-Only Scaffolding**:
   - `EdrFilesPage`, `EdrNetworkPage`, `EdrHuntingPage`, `EdrForensicsPage`, `EdrLiveQueryPage`, and `EdrResponsePage` in `EdrReservedPages.jsx` are static lock banners.
   - `EdrOverviewPage.jsx` displays hardcoded string `"Not isolated"`.

---

## 5. Architectural Gap & Roadmap Determination

### A. What Can Be Reused Unchanged
1. **Activity Inventory & Process Tree Engine**: `services.activity.ActivityInventory` and `v2.ancestry` accurately project parent-child execution hierarchies from canonical events.
2. **5-Lane Device Trajectory**: `GET /api/edr/device-trajectory` and `TrajectoryTimelineCanvas.jsx` provide a complete 3-pane chronological canvas.
3. **Response Orchestration Core**: `apps/nivxray-xdr-response` contains an enterprise-grade execution lifecycle with idempotency, approval state machine, audit trails, and evidence forwarding.
4. **Decoder & Static Analysis Pipeline**: 59 active registered codecs and UAIE static analysis modules unpack, deobfuscate, and dissect binaries with high fidelity.
5. **Investigation Knowledge Graph (IKG) & Security State FSM**: Core causal models and transition logic are mathematically sound and deterministic.

### B. What Must Be Extended
1. **Response Adapters**: Replace `_stub_ok` in `apps/nivxray-xdr-response` with real endpoint containment drivers (WFP host isolation, process termination RPC, quarantine directory relocation) and real vendor REST API calls.
2. **Dynamic Evidence Explorer Data Binding**: Remove `SAMPLE_ARTIFACTS` from `XdrEvidenceExplorerPage.jsx` and wire it dynamically to `GET /api/v2/cases/{id}/artifacts` with genuine empty/loading/error states.
3. **Investigation Sub-Tabs**: Wire Tabs 2 through 8 in `XdrInvestigationWorkspacePage.jsx` to live case endpoints (`/trajectory/device`, `/ancestry`, `/artifacts`, `/verdicts`).

### C. What Must Be Corrected
1. **Honest Empty States**: Eliminate all mock fallbacks in the UI. If a case or endpoint has no artifacts or trajectory events, render `NO MATCHING EVIDENCE`.
2. **Host Extraction**: Upgrade `GET /edr/endpoints` from extracting hosts solely from saved MongoDB cases to querying a persistent endpoint inventory.

### D. What Is Genuinely Missing
1. **Host Agent Daemon**: No resident software component exists on endpoints to collect real-time kernel events (Process, File, Registry, Network Socket).
2. **Live Endpoint Query Engine**: No osquery or TLS-based live query coordinator.
3. **Forensic / Memory Capture Service**: No volatile RAM acquisition or disk triage utility.

### E. Requirements for Enterprise-Grade NivXForge EDR
1. **Endpoint Ingestion Transport**: High-throughput TLS event streaming ingestion endpoint (gRPC / Protobuf / WebSockets) for endpoint agents.
2. **Agent Management Plane**: Device enrollment, mutual TLS (mTLS) certificate rotation, agent configuration distribution, and real-time heartbeat monitoring.
3. **Real Response Enforcement**: Local driver or OS API calls for network isolation, process killing, and file quarantine.

---

## 6. Clean Architectural Boundaries

### 1. NivXRay XDR $\to$ Incident $\to$ NivXForge EDR Boundary

```text
                        ┌─────────────────────────────────────────────────────────┐
                        │                      NivXRay XDR                        │
                        │           (Cross-Domain Threat Correlation)             │
                        └────────────────────────────┬────────────────────────────┘
                                                     │
                                                     ▼
                        ┌─────────────────────────────────────────────────────────┐
                        │                    Incident Record                      │
                        │          (Queue · Work Management · SLAs)               │
                        └─────────────┬─────────────────────────────┬─────────────┘
                                      │                             │
                     Deep-link to     │                             │  Pivots to
                     Full Forensics   ▼                             ▼  Domain Console
      ┌──────────────────────────────────────────────┐    ┌───────────────────────────────────┐
      │          Investigation Workspace             │    │          NivXForge EDR            │
      │         (IKG Causal Graph · FSM)             │    │    (Telemetry Console · Host)     │
      └───────────────────────┬──────────────────────┘    └─────────────────┬─────────────────┘
                              │                                             │
                              │            Telemetry & Evidence             │
                              └──────────────────────┬──────────────────────┘
                                                     ▼
                              ┌─────────────────────────────────────────────┐
                              │            NivXRay Security Core            │
                              │  (Evidence → Causality → State → Verdict)   │
                              └─────────────────────────────────────────────┘
```

**Boundaries & Ownership:**
- **NivXRay XDR**: Owns cross-domain correlation, global incident queue, and multi-source analytics.
- **Incident Record**: Owns operational case lifecycle, SLA aging, assignment, and SOC workflow.
- **NivXForge EDR**: Owns endpoint telemetry visualization (Process Tree, Device Trajectory, Files, Sockets), host health, and endpoint containment execution.
- **NivXRay Security Intelligence Core**: Owns canonical evidence, deobfuscation decoders, IUE, ICE, IKG graph reconstruction, Security State FSM, and deterministic verdicts. **EDR does not invent its own verdict engine.**

---

### 2. Future Sandbox Boundary

```text
                        ┌─────────────────────────────────────────────────────────┐
                        │                      NivXRay XDR                        │
                        │               (Incident / Analyst Trigger)              │
                        └─────────────┬─────────────────────────────┬─────────────┘
                                      │                             │
                                      ▼                             ▼
                        ┌───────────────────────────┐ ┌───────────────────────────┐
                        │       NivXForge EDR       │ │      Dynamic Sandbox      │
                        │    (Production Endpoint)  │ │   (Isolated Hypervisor)   │
                        └─────────────┬─────────────┘ └─────────────┬─────────────┘
                                      │                             │
                         Live Audit   │                             │  Detonation &
                         Telemetry    ▼                             ▼  API Instrumentation
                        ┌─────────────────────────────────────────────────────────┐
                        │             Canonical Evidence Ingestion                │
                        │      (JSON / Syslog / Protobuf Envelope Standard)       │
                        └────────────────────────────┬────────────────────────────┘
                                                     │
                                                     ▼
                        ┌─────────────────────────────────────────────────────────┐
                        │              NivXRay Reasoning Engines                  │
                        │               (IUE / ICE / VEEE / IKG)                  │
                        └────────────────────────────┬────────────────────────────┘
                                                     │
                                                     ▼
                        ┌─────────────────────────────────────────────────────────┐
                        │              Security State FSM & Verdict               │
                        │       (AUTHORIZED → SUSPICIOUS → ABUSED → ATTACK)       │
                        └─────────────────────────────────────────────────────────┘
```

**Boundaries & Ownership:**
- **NivXForge EDR**: Owns monitoring and telemetry of production enterprise endpoints in real time.
- **Dynamic Sandbox**: Owns safe, isolated execution of suspicious artifacts (executables, scripts, documents) within a disposable VM/container environment. Emits dynamic process execution, API call hooking, network connections, and dropped file telemetry.
- **Ingestion Boundary**: Sandbox telemetry is emitted as standard `CanonicalEnvelope` events into the platform.
- **NivXRay Core**: Consumes dynamic telemetry identically to EDR telemetry. The Verdict Engine, IUE, ICE, and Security State FSM evaluate sandbox evidence using the same 615-object Content Fabric without engine duplication.

---

## 7. Audit Sign-Off

* **Corpus Integrity**: 615 content objects remain 100% frozen.
* **Engine Integrity**: 59 registered decoders, 16 content evaluation engines, and Security State FSM untouched.
* **Audit Result**: Complete forensic clarity established. P0 data-binding gaps identified; EDR capability inventory accurately cataloged.
* **Next Gate**: Ready to address P0 data-binding cleanup or P1 Alert Triage Queue before building Sandbox on verified foundations.
