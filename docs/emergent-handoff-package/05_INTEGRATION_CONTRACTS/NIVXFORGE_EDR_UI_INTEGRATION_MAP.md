# NIVXFORGE EDR: UI INTEGRATION & SURFACE MAPPING SPECIFICATION
**Authoritative Frontend Routing, React Component Hierarchy, Backend API Mappings, and RBAC Boundaries for All 37 Surfaces**  
**Document ID:** `NIVXFORGE-UI-MAP-2026-09-05`  
**Classification:** Governing Engineering Handoff Pack  
**Handoff Status:** 🟢 APPROVED & READY FOR EMERGENT INTEGRATION REVIEW  

---

## 1. Executive Statement

This specification defines the exact frontend integration architecture connecting **NivXForge EDR** and the **Native Dynamic Sandbox** into the **NivXRay XDR Shell** (`apps/nivxray-xdr/src/xdr/XdrShell.jsx`). Every screen across the 37 mandatory surfaces is classified as **REUSE**, **EXTEND**, or **NEW**, with explicit routes, components, APIs, and authorization roles.

---

## 2. Global Shell Navigation Integration

The unified application shell is structured as follows:

```text
XdrShell (`apps/nivxray-xdr/src/xdr/XdrShell.jsx`)
├── Global Top Bar (Tenant Context, Search, Alerts, User Profile)
├── Left Navigation Rail (Operational Domain Selector)
│   ├── [1] Strategic & Fleet Governance (/edr/overview, /edr/agents, /edr/telemetry-health, /edr/policies)
│   ├── [2] Asset & Posture Intelligence (/edr/endpoints, /edr/endpoints/:id/360, /edr/users-sessions, /edr/vulnerabilities, /edr/ubae-context)
│   ├── [3] Detection & Alert Triage (/edr/detections, /edr/detections/:id, /edr/incidents, /edr/detection-engineering, /edr/attack-matrix)
│   ├── [4] Forensic Investigation & Analytics (/edr/endpoints/:id/trajectory, /edr/endpoints/:id/process-tree, /edr/processes/:guid, /edr/files, /edr/network, /edr/dns, /edr/registry, /edr/services, /edr/persistence, /edr/forensics, /edr/memory, /edr/attack-story/:caseId, /edr/evidence, /edr/investigation-pivots)
│   ├── [5] Threat Hunting & Live Query (/edr/hunting, /edr/live-query, /edr/threat-intel)
│   ├── [6] Containment & Response (/edr/response, /edr/response/isolation, /edr/response/quarantine, /edr/response/terminal)
│   └── [7] Native Dynamic Sandbox (/sandbox/submit, /sandbox/live/:jobId, /sandbox/reports/:jobId, /sandbox/bridge/:jobId)
└── Main Content Viewport (Dynamic Route Outlet)
```

---

## 3. Exhaustive 37-Surface Technical Mapping

| # | Surface Name | Action | Exact Route Path | React Component | Backend API Route | Backend Service Module | Data Source | Required RBAC Role |
|---|---|---|---|---|---|---|---|---|
| **1** | **EDR Overview** | `EXTEND` | `/edr/overview` | `XdrEdrOverviewPage.jsx` | `GET /api/v2/edr/metrics/overview` | `backend/routers/edr.py` | EDR Telemetry Cache | `TIER_1_ANALYST` |
| **2** | **Endpoint Fleet** | `EXTEND` | `/edr/endpoints` | `XdrEndpointsPage.jsx` | `GET /api/v2/endpoints` | `backend/routers/edr.py` | Sensor Registry DB | `TIER_1_ANALYST` |
| **3** | **Endpoint Entity 360** | `NEW` | `/edr/endpoints/:id/360` | `XdrEndpoint360Page.jsx` | `GET /api/v2/endpoints/:id/360` | `backend/routers/edr.py` | Asset Posture DB | `TIER_1_ANALYST` |
| **4** | **Detections Queue** | `REUSE` | `/edr/detections` | `XdrAlertsPage.jsx` | `GET /api/v2/alerts` | `backend/routers/incidents.py` | Alert Store | `TIER_1_ANALYST` |
| **5** | **Detection Detail** | `EXTEND` | `/edr/detections/:id` | `XdrAlertDetailPage.jsx` | `GET /api/v2/alerts/:id` | `backend/routers/incidents.py` | Alert Store + ETW | `TIER_1_ANALYST` |
| **6** | **Incidents** | `REUSE` | `/edr/incidents` | `XdrIncidentsPage.jsx` | `GET /api/v2/incidents` | `backend/routers/incidents.py` | Correlation DB | `TIER_1_ANALYST` |
| **7** | **Device Timeline** | `EXTEND` | `/edr/endpoints/:id/timeline` | `DeviceTimelinePage.jsx` | `GET /api/v2/endpoints/:id/timeline` | `backend/routers/timeline.py` | Telemetry Ledger | `TIER_2_ANALYST` |
| **8** | **Device Trajectory** | `NEW` | `/edr/endpoints/:id/trajectory`| `DeviceTrajectoryPage.jsx`| `GET /api/v2/trajectory/:id` | `backend/routers/timeline.py` | 5-Lane Stream DB | `TIER_2_ANALYST` |
| **9** | **Process Tree** | `NEW` | `/edr/endpoints/:id/process-tree`| `ProcessTreePage.jsx` | `GET /api/v2/endpoints/:id/process-tree`| `backend/routers/process_tree.py`| Process Ancestry DB| `TIER_2_ANALYST` |
| **10**| **Process Detail** | `NEW` | `/edr/processes/:guid` | `ProcessDetailDrawer.jsx`| `GET /api/v2/processes/:guid` | `backend/routers/process_tree.py`| Process Cache | `TIER_2_ANALYST` |
| **11**| **Files & Artifacts** | `EXTEND` | `/edr/files` | `XdrFilesPage.jsx` | `GET /api/v2/files` | `backend/routers/files.py` | Artifact Store | `TIER_2_ANALYST` |
| **12**| **File Detail** | `EXTEND` | `/edr/files/:sha256` | `FileDetailPage.jsx` | `GET /api/v2/files/:sha256` | `backend/routers/files.py` | PE Static Inspector | `TIER_2_ANALYST` |
| **13**| **Network Connections**| `EXTEND` | `/edr/network` | `XdrNetworkPage.jsx` | `GET /api/v2/network/connections`| `backend/routers/telemetry.py` | Flow Telemetry DB | `TIER_2_ANALYST` |
| **14**| **DNS Query Activity** | `EXTEND` | `/edr/dns` | `XdrDnsPage.jsx` | `GET /api/v2/network/dns` | `backend/routers/telemetry.py` | DNS Log Store | `TIER_2_ANALYST` |
| **15**| **Windows Registry** | `NEW` | `/edr/registry` | `XdrRegistryPage.jsx` | `GET /api/v2/registry/activity` | `backend/routers/telemetry.py` | Registry Stream DB | `TIER_2_ANALYST` |
| **16**| **System Services** | `NEW` | `/edr/services` | `XdrServicesPage.jsx` | `GET /api/v2/services` | `backend/routers/telemetry.py` | Services DB | `TIER_2_ANALYST` |
| **17**| **Users & Sessions** | `EXTEND` | `/edr/users-sessions` | `XdrUsersSessionsPage.jsx`| `GET /api/v2/sessions/active` | `backend/routers/sessions.py` | Session Ledger | `TIER_2_ANALYST` |
| **18**| **Persistence / ASEP** | `NEW` | `/edr/persistence` | `XdrPersistencePage.jsx` | `GET /api/v2/persistence/aseps` | `backend/routers/telemetry.py` | ASEP Cache | `TIER_2_ANALYST` |
| **19**| **Threat Hunting** | `EXTEND` | `/edr/hunting` | `XdrThreatHuntingPage.jsx`| `POST /api/v2/hunting/query` | `backend/routers/telemetry.py` | ClickHouse / Elastic| `THREAT_HUNTER` |
| **20**| **Distributed Live Query**| `NEW` | `/edr/live-query` | `LiveQueryPage.jsx` | `POST /api/v2/edr/fleet/live-query` | `backend/routers/edr_live_query.py`| osquery Sensors | `THREAT_HUNTER` |
| **21**| **Forensics Triage** | `NEW` | `/edr/forensics` | `XdrForensicsPage.jsx` | `POST /api/v2/forensics/collect` | `backend/routers/edr.py` | DFIR Package Vault | `DFIR_SPECIALIST` |
| **22**| **Memory / Volatiles** | `NEW` | `/edr/memory` | `XdrMemoryPage.jsx` | `POST /api/v2/memory/dump` | `backend/routers/edr.py` | Volatile Dump Store | `DFIR_SPECIALIST` |
| **23**| **Vulnerabilities / KEV**| `NEW` | `/edr/vulnerabilities` | `XdrVulnerabilitiesPage.jsx`| `GET /api/v2/vulnerabilities` | `backend/routers/xdr_cve.py` | NVD / CISA KEV DB | `SECURITY_ADMIN` |
| **24**| **Threat Intelligence**| `REUSE` | `/edr/threat-intel` | `ThreatIntelPage.jsx` | `GET /api/v2/threat-intel/iocs` | `backend/routers/threat_intel.py`| MISP / STIX Feeds | `TIER_2_ANALYST` |
| **25**| **Response Center** | `EXTEND` | `/edr/response` | `XdrResponseCenterPage.jsx`| `GET /api/v2/response/ledger` | `backend/routers/xdr_cortex_actions.py`| Action Audit DB | `INCIDENT_COMMANDER`|
| **26**| **Safety-Gated Isolation**| `NEW` | `/edr/response/isolation`| `HostIsolationModal.jsx` | `POST /api/v2/edr/actions/isolate`| `backend/routers/edr.py` | Kernel NDIS Driver | `INCIDENT_COMMANDER`|
| **27**| **Quarantine Vault** | `NEW` | `/edr/response/quarantine`| `QuarantineVaultPage.jsx`| `GET /api/v2/quarantine/files` | `backend/routers/edr.py` | Encrypted Vault DB | `INCIDENT_COMMANDER`|
| **28**| **Remote Response Shell**| `NEW` | `/edr/response/terminal` | `RemoteTerminalPage.jsx` | `WSS /api/v2/edr/terminal/ws` | `backend/routers/edr.py` | Live Sensor Socket | `INCIDENT_COMMANDER`|
| **29**| **Agent Management** | `EXTEND` | `/edr/agents` | `XdrAgentMgmtPage.jsx` | `GET /api/v2/edr/agents` | `backend/routers/edr.py` | Deployment Registry| `SYSTEM_ADMIN` |
| **30**| **Telemetry Health** | `NEW` | `/edr/telemetry-health` | `TelemetryHealthPage.jsx`| `GET /api/v2/edr/telemetry/health`| `backend/routers/platform_health.py`| Gateway Metrics | `SYSTEM_ADMIN` |
| **31**| **Detection Engineering**| `REUSE`| `/edr/detection-engineering`| `ModelStudioPage.jsx` | `GET /api/v2/detection-content/rules`| `backend/routers/xdr_detection_content.py`| 615 Content Fabric| `DETECTION_ENGINEER`|
| **32**| **Prevention Policies** | `NEW` | `/edr/policies` | `XdrPoliciesPage.jsx` | `GET /api/v2/edr/policies` | `backend/routers/edr.py` | Policy Engine DB | `SECURITY_ADMIN` |
| **33**| **MITRE ATT&CK Matrix**| `REUSE` | `/edr/attack-matrix` | `MitreHeatmapPage.jsx` | `GET /api/v2/mitre/matrix` | `backend/routers/mitre_heatmap.py`| MITRE Catalogue DB | `TIER_1_ANALYST` |
| **34**| **Attack Story Canvas** | `REUSE` | `/edr/attack-story/:caseId`| `EvidenceFirstInvestigationWorkspace.jsx`| `GET /api/v2/attack-story/:caseId`| `backend/routers/attack_story.py`| Causal IKG Graph | `TIER_2_ANALYST` |
| **35**| **Evidence Vault** | `REUSE` | `/edr/evidence` | `XdrEvidenceExplorerPage.jsx`| `GET /api/v2/artifacts` | `backend/routers/artifacts.py` | Immutable Hash Ledger| `TIER_1_ANALYST` |
| **36**| **Investigation Pivots**| `REUSE` | `/edr/investigation-pivots`| `EvidenceFirstInvestigationWorkspace.jsx`| `GET /api/v2/investigations/pivots`| `backend/routers/investigations.py`| Core Graph Pivots | `TIER_2_ANALYST` |
| **37**| **UBAE Entity Context** | `EXTEND` | `/edr/ubae-context` | `XdrUbaeContextPage.jsx` | `GET /api/v2/ubae/entities` | `backend/routers/sessions.py` | User Baseline DB | `TIER_2_ANALYST` |

---

## 4. Native Dynamic Sandbox Subsystem UI Mapping

| Screen / Surface | Route Path | React Component | Backend API Route | Subsystem | Required RBAC Role |
|---|---|---|---|---|---|
| **Detonation Intake** | `/sandbox/submit` | `SandboxIntakePage.jsx` | `POST /api/v2/sandbox/detonate` | MicroVM / QEMU Runner | `TIER_2_ANALYST` |
| **Live Hypervisor Console**| `/sandbox/live/:jobId` | `SandboxLiveConsolePage.jsx` | `WSS /api/v2/sandbox/jobs/:id/screen` | HTML5 VNC/WebRTC Stream | `TIER_2_ANALYST` |
| **Detonation Report** | `/sandbox/reports/:jobId`| `SandboxReportPage.jsx` | `GET /api/v2/sandbox/jobs/:id/report` | 6-Subtab Forensic Dissector | `TIER_1_ANALYST` |
| **Convergence Bridge** | `/sandbox/bridge/:jobId` | `SandboxBridgePanel.jsx` | `POST /api/v2/sandbox/jobs/:id/converge` | 59 Decoders / Blocklists | `INCIDENT_COMMANDER`|

---

## 5. Standardized UI State Models

Every component must implement the 6 core states:
1. `ACTIVE_DATA`: Fully rendered tabular/graph view.
2. `LOADING_SKELETON`: Pulsing CSS shimmer preserving layout dimensions.
3. `FAIL_CLOSED_EMPTY`: Honest `NO AUTHORITATIVE EVIDENCE RECORDED` banner.
4. `ACTIONABLE_ERROR`: Error code, failing endpoint, trace ID, and retry button.
5. `PERMISSION_RESTRICTED`: Explanatory badge when RBAC role is insufficient.
6. `DANGEROUS_ACTION_CONFIRMATION`: Two-step modal requiring explicit operator rationale.
