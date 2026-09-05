# NIVXFORGE EDR: ATTACK-CHAIN IMPLEMENTATION & STABLE IDENTIFIER CONTRACT
**Engineering Implementation Contract, Stable Key Propagations, and Parameter Passing for the 20-Step Causal Lifecycle**  
**Document ID:** `NIVXFORGE-ATTACK-CHAIN-IMP-2026-09-05`  
**Classification:** Governing Engineering Handoff Pack  
**Handoff Status:** 🟢 APPROVED & READY FOR EMERGENT INTEGRATION REVIEW  

---

## 1. Executive Statement

In NivXRay's evidence-first architecture, an attack-chain traversal is not a sequence of disconnected UI navigations; it is a **continuous, cryptographically verifiable graph traversal**.

This contract defines the **stable identifiers**, **parameter schemas**, and **API endpoints** that guarantee seamless state preservation across all 20 steps of the canonical attack-chain lifecycle.

---

## 2. Master Attack-Chain Identifier Propagation Flow

```text
[1] Detection Queue
         │
         │ alert_id: "ALT-2026-98124"
         ▼
[2] Alert Detail View
         │
         │ process_guid: "wks09:4912:1788581256"
         ▼
[3] Process Detail Drawer
         │
         │ parent_process_guid: "wks09:4110:1788581250"
         ▼
[4] Process Tree Ancestry
         │
         │ device_id: "9f1b2c4d-88a2-4a7b-b891-99882244aa11"
         ▼
[5] Endpoint Entity 360
         │
         │ user_id: "S-1-5-21-39482910-2918239-1002"
         ▼
[6] Users & Sessions View
         │
         │ network_flow_id: "flow-9f1b-198-51-100-45-8080"
         ▼
[7] Network Connections Telemetry
         │
         │ dns_event_id: "dns-9f1b-update-microsoft-check-net"
         ▼
[8] DNS Activity Explorer
         │
         │ ioc_value: "update.microsoft-check.net"
         ▼
[9] Threat Intelligence IOC Vault
         │
         │ artifact_sha256: "419c225566d6054d38fe5ee5c01bd9d2bdfedf79a312dd15ae71646e322255ae"
         ▼
[10] Dropped File Explorer
         │
         │ sandbox_job_id: "sbx-job-88129-441a"
         ▼
[11] Dynamic Sandbox Hypervisor
         │
         │ dynamic_evidence_ids: ["ev-sys-8812", "ev-mem-8813", "ev-pcap-8814"]
         ▼
[12] Dynamic Forensic Report
         │
         │ attck_technique_id: "T1055.002"
         ▼
[13] MITRE ATT&CK Navigator
         │
         │ ikg_node_ids: ["node-proc-4912", "node-net-8080"], ikg_edge_ids: ["edge-inject-1420"]
         ▼
[14] Incremental Knowledge Graph (IKG)
         │
         │ security_state_version: "sec-state-v4-case-841"
         ▼
[15] Authoritative Security State Engine
         │
         │ verdict_id: "vrd-case-841-conf-attack"
         ▼
[16] Deterministic Verdict Engine
         │
         │ impact_assessment_id: "imp-case-841-subnet-finance"
         ▼
[17] Enterprise Impact Engine
         │
         │ response_action_id: "act-plan-841-contain"
         ▼
[18] Response Center & Safety Gate
         │
         │ safety_gate_token: "sg-token-verified-non-dc-wks09"
         ▼
[19] Kernel Host Isolation Driver
         │
         │ containment_ledger_id: "iso-ledger-9f1b-confirmed"
         ▼
[20] Verification & Telemetry Proof
```

---

## 3. Detailed Step-by-Step Implementation Contract

| Step # | Transition | Inbound Identifier | Outbound Identifier | Source Endpoint & Component | Target Endpoint & Component | Context State Passed in URL / Session |
|---|---|---|---|---|---|---|
| **1** | `Queue → Alert` | `tenant_id` | `alert_id` | `GET /api/v2/alerts`<br>`XdrAlertsPage.jsx` | `GET /api/v2/alerts/:alertId`<br>`XdrAlertDetailPage.jsx` | `?case_id=...&severity=CRITICAL` |
| **2** | `Alert → Process` | `alert_id` | `process_guid` | `GET /api/v2/alerts/:alertId`<br>`XdrAlertDetailPage.jsx` | `GET /api/v2/processes/:guid`<br>`ProcessDetailDrawer.jsx` | `?host_id=...&timestamp=...` |
| **3** | `Process → Parent` | `process_guid` | `parent_process_guid` | `ProcessDetailDrawer.jsx` | `GET /api/v2/endpoints/:id/process-tree`<br>`ProcessTreePage.jsx` | `?highlight_guid=...` |
| **4** | `Parent → Device` | `parent_process_guid` | `device_id` | `ProcessTreePage.jsx` | `GET /api/v2/endpoints/:id/360`<br>`XdrEndpoint360Page.jsx` | `?device_id=9f1b...` |
| **5** | `Device → User` | `device_id` | `user_id` / `user_sid` | `XdrEndpoint360Page.jsx` | `GET /api/v2/sessions/active`<br>`XdrUsersSessionsPage.jsx` | `?username=CORP\jdoe` |
| **6** | `User → Network` | `user_id` | `network_flow_id` | `XdrUsersSessionsPage.jsx` | `GET /api/v2/network/connections`<br>`XdrNetworkPage.jsx` | `?device_id=...&time_window=10m` |
| **7** | `Network → DNS` | `network_flow_id` | `dns_event_id` | `XdrNetworkPage.jsx` | `GET /api/v2/network/dns`<br>`XdrDnsPage.jsx` | `?dest_ip=198.51.100.45` |
| **8** | `DNS → IOC` | `dns_event_id` | `ioc_value` (domain) | `XdrDnsPage.jsx` | `GET /api/v2/threat-intel/iocs`<br>`ThreatIntelPage.jsx` | `?observable=update.microsoft-check.net` |
| **9** | `IOC → File` | `ioc_value` | `artifact_sha256` | `ThreatIntelPage.jsx` | `GET /api/v2/files/:sha256`<br>`FileDetailPage.jsx` | `?sha256=419c2255...` |
| **10** | `File → Sandbox` | `artifact_sha256` | `sandbox_job_id` | `FileDetailPage.jsx` | `POST /api/v2/sandbox/detonate`<br>`SandboxIntakePage.jsx` | `?payload_path=C:\Windows\Temp\stage2.ps1` |
| **11** | `Sandbox → Traces` | `sandbox_job_id` | `dynamic_evidence_ids` | `WSS .../trace`<br>`SandboxLiveConsolePage.jsx` | `GET /api/v2/sandbox/jobs/:id/report`<br>`SandboxReportPage.jsx` | `?job_id=sbx-job-88129` |
| **12** | `Traces → ATT&CK` | `dynamic_evidence_ids` | `attck_technique_id` | `SandboxReportPage.jsx` | `GET /api/v2/mitre/matrix`<br>`MitreHeatmapPage.jsx` | `?technique=T1055.002` |
| **13** | `ATT&CK → IKG` | `attck_technique_id` | `ikg_node_ids`, `ikg_edge_ids` | `MitreHeatmapPage.jsx` | `GET /api/v2/attack-graph/:caseId`<br>`EvidenceFirstInvestigationWorkspace.jsx` | `?case_id=INC-2026-0841&tab=ikg` |
| **14** | `IKG → SecState` | `ikg_node_ids` | `security_state_version` | `EvidenceFirstInvestigationWorkspace.jsx` | `GET /v2/security-state/:id`<br>`XdrInvestigationWorkspacePage.jsx` (Tab 5) | `?case_id=...&fail_closed=true` |
| **15** | `SecState → Verdict`| `security_state_version` | `verdict_id` | `XdrInvestigationWorkspacePage.jsx` (Tab 5) | `GET /api/v2/verdict/:caseId`<br>`XdrInvestigationWorkspacePage.jsx` (Tab 7) | `?case_id=...&deterministic=true` |
| **16** | `Verdict → Impact` | `verdict_id` | `impact_assessment_id` | `XdrInvestigationWorkspacePage.jsx` (Tab 7) | `GET /api/v2/investigations/:caseId/impact`<br>`EvidenceFirstInvestigationWorkspace.jsx` | `?case_id=...&subnet=192.168.10.0/24` |
| **17** | `Impact → Response`| `impact_assessment_id` | `response_action_id` | `EvidenceFirstInvestigationWorkspace.jsx` | `POST /api/v2/response/actions`<br>`XdrResponseCenterPage.jsx` | `?action=ISOLATE_HOST&target=wks09` |
| **18** | `Response → Gate` | `response_action_id` | `safety_gate_token` | `XdrResponseCenterPage.jsx` | `POST /api/v2/edr/safety-gate/verify`<br>`HostIsolationModal.jsx` | `?device_id=...&operator=JP` |
| **19** | `Gate → Isolation` | `safety_gate_token` | `containment_ledger_id` | `HostIsolationModal.jsx` | `POST /api/v2/edr/actions/isolate`<br>`backend/routers/edr.py` | `?token=sg-token-...&mTLS=pinned` |
| **20** | `Isolation → Proof`| `containment_ledger_id` | `verification_evidence_id` | `backend/routers/edr.py` | `GET /api/v2/trajectory/:id`<br>`DeviceTrajectoryPage.jsx` | `?filter=post_isolation_packets` |

---

## 4. State Persistence Invariants

1. **URL Hash and Search Parameter Contract**: All pivots must update `window.location.search` with the current entity key (e.g., `?device_id=...&case_id=...`). This guarantees that browser reload, copy-pasting links, and team collaboration preserve the exact investigation locus.
2. **Session Storage Context Tray**: The active investigation tray (`[ Host: WKS-FINANCE-09 · Process: powershell.exe · Case: #INC-2026-0841 ]`) is mirrored in `window.sessionStorage.active_investigation_context` to allow cross-tab persistence without state corruption.
3. **Fail-Closed Behavior**: If an identifier lookup fails (e.g., `dns_event_id` references a session where DNS logging was disabled), the target surface displays `NO AUTHORITATIVE EVIDENCE RECORDED: Event ID not found in Canonical Evidence Store` rather than manufacturing fallback data.
