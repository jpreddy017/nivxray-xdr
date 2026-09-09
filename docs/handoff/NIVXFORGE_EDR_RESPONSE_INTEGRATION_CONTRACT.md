# NIVXFORGE EDR: RESPONSE & REMEDIATION INTEGRATION CONTRACT
**Authoritative Multi-Stage Response State Machine, Approval Workflows, Driver Interfaces, and Verification Invariants**  
**Document ID:** `NIVXFORGE-RESPONSE-CONTRACT-2026-09-05`  
**Classification:** Governing Engineering Handoff Pack  
**Handoff Status:** 🟢 APPROVED & READY FOR EMERGENT INTEGRATION REVIEW  

---

## 1. Executive Statement

In an enterprise XDR ecosystem, containment and remediation actions are dangerous operations that must never be executed blindly or without deterministic verification.

Emergent must understand the non-negotiable distinction between a **Security State Recommendation** and an **Authoritative Verified Intervention**. This contract codifies the 7-stage response lifecycle, approval requirements, sensor driver interfaces, and subsequent telemetry verification.

---

## 2. The 7-Stage Response State Machine

```text
[ STAGE 1: RECOMMENDATION ]
NivXRay Core (Security State / Verdict Engine) generates recommended actions
(e.g., "RECOMMEND: ISOLATE_HOST(WKS-FINANCE-09), QUARANTINE(svchost_update.exe)")
                    │
                    ▼
[ STAGE 2: INTERVENTION PLAN ]
Planner aggregates actions, checks policies, computes blast radius, and drafts plan
                    │
                    ▼
[ STAGE 3: APPROVAL ]
Requires Dual-Custody or Single Incident Commander signature based on policy
                    │
                    ▼
[ STAGE 4: ACTION REQUESTED ]
Safety Gate verifies target is NOT a Domain Controller or ICU Node
Command serialized and dispatched via mTLS to Sensor Agent:443
                    │
                    ▼
[ STAGE 5: ACTION EXECUTED ]
Endpoint kernel driver executes command (NDIS packet drop / process kill)
                    │
                    ▼
[ STAGE 6: ACTION ACKNOWLEDGED ]
Sensor agent returns cryptographic receipt confirming local kernel execution
                    │
                    ▼
[ STAGE 7: ACTION VERIFIED ]
Subsequent sensor telemetry proves zero outbound network flows & process halt
Evidence committed to Ledger; Security State updates to CONTAINED
```

---

## 3. Existing Response Components to Reuse vs. Extend

| Subsystem Component | Existing Repository Location | Current Truth | Emergent Action Directive |
|---|---|---|---|
| **Response Ingestion App** | `apps/nivxray-xdr-response/main.py` | `IMPLEMENTED` | **REUSE AS-IS**<br>Orchestrates action queues and receipts. |
| **Response Contract** | `apps/nivxray-xdr-response/RESPONSE_INGEST_CONTRACT.md` | `IMPLEMENTED` | **REUSE AS-IS**<br>Maintain existing API JSON schemas. |
| **Cortex Actions Router** | `backend/routers/xdr_cortex_actions.py` | `IMPLEMENTED` | **REUSE AS-IS**<br>Exposes approval and ledger endpoints. |
| **Response Evidence Router** | `backend/routers/xdr_response_evidence.py` | `IMPLEMENTED` | **REUSE AS-IS**<br>Binds action receipts into Evidence Store. |
| **Security State Intervention** | `backend/security_state/contracts.py` | `IMPLEMENTED` | **INTEGRATE**<br>Derive intervention plans from confirmed state. |
| **EDR Kernel Isolation Driver** | `[NEW] src/sensor/isolation/` | `MOCK` (Prototype) | **BUILD (Phase 1-4)**<br>NDIS 6.x / eBPF packet filtering driver. |
| **Quarantine Vault Driver** | `[NEW] src/sensor/quarantine/` | `MISSING` | **BUILD (Phase 4)**<br>Encrypted `.nvxvault` filesystem driver. |
| **Volatile Memory Acquirer** | `[NEW] src/sensor/memory/` | `MISSING` | **BUILD (Phase 4)**<br>Physical memory capture engine. |

---

## 4. EDR Response Driver Interface Specifications

Emergent must implement the endpoint response primitives conforming to the following driver interface:

### 4.1 Driver Primitive 1: `NetworkIsolationDriver`
* **Driver Target**: Windows NDIS Lightweight Filter (LWF) / Linux eBPF `XDP`/`tc` filter.
* **Command Contract**:
```json
{
  "command": "NETWORK_ISOLATE",
  "command_id": "cmd-iso-9812-4411",
  "parameters": {
    "target_device_id": "9f1b2c4d-88a2-4a7b-b891-99882244aa11",
    "pinned_controller_ip": "10.0.1.100",
    "pinned_controller_port": 443,
    "allow_dhcp": true,
    "allow_dns_internal": false
  }
}
```
* **Safety Gate Pre-Conditions (Enforced by Controller before dispatch)**:
  1. `TargetDevice.is_domain_controller == False` (Checked against AD directory metadata).
  2. `TargetDevice.tags NOT CONTAINS 'ICU'` AND `'HEALTHCARE_CRITICAL'` AND `'SCADA'`.
  3. `TargetDevice.sensor_connectivity == 'ONLINE'`.
* **Execution Semantics**:
  - Immediately drops all inbound and outbound IP packets EXCEPT packets with `DestinationIP == pinned_controller_ip && DestinationPort == 443`.
  - Maintains the pinned mTLS socket to prevent "orphaned isolation" where a host can never be re-connected.

### 4.2 Driver Primitive 2: `ProcessTerminationDriver`
* **Command Contract**:
```json
{
  "command": "TERMINATE_PROCESS_TREE",
  "command_id": "cmd-term-4912",
  "parameters": {
    "target_process_guid": "wks09:4912:1788581256",
    "target_pid": 4912,
    "kill_child_processes": true
  }
}
```
* **Execution Semantics**:
  - Sensor driver issues `ZwTerminateProcess` via kernel minifilter, bypassing user-mode API hooks or debugger attachments.
  - Recursively enumerates and terminates all descendant processes spawned by target PID.

### 4.3 Driver Primitive 3: `QuarantineVaultDriver`
* **Command Contract**:
```json
{
  "command": "QUARANTINE_FILE",
  "command_id": "cmd-quar-8a7f",
  "parameters": {
    "file_path": "C:\\ProgramData\\svchost_update.exe",
    "expected_sha256": "8a7f1e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f"
  }
}
```
* **Execution Semantics**:
  - File is atomically moved to `%ProgramData%\NivXForge\Quarantine\{sha256}.nvxvault`.
  - Content is encrypted using AES-256-GCM with a locally held sensor key; original file system inode/handle is deleted.

---

## 5. Telemetry Verification Invariant

An action is **NOT considered complete** merely because the sensor acknowledged command receipt (`STAGE 6`). An action enters `STAGE 7: ACTION VERIFIED` only when subsequent telemetry proves real-world effect:

$$\text{Isolation Verified} \iff \forall t \in [t_{\text{iso}}, t_{\text{iso}} + 30\text{s}], \quad \text{OutboundPackets}(t) \setminus \{\text{Controller:443}\} \equiv \emptyset$$

1. The Verification Engine inspects incoming `network` telemetry from the target host for 30 seconds post-isolation.
2. If zero non-controller outbound sockets are reported, the engine generates an immutable `VerificationEvidence` record.
3. The XDR Investigation Workspace automatically updates the host badge to `CONTAINMENT VERIFIED`.
