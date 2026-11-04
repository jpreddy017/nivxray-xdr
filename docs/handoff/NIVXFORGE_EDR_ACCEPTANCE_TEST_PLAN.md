# NIVXFORGE EDR: ACCEPTANCE TEST PLAN & VALIDATION SUITE
**Authoritative End-to-End Test Scenarios, Automated Assertions, and Pass/Fail Criteria for Emergent Integration**  
**Document ID:** `NIVXFORGE-TEST-PLAN-2026-09-05`  
**Classification:** Governing Engineering Handoff Pack  
**Handoff Status:** 🟢 APPROVED & READY FOR EMERGENT INTEGRATION REVIEW  

---

## 1. Executive Statement

This document defines the automated and manual **Acceptance Test Battery** that **Emergent** must execute and pass before any Phase 1–4 release can be certified for staging or production. Tests validate the complete lifecycle across **EDR Telemetry Ingestion**, **Dynamic Sandbox Detonation**, and **Safety-Gated Closed-Loop Remediation**.

---

## 2. Test Scenario 1: EDR End-to-End Telemetry & Detection Lifecycle

### Objective
Verify that a live sensor enrolls, streams telemetry, triggers a detection from the 615 Content Fabric, updates the 5-lane trajectory and process tree, correlates into an incident, and updates the investigation workspace without synthetic fallbacks.

```text
[1] Sensor Enrolls via mTLS (X.509 Device Cert)
          ↓
[2] Telemetry Arrives at Gateway (:8443)
          ↓
[3] Canonical Evidence Object Created in Vault (SHA-256 Digest)
          ↓
[4] Process Node Appears in Process Ancestry Tree
          ↓
[5] Event Appears on 5-Lane Device Trajectory Scrubber
          ↓
[6] Detection Rule (SIG-2026-WIN-PS-004) Fires from 615 Content Fabric
          ↓
[7] ICE Correlation Correlates Signals into Incident
          ↓
[8] Investigation Workspace Dossier Automatically Updates
```

### Automated Assertions:
1. `GET /api/v2/endpoints/:id` returns status `ONLINE` with streaming EPS $>0$.
2. `GET /api/v2/artifacts` contains canonical evidence record matching `process_guid`.
3. `GET /api/v2/endpoints/:id/process-tree` contains parent `pid: 4110` connected to child `pid: 4912`.
4. `GET /api/v2/alerts` contains alert `SIG-2026-WIN-PS-004` with severity `CRITICAL`.
5. `GET /api/v2/incidents` contains correlated incident binding the endpoint and process.

---

## 3. Test Scenario 2: Native Sandbox Detonation & Convergence Lifecycle

### Objective
Verify that submitting a suspect binary provisions a MicroVM, executes the sample, streams live syscalls, forwards dropped payloads to the 59-decoder suite, and projects findings onto the Incremental Knowledge Graph (IKG).

```text
[1] Submit Artifact to POST /api/v2/sandbox/detonate
          ↓
[2] MicroVM Created in Firecracker (<500ms spinup)
          ↓
[3] Artifact Executes under In-Guest Syscall Hooks
          ↓
[4] Dynamic Evidence Generated (Syscall, PCAP, Memory RWX)
          ↓
[5] Dynamic Telemetry Enters NivXRay Canonical Evidence Vault
          ↓
[6] Dropped Payload Forwarded to 59 Decoders (Plaintext C2 Recovered)
          ↓
[7] IKG projects Dynamic Execution Nodes onto Causal Graph
          ↓
[8] Authoritative Security State & Deterministic Verdict Update
```

### Automated Assertions:
1. `POST /api/v2/sandbox/detonate` returns `202 Accepted` with `detonation_job_id`.
2. Live WebSocket stream `WSS .../trace` receives $\ge 1$ `NtAllocateVirtualMemory` call with `PAGE_EXECUTE_READWRITE`.
3. `POST /api/decode/smart` returns decoded plaintext C2 IP (`198.51.100.45:8080`) in $<100\text{ms}$.
4. `GET /api/v2/attack-graph/:caseId` contains edge `COBALT_STRIKE_BEACON` connecting host to C2 IP.
5. `GET /v2/security-state/:id` returns authoritative state `CONFIRMED_ATTACK`.

---

## 4. Test Scenario 3: Safety-Gated Response & Containment Verification

### Objective
Verify that a host isolation command enforces the Domain Controller and Healthcare ICU safety checks, applies kernel-level packet drops while maintaining pinned controller mTLS:443, and generates cryptographic telemetry proof of containment.

```text
[1] Threat Detected & Impact Assessed on Workstation Subnet
          ↓
[2] Intervention Recommended: ISOLATE_HOST(WKS-FINANCE-09)
          ↓
[3] Safety Gate Verifies: Non-DC, Non-ICU, Controller mTLS Pinned
          ↓
[4] Incident Commander Approves Action with Justification Note
          ↓
[5] Sensor Kernel Driver Executes Packet Drops (NDIS / eBPF)
          ↓
[6] Sensor Returns Cryptographic Execution Receipt
          ↓
[7] Ingested Network Telemetry Confirms Zero Outbound Non-Controller Packets
          ↓
[8] Verification Evidence Committed to Sealed Audit Ledger
          ↓
[9] Security State Transitions to CONTAINED
```

### Negative Safety Assertions (Must Refuse Isolation):
1. Dispatching isolation against a registered Active Directory Domain Controller (`SRV-DC-01`) returns HTTP `400 Bad Request` with error `SAFETY_GATE_VIOLATION: DOMAIN_CONTROLLER_CANNOT_BE_ISOLATED`.
2. Dispatching isolation against an ICU node returns HTTP `400 Bad Request` with error `SAFETY_GATE_VIOLATION: LIFE_SAFETY_CRITICAL_ASSET`.

### Positive Containment Assertions:
1. Target host `WKS-FINANCE-09` receives containment command.
2. Inbound/outbound pings (`ICMP`) and HTTP connections (`TCP:80`) immediately fail (timeout).
3. The sensor agent continues to stream heartbeats to Gateway:8443 without disconnection.
4. `GET /api/v2/response/ledger` contains cryptographically signed audit entry with operator signature.
5. Subsequent telemetry for 30s contains zero external sockets; `VerificationEvidence` is recorded.

---

## 5. Test Scenario 4: Strict Multi-Tenant Boundary Enforcement

### Objective
Prove that an authenticated analyst belonging to Tenant A can never query, inspect, or execute actions against endpoints, evidence, or sandbox jobs belonging to Tenant B.

### Automated Assertions:
1. Request with `JWT_TENANT_A` to `GET /api/v2/endpoints?tenant_id=TENANT_B` completely ignores query parameter and returns ONLY Tenant A endpoints.
2. Request with `JWT_TENANT_A` to `GET /api/v2/artifacts/art-tenant-b-uuid` returns HTTP `404 Not Found` (fail-closed, no existence leakage).
3. Request with `JWT_TENANT_A` to `POST /api/v2/edr/actions/isolate` targeting `host-tenant-b` returns HTTP `404 Not Found`.

---

## 6. Regression Testing: Frozen Assets Verification

Before any code merge or deployment, the following test scripts must be executed and exit with status code 0:

```bash
# 1. Verify 615 Content Fabric (Zero modifications permitted)
python backend/run_content_truth_audit.py

# 2. Verify 59 Decoders (Zero modifications permitted)
python backend/verify_decoder_truth_e2e.py
```

**Pass Criteria**: Both scripts must output `100% VERIFIED & PASSED` with zero errors, zero semantic duplicates, and zero quarantined objects.
