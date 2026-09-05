# NIVXFORGE EDR: SECURITY, MULTI-TENANCY & CRYPTOGRAPHIC LEDGER CONTRACT
**Authoritative Specification for Multi-Tenant Isolation, Sensor Identity, mTLS, RBAC, and Tamper-Proof Audit Logging**  
**Document ID:** `NIVXFORGE-SEC-TENANCY-2026-09-05`  
**Classification:** Governing Engineering Handoff Pack  
**Handoff Status:** 🟢 APPROVED & READY FOR EMERGENT INTEGRATION REVIEW  

---

## 1. Executive Statement

Enterprise security platforms must never compromise tenant isolation or allow privilege escalation during emergency response actions. This contract codifies the non-negotiable security invariants governing **Multi-Tenancy**, **Sensor PKI / mTLS**, **Sandbox Hypervisor Isolation**, and **Cryptographically Sealed Audit Ledgers** across **NivXForge EDR** and **NivXRay Core**.

---

## 2. Strict Multi-Tenancy Architecture

### 2.1 The Server-Side Context Invariant
All database queries, evidence storage operations, and response actions must resolve tenant ownership strictly through cryptographically validated server-side tokens:

```text
[ Client (Browser / UI / Agent) ]
               │
               │ HTTP Authorization: Bearer <JWT>  OR  X.509 Client Cert
               ▼
[ NivXRay API Gateway / Reverse Proxy ]
               │
               │ 1. Validate JWT signature against internal KMS public key
               │ 2. Extract tenant_id from claims: claims["tid"]
               │ 3. Inject context into RequestContext: request.state.tenant_id
               ▼
[ Application Business Logic / Routers ]
               │
               │ Context enforced on all DB / Cache / Evidence operations:
               │ SELECT * FROM telemetry WHERE tenant_id = request.state.tenant_id
               ▼
[ PostgreSQL / ClickHouse / Object Storage ]
```

> [!CAUTION]
> **Prohibited Pattern**:
> $$\text{Client} \longrightarrow \text{Query Parameter } (\texttt{?tenant\_id=xyz}) \longrightarrow \text{Direct DB Filter} \quad \text{[STRICTLY FORBIDDEN]}$$
> Any request attempting to override tenant context via query parameters, URL path segments, or request JSON bodies must be immediately rejected with HTTP `403 Forbidden` and logged as a high-severity security anomaly.

---

## 3. Sensor PKI & Mutual TLS (mTLS) Invariants

### 3.1 Sensor Enrollment Protocol
1. **Enrollment Token**: Admin generates a cryptographically signed, short-lived enrollment token via the XDR UI (`POST /api/v2/edr/enrollment-tokens`).
2. **CSR Submission**: The sensor installer generates an ephemeral RSA-4096 or ECDSA P-384 private key on the endpoint and dispatches a Certificate Signing Request (CSR) to Gateway:8443.
3. **CA Verification & Issuance**: The internal NivXForge Certificate Authority (CA) verifies the token and issues an X.509 device certificate:
   - `Subject`: `CN={device_uuid}, O=NivXForge, OU={tenant_id}`
   - `Key Usage`: Digital Signature, Key Encipherment
   - `Extended Key Usage`: Client Authentication (`1.3.6.1.5.5.7.3.2`)
   - `Validity`: 90 days with automated over-the-air renewal.
4. **Mutual TLS 1.3**: All subsequent telemetry streaming and command execution channels enforce mTLS 1.3 with TLS_AES_256_GCM_SHA384 cipher suites. The Gateway terminates TLS and extracts `tenant_id` directly from certificate `OU`.

---

## 4. Native Dynamic Sandbox Isolation Boundaries

To guarantee that detonated malware cannot compromise the virtualization host or lateral movement into corporate networks:

1. **Hypervisor Isolation**:
   - MicroVMs run under Firecracker / Cloud-Hypervisor utilizing Linux Kernel-based Virtual Machine (KVM) acceleration.
   - Host isolation is reinforced via `cgroups v2` (memory limits, CPU quota) and `seccomp-bpf` syscall whitelisting on the hypervisor runner process.
2. **Ephemeral Storage Layer**:
   - Each guest VM mounts a read-only base operating system image with an ephemeral `overlayfs` scratchpad backed by host memory.
   - Upon detonation termination, the overlay filesystem is wiped immediately; zero modified guest sectors persist to disk.
3. **Network Namespace Containment**:
   - Each guest VM connects exclusively to a dedicated virtual bridge (`br-sbx-{job_id}`) enclosed in an isolated Linux network namespace (`netns`).
   - Outbound egress defaults to **Isolated Airgap (TCP RST)** or is routed through an **INETSim service container** emitting synthetic HTTP/DNS responses.
   - Live internet access is strictly routed through an authenticated egress WireGuard proxy enforcing SSL inspection and rate limiting.

---

## 5. Role-Based Access Control (RBAC) Matrix

NivXForge enforces six (6) discrete operational roles:

| RBAC Role | Telemetry & Alerts | Process Tree & Trajectory | Live Query (osquery) | Sandbox Detonation | Host Isolation & Remediation | Policy & Agent Management |
|---|---|---|---|---|---|---|
| `SOC_TIER_1` | **Read** | **Read** | No Access | Submit Only | No Access | No Access |
| `SOC_TIER_2` | **Read / Edit** | **Read / Pivot** | Read Only | Submit & Analyze | Request Only | No Access |
| `THREAT_HUNTER` | **Read** | **Read / Pivot** | **Full Execute** | Submit & Analyze | No Access | Read Only |
| `DFIR_SPECIALIST` | **Read** | **Read / Pivot** | **Full Execute** | **Full Access** | Memory Dump Only | No Access |
| `INCIDENT_COMMANDER` | **Full Access** | **Full Access** | **Full Execute** | **Full Access** | **Approve & Execute** | Read Only |
| `SECURITY_ADMIN` | **Full Access** | **Full Access** | **Full Execute** | **Full Access** | **Full Access** | **Full Admin** |

---

## 6. Cryptographically Sealed Audit Ledger

All containment and remediation actions (Host Isolation, Process Termination, File Quarantine, Memory Dump) are committed to an append-only cryptographic ledger:

```json
{
  "ledger_entry_id": "iso-ledger-9f1b-confirmed",
  "tenant_id": "9f1b2c4d-88a2-4a7b-b891-99882244aa11",
  "sequence_number": 8412,
  "timestamp": "2026-09-05T00:39:10.114208Z",
  "action_type": "HOST_NETWORK_ISOLATION",
  "target_device_id": "9f1b2c4d-88a2-4a7b-b891-99882244aa11",
  "target_hostname": "WKS-FINANCE-09",
  
  "operator": {
    "user_id": "usr-admin-jp",
    "email": "jp@corp.internal",
    "rbac_role": "INCIDENT_COMMANDER",
    "client_ip": "10.0.1.42"
  },
  
  "safety_gate_verification": {
    "domain_controller_check": "PASSED (NON-DC)",
    "healthcare_icu_check": "PASSED (NON-ICU)",
    "controller_mtls_pinned": "VERIFIED (PORT 443 OPEN)"
  },
  
  "justification_note": "Active C2 beaconing and memory injection under Case #INC-2026-0841",
  
  "previous_entry_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "entry_signature": "MEQCIF98a7...31a2== (Ed25519 signature by NivXForge Root Key)"
}
```

* **Tamper Evidence**: Every entry contains `previous_entry_hash`, creating an unbroken Merkle hash chain. Any retroactive modification breaks verification.
