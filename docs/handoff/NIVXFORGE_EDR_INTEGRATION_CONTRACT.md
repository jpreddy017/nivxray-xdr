# NIVXFORGE EDR: INTEGRATION & PIPELINE DATAFLOW CONTRACT
**Architectural Contract Governing Dataflow, Ingestion Pipelines, Engine Boundaries, and Sandbox Subsystem Integration**  
**Document ID:** `NIVXFORGE-INT-CONTRACT-2026-09-05`  
**Classification:** Governing Engineering Handoff Pack  
**Handoff Status:** 🟢 APPROVED & READY FOR EMERGENT INTEGRATION REVIEW  

---

## 1. Executive Statement & Subsystem Architecture

This contract establishes the formal dataflow and pipeline boundaries connecting **NivXForge EDR Sensor Agents** and the **Native Dynamic Sandbox** into the **NivXRay Core Reasoning Platform**.

### Core Architecture Invariant:
$$\text{Sensor Telemetry / Sandbox Traces} \longrightarrow \text{Canonical Evidence Vault} \longrightarrow \text{NivXRay Core Reasoning} \longrightarrow \text{Closed-Loop Response}$$

> [!CRITICAL]
> **Boundary Rule for the Native Sandbox**: The Sandbox functions strictly as an **evidence-producing execution subsystem**. It executes untrusted binaries inside isolated microVMs/QEMU instances and emits low-level execution telemetry (syscalls, network flows, dropped files, memory modifications) directly into the Canonical Evidence Vault. It does **NOT** build or maintain its own reasoning, correlation, IKG, or verdict calculation engine.

---

## 2. End-to-End EDR Telemetry Ingestion Pipeline

The diagram below details the authoritative sequential flow from endpoint kernel sensors into the NivXRay reasoning and response engines:

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                    NIVXFORGE ENDPOINT SENSOR (WIN / LINUX)                  │
│  Kernel Driver (Minifilter / eBPF) + Local SQLite Ring Buffer (250 MB)      │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ mTLS 1.3 Streaming (Batch 500ms / 100 evts)
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      TELEMETRY INGESTION GATEWAY (:8443)                    │
│  Validates Client X.509 Cert · Extracts Tenant Context · Rejects Spoofing   │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ Raw Event Stream
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                       PARSER & NORMALIZATION ENGINE                         │
│  Transforms Raw ETW/eBPF events into Canonical Evidence Schemas             │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ Normalized JSON
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                   CANONICAL EVIDENCE STORE (IMMUTABLE LEDGER)               │
│  Calculates SHA-256 Digest · Assigns Evidence UUID · Stores Raw & Canonical │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ Evidence Event Stream
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        NIVXRAY CORE REASONING LAYER                         │
│                                                                             │
│   1. IUE (Identity Understanding Engine - Lanes A, B, C)                    │
│      Resolves process, user, and device identity context.                   │
│                                                                             │
│   2. ICE (Investigation Correlation Engine) & 615 Content Fabric            │
│      Evaluates behavioral Sigma/YARA-L rules against incoming telemetry.    │
│                                                                             │
│   3. IKG (Incremental Knowledge Graph)                                      │
│      Updates causal DAG linking processes, files, sockets, and techniques.  │
│                                                                             │
│   4. Authoritative Security State Engine                                    │
│      Evaluates compromised posture (strictly decoupled from verdict score). │
│                                                                             │
│   5. Deterministic Verdict Engine                                           │
│      Calculates mathematically verifiable verdict without proxy weights.    │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ Case State & Recommendations
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                       INVESTIGATION WORKSPACE (UI/UX)                       │
│  Analyst explores 8-stage causal tabs · Triggers response intervention      │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ Safety-Gated Action Dispatched
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                  RESPONSE & CONTAINMENT CENTER (EDR DRIVERS)                │
│  Executes Safety Gate Check (Non-DC / Non-ICU) · Issues Kernel Isolation    │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ Post-Containment Telemetry
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                       VERIFICATION & AUDIT LEDGER                           │
│  Confirms packet drop via sensor telemetry · Seals action in tamper-proof log│
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Native Dynamic Sandbox Integration Pipeline

The Native Dynamic Sandbox executes under an on-demand, closed-loop evidence production lifecycle:

```text
[ Investigation Workspace / EDR Fleet / Detection Rule ]
                          │
                          │ POST /api/v2/sandbox/detonate
                          ▼
[ Sandbox Orchestration Controller ]
  - Allocates Isolated Hypervisor Guest (Firecracker MicroVM or QEMU/KVM)
  - Configures Network Simulation (Airgap, INETSim, or WireGuard Proxy)
  - Applies Anti-Evasion Hardening (Mouse jitter, uptime offset >72h)
                          │
                          ▼
[ Guest Virtual Machine Execution ]
  - Malware detonates in guest OS (Windows 11 / Windows 10 / Ubuntu)
  - In-guest instrumentation hooks kernel syscalls (NtAllocateVirtualMemory, etc.)
  - Hypervisor captures network packets (PCAP) and physical memory
                          │
                          │ Real-time Stream: Syscalls, Net Sockets, Dropped Files
                          ▼
[ Sandbox Telemetry Ingestion Bridge ]
  - Normalizes dynamic traces to Canonical Evidence format
  - Commits artifacts (PCAP, Memory Dump, Screenshots) to Evidence Store
                          │
                          ├───► [ 1-Click 59-Decoder Pipeline ]
                          │     Secondary dropped scripts forwarded for deobfuscation
                          │
                          ▼
[ NivXRay Core Platform ]
  - Dynamic evidence binds directly into active XDR Investigation Case
  - IKG projects dynamic execution nodes onto attack graph
  - Security State and Verdict recalculate deterministically based on real proof
```

---

## 4. API Route Contracts

### 4.1 EDR Telemetry Gateway
* **Route**: `POST /api/v2/edr/telemetry/stream`
* **Transport**: HTTPS / gRPC with Mutual TLS 1.3 (mTLS).
* **Headers**:
  - `Content-Type`: `application/json` or `application/x-protobuf`
  - `X-Sensor-ID`: `<UUID>`
  - `X-Sensor-Version`: `2.4.0`
  - `X-Sensor-Timestamp`: `ISO-8601 UTC`
* **Payload Format**:
```json
{
  "batch_id": "9f1b2c4d-88a2-4a7b-b891-99882244aa11",
  "sensor_id": "c4d3b2a1-0000-4a7b-9999-112233445566",
  "event_count": 2,
  "events": [
    {
      "event_type": "process_create",
      "timestamp": "2026-09-05T00:38:12.441920Z",
      "event_data": {
        "process_guid": "wks09:4912:1788581256",
        "parent_process_guid": "wks09:4110:1788581250",
        "pid": 4912,
        "ppid": 4110,
        "image_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "command_line": "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand WwBTAHk...",
        "user_sid": "S-1-5-21-39482910-2918239-1002",
        "username": "CORP\\jdoe",
        "sha256": "419c225566d6054d38fe5ee5c01bd9d2bdfedf79a312dd15ae71646e322255ae"
      }
    }
  ]
}
```
* **Response**: `202 Accepted` with `{"status": "queued", "accepted_events": 2}`.

### 4.2 Distributed Live Query (osquery) Dispatch
* **Route**: `POST /api/v2/edr/fleet/live-query`
* **Authorization**: RBAC `SOC_ANALYST_TIER_2` or higher.
* **Payload Format**:
```json
{
  "query": "SELECT pid, name, cmdline, path FROM processes WHERE name LIKE '%powershell%'",
  "target_scope": {
    "filter_type": "all_online"
  },
  "timeout_seconds": 30
}
```
* **Response**:
```json
{
  "job_id": "lq-2026-09-05-99812",
  "target_sensor_count": 48,
  "status": "DISPATCHED"
}
```

### 4.3 Native Dynamic Sandbox Detonation
* **Route**: `POST /api/v2/sandbox/detonate`
* **Payload Format**:
```json
{
  "case_id": "INC-2026-0841",
  "sample_artifact_id": "art-sha256-419c2255",
  "environment": "win11_x64_enterprise",
  "hypervisor_profile": "microvm_fast",
  "network_mode": "inetsim_emulated",
  "duration_seconds": 180,
  "anti_evasion": {
    "mouse_jitter": true,
    "human_typing": true,
    "uptime_offset_hours": 72
  }
}
```
* **Response**:
```json
{
  "detonation_job_id": "sbx-job-88129-441a",
  "status": "PROVISIONING_VM",
  "live_trace_stream_url": "/api/v2/sandbox/jobs/sbx-job-88129-441a/trace"
}
```

---

## 5. Resilience, Backpressure, and Error Handling

1. **Sensor Disconnection**: When network connectivity to Gateway:8443 is severed, the sensor agent buffers events in its local encrypted SQLite ring-buffer (maximum $250\text{ MB}$). Once capacity is reached, oldest low-priority events (file reads) are dropped first; process executions, logins, and network sockets are preserved.
2. **Gateway Throttling**: The gateway monitors ingestion queue depth. If backpressure exceeds $80\%$ buffer capacity, the gateway returns HTTP `429 Too Many Requests` with a `Retry-After: <seconds>` header. Sensors back off exponentially ($1\text{s}, 2\text{s}, 4\text{s}, \dots, 30\text{s}$).
3. **Idempotency**: Every telemetry event contains a deterministic `event_id` derived from `hash(sensor_id + timestamp + event_type + process_guid + sequence)`. Duplicate deliveries are deduplicated at the Normalization stage without polluting the Evidence Vault.
