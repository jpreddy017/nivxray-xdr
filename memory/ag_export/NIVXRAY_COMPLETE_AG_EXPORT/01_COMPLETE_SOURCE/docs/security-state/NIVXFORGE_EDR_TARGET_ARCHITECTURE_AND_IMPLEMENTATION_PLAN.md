# NIVXFORGE EDR & XDR EXTENSIONS: TARGET ARCHITECTURE & IMPLEMENTATION PLAN
**Comprehensive Architectural Blueprint, Domain Specifications & Phased Implementation Roadmap**
**Document ID:** `NIVXFORGE-TARGET-ARCH-2026-09-05`
**Status:** Approved Master Architectural Specification
**Rule:** NO EVIDENCE → NO CLAIM · PRESERVE FROZEN CONTENT FABRIC & CORE ENGINES

---

## 1. Executive Vision & Architectural Philosophy

### 1.1 The Core Thesis
NivXRay XDR already possesses an industry-leading analytical, causal reasoning, and security state computing engine:
* **The 615-Object Content Fabric** across 16 domains (600 active certified + 15 synthetic validation scenarios).
* **The 59-Active Decoder Suite** performing multi-stage payload deobfuscation and family unpacking.
* **The 7-Stage Causal Investigation Pipeline**:
  $$\text{Evidence} \longrightarrow \text{Causality (IUE/ICE)} \longrightarrow \text{Security State FSM} \longrightarrow \text{Verdict} \longrightarrow \text{Impact} \longrightarrow \text{Intervention} \longrightarrow \text{Verification}$$
* **Investigation Knowledge Graph (IKG)** node-link causal graph reconstruction.

However, as proven by the technical truth audit, **NivXForge EDR and Sandbox capabilities are currently post-facto analytical projections or static decoders**, lacking live endpoint presence, dynamic hypervisor execution, and real-time behavioral baselining.

### 1.2 The Convergence Invariant
```text
                    ┌────────────────────────────────────────────────────────┐
                    │                      NivXRay XDR                       │
                    │               Operational Triage & Correlation         │
                    └───────────────────────────┬────────────────────────────┘
                                                │
       ┌───────────────┬────────────────┬───────┴────────┬───────────────┬───────────────┐
       ▼               ▼                ▼                ▼               ▼               ▼
 ┌───────────┐   ┌───────────┐    ┌───────────┐    ┌───────────┐   ┌───────────┐   ┌───────────┐
 │   EDR     │   │   UBAE    │    │    NDR    │    │   ITDR    │   │  Sandbox  │   │Cloud/Email│
 │(Endpoint) │   │ (Entity)  │    │ (Network) │    │(Identity) │   │(Detonate) │   │(Workloads)│
 └─────┬─────┘   └─────┬─────┘    └─────┬─────┘    └─────┬─────┘   └─────┬─────┘   └─────┬─────┘
       │               │                │                │               │               │
       └───────────────┴────────────────┼────────────────┴───────────────┴───────────────┘
                                        ▼
                  ┌───────────────────────────────────────────┐
                  │        Canonical Evidence Ingestion       │
                  │   (Envelope: Identity, Timestamp, Hash)   │
                  └─────────────────────┬─────────────────────┘
                                        ▼
                  ┌───────────────────────────────────────────┐
                  │      59-Decoder Deobfuscation Suite       │
                  │ (RTE: Multi-stage payload peeling ≤ 64KB) │
                  └─────────────────────┬─────────────────────┘
                                        ▼
                  ┌───────────────────────────────────────────┐
                  │      Causal Reasoning & Correlation       │
                  │         (IUE · ICE · IEDDE · UAIE)        │
                  └─────────────────────┬─────────────────────┘
                                        ▼
                  ┌───────────────────────────────────────────┐
                  │       615-Object Detection Content        │
                  │      (16 Native Content Evaluators)       │
                  └─────────────────────┬─────────────────────┘
                                        ▼
                  ┌───────────────────────────────────────────┐
                  │    Security State Computing Engine (FSM)  │
                  │ (AUTHORIZED → SUSPICIOUS → ABUSED → ATTACK)│
                  └─────────────────────┬─────────────────────┘
                                        ▼
                  ┌───────────────────────────────────────────┐
                  │         Deterministic Verdict Engine      │
                  │ (Stage-1 Heuristic + Stage-2 Calibration) │
                  └─────────────────────┬─────────────────────┘
                                        ▼
                  ┌───────────────────────────────────────────┐
                  │      IKG & Flagship Investigation Canvas  │
                  │   (Process Tree, Trajectory, Narrative)   │
                  └─────────────────────┬─────────────────────┘
                                        ▼
                  ┌───────────────────────────────────────────┐
                  │      Verified Closed-Loop Response        │
                  │  (Idempotent Approval → Action → Audit)   │
                  └───────────────────────────────────────────┘
```

**Cardinal Rule**: Neither EDR, UBAE, NDR, nor Sandbox will implement their own duplicate Verdict, IKG, or Rule Evaluation engines. They are **evidence providers** emitting standard telemetry. NivXRay Security Core evaluates all evidence uniformly.

---

## 2. NivXForge EDR: Target Architecture & Capability Mapping

The EDR foundation cannot start with response actions. Without a resident agent and streaming telemetry contract, isolation, process killing, files, and threat hunting remain empty abstractions. The build sequence strictly begins with **Agent Architecture $\to$ Endpoint Identity $\to$ Telemetry Ingestion**.

---

### EDR Capability 1: EDR Resident Agent
* **Current State:** `MISSING`. No binary, daemon, or service exists in the repository.
* **Industry Requirement:** Cross-platform resident sensor (Windows, Linux, macOS) operating with $<1\%$ CPU overhead, $<150\text{ MB}$ RAM footprint, user-space event filtering, and tamper-resistant heartbeat.
* **Target Design:** `nivxforge-sensor`
  - Windows: Native Windows Service in Go/Rust utilizing Event Tracing for Windows (ETW) via Microsoft-Windows-Kernel-Process, Microsoft-Windows-Kernel-File, Microsoft-Windows-Kernel-Network, and Microsoft-Windows-Kernel-Registry.
  - Linux: eBPF-based tracepoint collector (`sched_process_exec`, `sched_process_exit`, `vfs_write`, `tcp_connect`).
  - Safe user-space fallback buffer with disk-backed ring buffer (capped at 500MB).
* **Reuse:** Collector transport contracts (`apps/nivxray-xdr-collector`).
* **New Components:** `agent/src/core/`, `agent/src/etw/`, `agent/src/ebpf/`.
* **API Contract:**
  - `POST /api/edr/agent/heartbeat`
  - `POST /api/edr/agent/events/stream`
* **Evidence Contract:** Emits `SensorHeartbeatEnvelope` with OS, architecture, agent version, driver status, and tamper-check hash.
* **Dependencies:** None.
* **Priority:** **P0-A** (Foundational Pre-requisite).
* **Acceptance Test:** Sensor compiles, installs as a Windows Service, boots on system start, maintains $<1\%$ idle CPU, and buffers events during network disconnection.

---

### EDR Capability 2: Endpoint Registration, Identity & mTLS
* **Current State:** `PARTIAL`. `GET /edr/endpoints` is a read-only projection extracting hosts from saved MongoDB incident cases.
* **Industry Requirement:** Secure enrollment token exchange, automated certificate authority provisioning, mutual TLS (mTLS) session establishment, and hardware-bound host UUID.
* **Target Design:** `NivXForge Endpoint Registry Service`
  - Enrollment API validating a tenant-scoped, time-bounded enrollment key.
  - Automatic provisioning of endpoint mTLS client certificates (x509) signed by internal platform CA.
  - Device Fingerprinting: Machine GUID, BIOS UUID, primary MAC, Active Directory SID.
  - Persistent MongoDB Collection: `xdr_endpoints`.
* **Reuse:** `deps.py` auth framework, `xdr_rbac.py` tenant isolation.
* **New Components:** `backend/services/edr_identity/`, `backend/routers/edr_enrollment.py`.
* **API Contract:**
  - `POST /api/edr/enroll` `{"enrollment_token": "...", "machine_guid": "...", "hostname": "..."}` $\to$ `{cert_pem, key_pem, endpoint_id}`
  - `GET /api/edr/endpoints` $\to$ query real endpoint inventory (Status, Agent Version, Last Seen, IP, OS).
* **Evidence Contract:** `xdr_endpoints` document containing `endpoint_id`, `tenant_id`, `hostname`, `status` (`ONLINE`, `DEGRADED`, `OFFLINE`, `ISOLATED`), `enrolled_at`, `last_heartbeat`.
* **Dependencies:** Capability 1.
* **Priority:** **P0-A**.
* **Acceptance Test:** New endpoint enrolls using an admin-minted token, receives mTLS certificate, establishes secure connection, and updates `xdr_endpoints` within 2 seconds.

---

### EDR Capability 3: Endpoint Telemetry Streaming Contract
* **Current State:** `PARTIAL`. Syslog/webhook collectors exist; `v2/routers/ingest.py` only extracts command lines.
* **Industry Requirement:** High-throughput streaming of 5 core telemetry lanes: Process, File, Registry, Network Socket, and Script Blocks with strict JSON/Protobuf schemas.
* **Target Design:** `NivXForge Telemetry Streaming Pipe`
  - Ingestion endpoint accepting batched, compressed events over gRPC / HTTP/2 mTLS.
  - Standardized `EndpointEventEnvelope`:
    ```json
    {
      "tenant_id": "tenant-01",
      "endpoint_id": "ep-8941",
      "host": "WORKSTATION-04",
      "event_type": "PROCESS_SPAWN",
      "timestamp": "2026-09-05T00:15:30.120Z",
      "process": {
        "pid": 5120, "ppid": 4912, "name": "cmd.exe",
        "path": "C:\\Windows\\System32\\cmd.exe",
        "command_line": "cmd.exe /c powershell.exe -enc ...",
        "user": "CORP\\jdoe", "user_sid": "S-1-5-21-...",
        "integrity_level": "Medium", "hash_sha256": "3a8b..."
      }
    }
    ```
  - Immediate normalization into `xdr_canonical_events`.
* **Reuse:** `apps/nivxray-xdr-collector` buffering primitives, `backend/routers/xdr_ingest.py`.
* **New Components:** `backend/v2/ingestion/endpoint_stream.py`, `backend/routers/edr_telemetry.py`.
* **API Contract:**
  - `POST /api/edr/telemetry/batch` (HTTP/2 mTLS)
* **Evidence Contract:** Schema-validated `CanonicalEvent` with deterministic lane assignment (`process`, `file`, `registry`, `network`, `system`).
* **Dependencies:** Capabilities 1, 2.
* **Priority:** **P0-A**.
* **Acceptance Test:** Ingests 5,000 endpoint events per second per tenant with zero event drops, validating schema adherence and assigning event UUIDs.

---

### EDR Capability 4: Process Monitoring & Real-Time Ancestry
* **Current State:** `IMPLEMENTED` (in backend analytical projection). `ActivityInventory` & `v2.ancestry` accurately project parent-child trees from timeline events.
* **Industry Requirement:** Continuous process lifecycle tracking (spawn, exit, thread injection, token duplication, PPID spoofing detection).
* **Target Design:** Transition `ActivityInventory` from incident-batch calculation to an incremental streaming graph store.
  - Correlate `parent_pid` and `process_create_time` to prevent PID reuse collisions.
  - Detect PPID spoofing by comparing parent process creation token against actual ETW creator token.
* **Reuse:** `services.activity.projector.build_inventory`, `backend/v2/routers/ancestry.py`, `EdrProcessTreePage.jsx`.
* **New Components:** Incremental stream updater `backend/services/activity/incremental.py`.
* **API Contract:** `GET /api/edr/process-tree/{endpoint_id}?time_window=1h`
* **Evidence Contract:** `ProcessNode` with `entity_id`, `pid`, `ppid`, `real_creator_pid`, `spoofed`, `command_line`, `hash`.
* **Dependencies:** Capability 3.
* **Priority:** **P0-B**.
* **Acceptance Test:** Replays process tree including deliberate PPID spoofing; verifies tree displays true ancestry and highlights the spoofed parent.

---

### EDR Capability 5: Real-Time Filesystem & FIM Monitoring
* **Current State:** `SCAFFOLD`. `EdrFilesPage.jsx` renders a locked banner; backend file monitoring is absent.
* **Industry Requirement:** Real-time auditing of file drops, writes, renames, and deletions in critical directories (`System32`, `AppData`, `Startup`, `/bin`, `/etc`), accompanied by automatic SHA-256 computation and authenticode signature verification.
* **Target Design:** `NivXForge Filesystem Monitor`
  - Sensor ETW/eBPF file-driver hooking `FILE_CREATE`, `FILE_WRITE`, `FILE_DELETE`.
  - On write completion of executable extensions (`.exe`, `.dll`, `.sys`, `.ps1`, `.bat`, `.vbs`, `.elf`), sensor computes SHA-256 hash and checks digital signature (Authenticode).
  - Unhide and wire `EdrFilesPage.jsx` to consume real file events.
* **Reuse:** `backend/services/uaie` static file inspector, `backend/routers/files.py`.
* **New Components:** `backend/routers/edr_files.py`, `backend/services/edr/file_tracker.py`.
* **API Contract:** `GET /api/edr/endpoints/{endpoint_id}/files?filter=suspicious`
* **Evidence Contract:** `FileEvent` with `path`, `action`, `sha256`, `signer`, `is_signed`, `signed_by_msft`, `entropy`.
* **Dependencies:** Capabilities 1, 3.
* **Priority:** **P1**.
* **Acceptance Test:** Dropping an unsigned payload in `AppData\Local\Temp` triggers a file event with computed SHA-256 and surfaces on `EdrFilesPage.jsx` within 1 second.

---

### EDR Capability 6: Network Connections & Socket Telemetry
* **Current State:** `SCAFFOLD`. `EdrNetworkPage.jsx` is a locked banner; sockets are only inferred from decoded payload strings.
* **Industry Requirement:** Continuous process-attributed network socket logging: local IP/port, remote IP/port, protocol, byte counts, and associated process PID/path.
* **Target Design:** `NivXForge Socket & DNS Telemetry Engine`
  - Sensor captures `TCP_CONNECT`, `TCP_ACCEPT`, `UDP_SEND` attributed to originating PID.
  - Captures DNS query/response pairs (Query Name, Query Type, Resolved IPs, Return Code).
  - Unhide and wire `EdrNetworkPage.jsx` to render live connection streams.
* **Reuse:** `backend/routers/ioc_intelligence.py` for immediate IP/domain reputation scoring.
* **New Components:** `backend/routers/edr_network.py`, `backend/services/edr/socket_tracker.py`.
* **API Contract:** `GET /api/edr/endpoints/{endpoint_id}/network`
* **Evidence Contract:** `SocketEvent` with `src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol`, `domain`, `process_pid`, `process_name`.
* **Dependencies:** Capabilities 1, 3.
* **Priority:** **P1**.
* **Acceptance Test:** Outbound beaconing to external test IP creates a process-attributed socket record visible in the Network tab.

---

### EDR Capability 7: Live Query & Fleet osquery Coordination
* **Current State:** `SCAFFOLD`. `EdrLiveQueryPage.jsx` is locked; `ActionSpec("endpoint.live_query")` returns a simulation stub.
* **Industry Requirement:** Ad-hoc and scheduled SQL queries executed across the fleet (osquery / Velociraptor protocol) with query approval gates and structured tabular results.
* **Target Design:** `NivXForge Live Query Coordinator`
  - Sensor embeds osquery extension or native SQL engine (sqlite3 virtual tables for processes, sockets, services, users, autoruns).
  - Backend dispatches signed queries to target endpoint over the persistent mTLS tunnel.
  - Query execution requires RBAC scope `endpoint:query` and records audit entries.
* **Reuse:** `apps/nivxray-xdr-response` approval workflow and idempotency execution store.
* **New Components:** `backend/services/edr/live_query.py`, `backend/routers/edr_live_query.py`.
* **API Contract:**
  - `POST /api/edr/queries/execute` `{"query": "SELECT name, path, pid FROM processes WHERE on_disk = 0;", "endpoint_id": "..."}`
  - `GET /api/edr/queries/{query_id}/results`
* **Evidence Contract:** Structured tabular JSON results with execution duration and cryptographic signature.
* **Dependencies:** Capabilities 1, 2.
* **Priority:** **P1**.
* **Acceptance Test:** Analyst queries running processes without backing disk images; results return to UI within 3 seconds.

---

### EDR Capability 8: Real-Time Host Isolation (WFP / Netsh / eBPF)
* **Current State:** `PARTIAL`. Orchestration and approval drawer are implemented; execution is an `_stub_ok` simulation.
* **Industry Requirement:** Instant cryptographic network containment: drops all inbound/outbound IP traffic except for the NivXRay management tunnel and DNS. Reversible upon analyst authorization.
* **Target Design:** `NivXForge Real Network Isolation Driver`
  - Windows: Configures Windows Filtering Platform (WFP) sublayer or native netsh firewall rules allowing only the NivXRay controller IP/port.
  - Linux: Injects priority iptables/nftables rules dropping all traffic outside the controller subnet.
  - Reversal: Persistent `reversal_id` unlocks the firewall upon approved `unisolate` command.
* **Reuse:** `apps/nivxray-xdr-response/framework/executor.py`, `AnalystResponseDrawer.jsx`.
* **New Components:** `agent/src/response/isolation_windows.go`, `agent/src/response/isolation_linux.go`.
* **API Contract:** `POST /api/respond/execute` with `action_id: "endpoint.isolate"`
* **Evidence Contract:** Sealed `ResponseExecutionRecord` containing before/after network routing table and firewall rule confirmation.
* **Dependencies:** Capabilities 1, 2.
* **Priority:** **P0-B**.
* **Acceptance Test:** Triggering isolation cuts active web browsing while maintaining the live telemetry/response link; unisolating restores full connectivity.

---

### EDR Capability 9: File Quarantine & Process Containment
* **Current State:** `SCAFFOLD / MOCK`. Simulation stubs only.
* **Industry Requirement:** Atomic process termination (tree termination) and secure file quarantine (relocate file to encrypted, unmapped vault with restricted permissions).
* **Target Design:** `NivXForge Containment Realization`
  - Process Kill: Sensor invokes `TerminateProcess` / `SIGKILL` on the target PID and all active child processes.
  - File Quarantine: File is moved to `%ProgramData%\NivXForge\Quarantine\<sha256>`, XOR-encrypted with a platform key, and stripped of execute permissions.
* **Reuse:** `apps/nivxray-xdr-response` execution registry.
* **New Components:** `agent/src/response/quarantine.go`, `agent/src/response/kill.go`.
* **API Contract:** `POST /api/respond/execute` (`endpoint.kill_process`, `endpoint.quarantine_file`)
* **Evidence Contract:** SHA-256 verified quarantine receipt with original path, metadata, and ACL snapshot.
* **Dependencies:** Capabilities 1, 2.
* **Priority:** **P0-B**.
* **Acceptance Test:** Quarantined malware payload cannot be executed from disk; process tree termination kills target PID and spawned children immediately.

---

## 3. UBAE / UEBA: First-Class XDR Behavioral Intelligence

### 3.1 Architectural Positioning
User & Entity Behavioral Analytics (UBAE) is **not an EDR feature**. It is a **first-class XDR plane** that synthesizes evidence across endpoints, cloud providers, SaaS identities, and on-premises Active Directory.

```text
       Endpoints (EDR)           Cloud (AWS/GCP/Azure)         Identity (Entra/Okta/AD)
             │                             │                             │
             ▼                             ▼                             ▼
   Process & Host Context         API & IAM Audit Logs         Logins, Tokens & Sessions
             │                             │                             │
             └─────────────────────────────┼─────────────────────────────┘
                                           ▼
                       ┌───────────────────────────────────────┐
                       │          UBAE Analytics Core          │
                       │   (Dynamic Baselining & Anomaly FSM)  │
                       └───────────────────┬───────────────────┘
                                           ▼
                       ┌───────────────────────────────────────┐
                       │     Causal Behavioral State Machine   │
                       │ (BASELINE → ANOMALY → ABUSE → COMPROMISE)
                       └───────────────────┬───────────────────┘
                                           ▼
                       ┌───────────────────────────────────────┐
                       │        NivXRay Reasoning Core         │
                       │        (IUE · ICE · IKG Graph)        │
                       └───────────────────────────────────────┘
```

---

### 3.2 UBAE Capability Specifications

#### UBAE-1: Multi-Dimensional Entity Modeling
* **Entities Modeled:**
  1. **User Accounts**: Interactive corporate users, VIP/executives, contractors.
  2. **Service Accounts**: Non-interactive system accounts, CI/CD runners, scheduled task identities.
  3. **Endpoints / Devices**: Laptops, servers, domain controllers, production bastions.
  4. **Applications**: SaaS apps (Office 365, GitHub, Salesforce), local administrative utilities.
* **Design:** Entity 360 profile aggregating historical activity windows (7d, 14d, 30d, 90d).

#### UBAE-2: Dynamic Behavioral Baselining (Zero Static Thresholds)
* **Statistical Baselines:**
  - **Working Hours & Geography**: Expected logon hours, typical source IP ranges, geovelocity (impossible travel).
  - **Host Affinity**: Which machines does this user normally access? Does a developer suddenly RDP into a financial database?
  - **Process Execution Norms**: Which processes does this service account execute? (e.g. IIS app pool worker spawning `whoami.exe` or `powershell.exe` represents an immediate anomalous deviation).
  - **Volume & Velocity**: Average bytes transferred per day, average files accessed, typical directory read operations.

#### UBAE-3: Causal Behavioral Progression Model
Beyond traditional UEBA ("User score is 85"), NivXRay UBAE maps anomalies into the causal attack lifecycle:
1. **Behavioral Divergence**: First observed deviation from 30-day baseline (e.g. logon at 03:00 AM from atypical ASN).
2. **Privilege Transition**: User identity escalates or impersonates an unmanaged/privileged token.
3. **Capability Repurposing**: Trusted dual-use tool (PowerShell, AnyDesk, RDP) executed in an anomalous operational context.
4. **Reachability Traversal**: Entity accesses assets containing crown-jewel tags outside its established authorization graph.

#### UBAE-4: Integration with NivXRay Reasoning Core
* **Evidence Ingestion**: UBAE emits `BehavioralAnomalyEvent` into Canonical Evidence.
* **IKG Projection**: Entity nodes in the Investigation Knowledge Graph are enriched with behavioral risk vectors.
* **Verdict Engine Calibration**: UBAE anomaly scores adjust the positive/negative explainability offsets in the Verdict Engine without overriding deterministic detection rules.

---

## 4. Native Dynamic Sandbox: Architecture & Isolation Plan

### 4.1 Ground Rule
**The Sandbox produces dynamic evidence; it does NOT formulate verdicts.**
Dynamic telemetry produced in the sandbox flows directly into the platform's Canonical Ingestion pipe, where the **frozen 615-object Content Fabric**, 59 decoders, and Security State FSM evaluate it identically to live production telemetry.

---

### 4.2 Sandbox Architecture

```text
               ┌────────────────────────────────────────────────────────┐
               │              NivXRay Sandbox Orchestrator              │
               │        (Queue · Detonation Profile · Dispatcher)       │
               └───────────────────────────┬────────────────────────────┘
                                           │
                                           ▼
               ┌────────────────────────────────────────────────────────┐
               │             Disposable MicroVM / QEMU-KVM              │
               │   ┌────────────────────────────────────────────────┐   │
               │   │               Guest OS Environment             │   │
               │   │     (Windows 10/11 x64 · Clean Golden Image)   │   │
               │   │                                                │   │
               │   │   [Artifact Detonation Target]                 │   │
               │   │              │                                 │   │
               │   │              ▼                                 │   │
               │   │   [Guest Sensor / Hooking Engine]              │   │
               │   │   • Kernel ETW / Minifilter driver             │   │
               │   │   • User-space API hook DLL (ntdll/kernel32)   │   │
               │   │   • Anti-evasion RDTSC/Sleep dilator           │   │
               │   └──────────────────────┬─────────────────────────┘   │
               └──────────────────────────┼─────────────────────────────┘
                                          │  VirtIO / Serial Stream
                                          ▼
               ┌────────────────────────────────────────────────────────┐
               │             Isolated Network Simulation Gateway        │
               │   • INetSim (DNS/HTTP/SMTP/FTP responses)              │
               │   • MITM TLS Decryption Proxy                          │
               │   • PCAP Capture Ring Buffer (tcpdump)                 │
               │   • Suricata Signature Evaluator                       │
               └──────────────────────────┬─────────────────────────────┘
                                          │
                                          ▼
               ┌────────────────────────────────────────────────────────┐
               │              Dynamic Evidence Synthesizer              │
               │  (Normalizes VM events into CanonicalEnvelope Stream)  │
               └──────────────────────────┬─────────────────────────────┘
                                          │
                                          ▼
               ┌────────────────────────────────────────────────────────┐
               │            Platform Canonical Evidence Pipe            │
               │      (→ 59 Decoders → IUE → ICE → 615 Rules → IKG)     │
               └────────────────────────────────────────────────────────┘
```

---

### 4.3 Sandbox Core Subsystems

#### SB-1: Isolated Detonation Hypervisor Core
* **Technology**: QEMU / KVM with MicroVM architecture or libvirt orchestration.
* **Golden Images**: Windows 11 Enterprise x64, Windows 10 x64, Ubuntu 22.04 LTS.
* **Snapshot Rollback**: Copy-on-write (qcow2 overlay) disposable execution. Rolling back to clean baseline takes $<1.5\text{ seconds}$.

#### SB-2: Guest Instrumentation & Behavioral Tracing
* **Hooking Layer**:
  - Minifilter driver monitoring all filesystem create/write/delete operations.
  - Inline API hooking on sensitive DLLs (`ntdll.dll`, `kernelbase.dll`, `advapi32.dll`, `ws2_32.dll`, `wininet.dll`) to intercept process creation, memory allocation (`VirtualAllocEx` with `PAGE_EXECUTE_READWRITE`), and process hollowing.
* **Anti-Evasion Hardening**:
  - Time Dilation: Intercept `Sleep`, `NtDelayExecution`, and `RDTSC` assembly instructions to accelerate malware wait loops without detection.
  - Human Emulation: Synthetic cursor jitter, document scrolling, and dialog prompt dismissal (e.g. clicking "Enable Editing", "OK").
  - Hypervisor Cloaking: Redact QEMU/KVM artifacts from registry, ACPI tables, and device manager.

#### SB-3: Network Simulation & TLS Interception
* **Fake Internet (INetSim)**: Provides authentic responses for standard protocols (HTTP 200, DNS A-records, SMTP banner, NTP sync).
* **TLS Decryption**: Transparent MITM proxy injecting a custom Root CA into the guest VM, recording full plaintext HTTP request/response payloads, headers, and downloaded secondary stages.
* **PCAP & IDS**: Full packet capture saved per detonation; Suricata inspects network traffic for known C2 signatures.

#### SB-4: Memory Extraction & Config Decoding
* **Memory Dump**: Dumps memory spaces of suspicious injected processes (e.g. unmapped PEs, hollowed processes).
* **Config Extraction**: Feeds extracted memory strings and dropped files directly into the platform's **59 registered decoders** to unpack family configs (RedLine, AgentTesla, Lumma, Cobalt Strike beacon configs).

#### SB-5: Interactive Analyst Console ("Glovebox")
* **Interactive Steering**: In-browser low-latency canvas (WebRTC / Apache Guacamole) allowing the analyst to interact directly with the detonating sample, solve CAPTCHAs, enter passwords, and guide execution.
* **Frame Recording**: Records MP4 video and timestamped milestone screenshots for the attack story canvas.

---

## 5. Master Implementation Roadmap & Build Phases

To ensure stability and enforce technical discipline, development proceeds in strict dependency order. **EDR foundations precede sandbox hypervisors, and agent presence precedes response realization.**

```text
========================================================================================
PHASE 0: FOUNDATION & DATA-BINDING INTEGRITY (Immediate Gate)
========================================================================================
  [0.1] Purge SAMPLE_ARTIFACTS fallback from Evidence Explorer (XdrEvidenceExplorerPage.jsx).
  [0.2] Bind Evidence Explorer dynamically to GET /api/v2/cases/{id}/artifacts.
  [0.3] Implement honest EMPTY and ERROR state banners across all investigation surfaces.
  [0.4] Connect Investigation Workspace sub-tabs 2–8 to dynamic case data endpoints.

========================================================================================
PHASE 1: NIVXFORGE EDR CORE SENSOR & TELEMETRY FOUNDATION
========================================================================================
  [1.1] NivXForge Sensor Core (Windows ETW + Linux eBPF user-space service).
  [1.2] Endpoint Identity & Enrollment (mTLS certificate issuance & persistent xdr_endpoints).
  [1.3] High-throughput Streaming Ingestion (HTTP/2 mTLS endpoint telemetry pipeline).
  [1.4] Real-time Process Ancestry & PPID Spoofing Detection.
  [1.5] Real-time Filesystem & FIM Monitoring (Unhide & wire EdrFilesPage.jsx).
  [1.6] Real-time Network Socket & DNS Monitoring (Unhide & wire EdrNetworkPage.jsx).

========================================================================================
PHASE 2: EDR CONTAINMENT REALIZATION & THREAT HUNTING
========================================================================================
  [2.1] Real Network Isolation Driver (WFP sublayer / iptables containment).
  [2.2] Real Process Termination & Encrypted File Quarantine Vault.
  [2.3] Live Query Engine (osquery extension & signed query coordinator).
  [2.4] Remote Forensic Triage Collector (MFT, Prefetch, Shimcache acquisition).
  [2.5] Live Vendor Adapters (CrowdStrike Falcon & MDE real API containment).

========================================================================================
PHASE 3: UBAE / UEBA ANALYTICS ENGINE (First-Class XDR Plane)
========================================================================================
  [3.1] Multi-Dimensional Entity 360 Profiler (Users, Services, Hosts, SaaS).
  [3.2] Statistical Dynamic Baselining Engine (Working hours, geo-velocity, process norms).
  [3.3] Behavioral State Machine (BASELINE → ANOMALY → ABUSE → COMPROMISE).
  [3.4] Integration with IKG Graph & Verdict Explainability Offsets.

========================================================================================
PHASE 4: NATIVE DYNAMIC SANDBOX (Detonation & Dynamic Evidence)
========================================================================================
  [4.1] Hypervisor Controller (QEMU-KVM MicroVM lifecycle & CoW snapshot rollback).
  [4.2] Guest Instrumentation & Kernel API Hooking (ETW, Minifilter, Memory Alloc).
  [4.3] Isolated Network Gateway (INetSim, MITM TLS decryptor, PCAP, Suricata).
  [4.4] Anti-Evasion Countermeasures (Time dilation, sleep acceleration, human simulation).
  [4.5] Dynamic-to-Canonical Evidence Synthesizer (Feeds 59 decoders & 615 Content Fabric).
  [4.6] Interactive Analyst Glovebox (WebRTC browser console & video session replay).
========================================================================================
```

---

## 6. Verification Plan & Architectural Acceptance Criteria

Every capability must satisfy its formal acceptance criteria before the phase is considered complete:

1. **Zero Mock Invariant**: No page in the UI may render hardcoded fallback arrays (`SAMPLE_*`). Empty states must explicitly display `NO MATCHING EVIDENCE`.
2. **Deterministic Provenance Invariant**: Every detection, process node, socket event, and sandbox artifact must carry an immutable source reference, timestamp, and SHA-256 hash.
3. **Reasoning Engine Isolation**: EDR and Sandbox modules must compile and run as telemetry producers without importing or duplicating Verdict, IKG, or Rule Engine code.
4. **Frozen Fabric Preservation**: All 615 content objects in `backend/detection_content/corpus/` and all 59 registered decoders in `backend/decoders/` must remain byte-identical throughout all phases.
