# NIVXFORGE EDR: ACTIONABLE ENGINEERING PHASE BACKLOG
**Emergent Sprint Backlog, User Stories, Technical Tasks, Inputs, Outputs, and Definition of Done (P0 through P4)**  
**Document ID:** `NIVXFORGE-BACKLOG-2026-09-05`  
**Classification:** Governing Engineering Handoff Pack  
**Handoff Status:** 🟢 APPROVED & READY FOR EMERGENT INTEGRATION REVIEW  

---

## 1. Executive Statement

This backlog translates the architectural contracts into an actionable, sequential engineering work breakdown for **Emergent**. Work is structured across five sequential phases (P0 to P4) with strict dependencies, explicit technical tasks, and verifiable **Definitions of Done (DoD)**.

---

## 2. Phase P0: Integration Foundation

**Objective**: Wire the XDR Shell navigation, establish the Telemetry Gateway skeleton, and enforce server-side tenancy context before sensor driver implementation.

### Stories & Tasks:
* **EPIC P0-1: XDR Shell & Navigation Wiring**
  - `TASK-P0-1.1`: Register `/edr/*` and `/sandbox/*` routes inside `apps/nivxray-xdr/src/xdr/XdrShell.jsx`.
  - `TASK-P0-1.2`: Register new capabilities in `apps/nivxray-xdr/src/xdr/capabilityRegistry.js`.
  - `TASK-P0-1.3`: Mount `XdrEdrOverviewPage`, `XdrEndpointsPage`, and `SandboxIntakePage` shells.
* **EPIC P0-2: Telemetry Gateway & Normalization Skeleton**
  - `TASK-P0-2.1`: Implement FastAPI router `POST /api/v2/edr/telemetry/stream` in `backend/routers/edr.py`.
  - `TASK-P0-2.2`: Bind request context middleware to extract `tenant_id` server-side from JWT claims.
  - `TASK-P0-2.3`: Implement schema validator for the Common Envelope (`NIVXFORGE_EDR_CANONICAL_EVIDENCE_CONTRACT.md`).
* **EPIC P0-3: Evidence Binding Integration**
  - `TASK-P0-3.1`: Wire validated incoming telemetry into `backend/routers/artifacts.py`.
  - `TASK-P0-3.2`: Ensure `XdrEvidenceExplorerPage.jsx` renders live ingested telemetry with zero synthetic fallbacks.

**Definition of Done (DoD) for P0**:
- Running `POST /api/v2/edr/telemetry/stream` with a valid JWT stores evidence in the database under the correct tenant ID.
- Evidence Explorer displays the newly ingested event within 500ms.
- 615 Content Fabric and 59 decoders pass verification audits 100%.

---

## 3. Phase P1: EDR Sensor Agent & Telemetry Streaming

**Objective**: Develop the cross-platform endpoint sensor daemon and streaming pipeline for Windows and Linux.

### Stories & Tasks:
* **EPIC P1-1: Endpoint Enrollment & PKI mTLS**
  - `TASK-P1-1.1`: Implement sensor CSR generation and enrollment handler in `src/sensor/enrollment/`.
  - `TASK-P1-1.2`: Implement Gateway mTLS listener on port 8443 with client certificate validation.
  - `TASK-P1-1.3`: Implement local SQLite ring-buffer (250 MB) for offline telemetry persistence.
* **EPIC P1-2: Windows Sensor Telemetry Collector (C++ / Rust)**
  - `TASK-P1-2.1`: Implement kernel minifilter hook `PsSetCreateProcessNotifyRoutineEx` for process tracking.
  - `TASK-P1-2.2`: Implement ETW providers for `Microsoft-Windows-Kernel-File`, `Microsoft-Windows-Kernel-Network`, and `Microsoft-Windows-Kernel-Registry`.
  - `TASK-P1-2.3`: Implement authenticode digital signature verifier for executed binaries.
* **EPIC P1-3: Linux Sensor Telemetry Collector (eBPF)**
  - `TASK-P1-3.1`: Implement eBPF probe on `sys_enter_execve` / `sys_enter_execveat` for process tracking.
  - `TASK-P1-3.2`: Implement eBPF kprobe/kretprobe on `tcp_v4_connect` and `sock_sendmsg` for network socket monitoring.
  - `TASK-P1-3.3`: Package sensor as systemd daemon (`nivx-sensor.service`) with auto-restart.

**Definition of Done (DoD) for P1**:
- Sensor daemon installs cleanly on Windows 11 and Ubuntu 22.04 LTS.
- Live process launches, file writes, and outbound TCP sockets appear in the Telemetry Gateway at $\ge 1{,}000\text{ EPS}$.
- Agent maintains $<2\%$ CPU utilization and $<150\text{ MB}$ RAM footprint under load.

---

## 4. Phase P2: EDR Investigation & Deep Analytics

**Objective**: Implement the microsecond 5-lane trajectory replay, interactive process tree, and distributed live query engine.

### Stories & Tasks:
* **EPIC P2-1: 5-Lane Device Trajectory Replay Engine**
  - `TASK-P2-1.1`: Create backend aggregator `GET /api/v2/trajectory/:id` sorting events into Process, Net, File, Reg, and System lanes.
  - `TASK-P2-1.2`: Implement React timeline scrubber component with Play/Pause, speed multipliers ($1\times, 5\times, 20\times$).
  - `TASK-P2-1.3`: Implement raw ETW/eBPF canonical JSON drawer on event click.
* **EPIC P2-2: Interactive Process Tree Canvas**
  - `TASK-P2-2.1`: Build directed parent-child tree generator linking `ppid` to `pid` in `backend/routers/process_tree.py`.
  - `TASK-P2-2.2`: Implement SVG hierarchy renderer in `apps/nivxray-xdr/` with LOLBAS and memory injection badges.
  - `TASK-P2-2.3`: Wire right-click context actions (`Detonate in Sandbox`, `Inspect Hash`, `Terminate Process`).
* **EPIC P2-3: Distributed Live Query (osquery) Integration**
  - `TASK-P2-3.1`: Implement osquery daemon management bridge in sensor agent.
  - `TASK-P2-3.2`: Build query dispatch router `POST /api/v2/edr/fleet/live-query` with progress tracking.
  - `TASK-P2-3.3`: Build interactive SQL query editor with template presets in XDR UI.

**Definition of Done (DoD) for P2**:
- Replaying a process execution shows concurrent network connections and file modifications aligned on the 5-lane timeline.
- An analyst can run an ad-hoc SQL query across 48 online endpoints and receive aggregated tabular results within 2 seconds.

---

## 5. Phase P3: User & Entity Behavior Analytics (UBAE / UEBA)

**Objective**: Establish continuous identity and machine behavioral baselines and project anomaly scores into the IKG.

### Stories & Tasks:
* **EPIC P3-1: Entity 360 & Baseline Engine**
  - `TASK-P3-1.1`: Implement user session aggregator tracking interactive (Type 2), network (Type 3), and RDP (Type 10) logins.
  - `TASK-P3-1.2`: Build 14-day rolling activity baseline for user accounts and service accounts.
  - `TASK-P3-1.3`: Mount `XdrEndpoint360Page.jsx` and `XdrUbaeContextPage.jsx` in XDR UI.
* **EPIC P3-2: Behavioral Anomaly Detection & IKG Enrichment**
  - `TASK-P3-2.1`: Implement anomaly detectors for off-hours logins, peer group deviations, and lateral RDP hops.
  - `TASK-P3-2.2`: Project identity anomaly edges into `backend/routers/attack_graph.py` (IKG).
  - `TASK-P3-2.3`: Bind UBAE risk scores into the Authoritative Security State evaluation pipeline.

**Definition of Done (DoD) for P3**:
- A simulated off-hours RDP logon triggers a behavioral anomaly and elevates user risk score.
- The IKG renders an enriched identity node connected to the target workstation.

---

## 6. Phase P4: Native Dynamic Sandbox Subsystem

**Objective**: Deploy the isolated hypervisor detonation runner and closed-loop convergence bridge to the 59-decoder suite.

### Stories & Tasks:
* **EPIC P4-1: Hypervisor Orchestration & Guest Hardening**
  - `TASK-P4-1.1`: Implement MicroVM orchestration runner using Firecracker / Cloud-Hypervisor.
  - `TASK-P4-1.2`: Implement guest anti-evasion hooks (mouse jitter, human typing, uptime virtualization $>72\text{h}$).
  - `TASK-P4-1.3`: Build INETSim network container bridge and WireGuard outbound egress proxy.
* **EPIC P4-2: Guest Instrumentation & Live Telemetry Stream**
  - `TASK-P4-2.1`: Implement Windows kernel minifilter hook streaming low-level syscalls (`NtAllocateVirtualMemory`, etc.).
  - `TASK-P4-2.2`: Stream live guest display frames via WebSockets to `SandboxLiveConsolePage.jsx`.
  - `TASK-P4-2.3`: Build 6-subtab forensic report generator (Process, Net, File, Reg, Memory, Config).
* **EPIC P4-3: Convergence Bridge & 59-Decoder Integration**
  - `TASK-P4-3.1`: Build automated forwarder dispatching dropped secondary payloads to `POST /api/decode/smart`.
  - `TASK-P4-3.2`: Implement 1-click fleet IOC blocklist push to all active EDR sensor agents.
  - `TASK-P4-3.3`: Commit dynamic PCAP, memory dump, and execution trace to the Evidence Vault under active case ID.

**Definition of Done (DoD) for P4**:
- Submitting a Cobalt Strike dropper spawns a MicroVM in $<500\text{ms}$.
- Live syscall feed displays memory injection hooks in real-time.
- Dropped secondary script is automatically decoded by the 59-decoder suite, extracting the plaintext C2 IP.
