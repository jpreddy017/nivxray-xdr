# NIVXFORGE EDR: ATTACK-CHAIN UX INTERACTION & PIVOT MATRIX
**End-to-End Investigation Walkthrough, Pivot Specifications, and Evidence Flow Contracts**  
**Document ID:** `NIVXFORGE-ATTACK-CHAIN-UX-2026-09-05`  
**Classification:** Operational UI/UX Contract Baseline  
**Companion Artifacts:**
* Prototype: [`NIVXFORGE_EDR_SANDBOX_OPERATIONAL_PROTOTYPE.html`](file:///d:/Projects/docs/uiux/NIVXFORGE_EDR_SANDBOX_OPERATIONAL_PROTOTYPE.html)
* Information Architecture: [`NIVXFORGE_EDR_INFORMATION_ARCHITECTURE.md`](file:///d:/Projects/docs/uiux/NIVXFORGE_EDR_INFORMATION_ARCHITECTURE.md)
* Parity Matrix: [`NIVXFORGE_EDR_EXHAUSTIVE_UIUX_PARITY_MATRIX.md`](file:///d:/Projects/docs/uiux/NIVXFORGE_EDR_EXHAUSTIVE_UIUX_PARITY_MATRIX.md)
* UI/UX Spec: [`NIVXFORGE_EDR_SANDBOX_UIUX_SPEC.md`](file:///d:/Projects/docs/uiux/NIVXFORGE_EDR_SANDBOX_UIUX_SPEC.md)

---

## 1. Executive Statement & Architectural Contract

In enterprise security operations, investigations fail when analysts encounter cognitive dead-ends—points where an analyst must manually copy-paste an IP, file hash, or host GUID between siloed applications.

NivXForge EDR enforces an **unbroken, bidirectional attack-chain traversal model**. Every node in an investigation graph exposes explicit, context-preserving pivots that carry investigation state forward.

### The Canonical Reasoning Flow Invariant:
```text
Telemetry
   ↓
Canonical Evidence (Raw ETW/eBPF/Sandbox Trace)
   ↓
IUE / ICE (Identity & Correlation Engines)
   ↓
IKG (Incremental Knowledge Graph)
   ↓
Security State (Authoritative Assessment)
   ↓
Deterministic Verdict (Calculated without synthetic weight fabrication)
   ↓
Investigation Workspace
   ↓
Intervention (Safety-Gated Response)
   ↓
Verification (Audit Ledger & Telemetry Proof)
```

> [!IMPORTANT]
> **Sandbox Architectural Boundary**: The Native Dynamic Sandbox functions strictly as an **evidence-producing subsystem**. It detonates samples in isolated hypervisors and emits raw telemetry (processes, syscalls, network sockets, dropped files) into the canonical Evidence Vault. It does **not** host an independent reasoning or verdict engine.

---

## 2. The 20-Step Canonical Attack-Chain Pivot Matrix

The table below maps the complete 20-step investigation lifecycle from initial triage to post-remediation verification. Every arrow is bound to a concrete UI trigger, context parameters, destination surface, and cognitive question.

| Step | Transition Arrow | Source Surface | Trigger UI Element | Destination Surface | Context Parameters Passed | Analyst Cognitive Question Answered |
|---|---|---|---|---|---|---|
| **1** | `Detection → Alert Detail` | `/edr/detections` | Click Alert Row or "Inspect Alert" button | `/edr/detections/:alertId` | `alert_id`, `rule_id`, `severity` | *"What behavioral rule triggered this detection and what was the initial telemetry payload?"* |
| **2** | `Alert Detail → Process` | `/edr/detections/:alertId` | Process Name Hyperlink in Execution Banner | `/edr/processes/:processGuid` | `process_guid`, `pid`, `host_id`, `timestamp` | *"What binary executed, what command-line parameters were passed, and what was its working directory?"* |
| **3** | `Process → Parent Process` | `/edr/processes/:processGuid` | "Inspect Parent" button in Ancestry Widget | `/edr/endpoints/:id/process-tree` | `parent_process_guid`, `ppid`, `host_id` | *"Who spawned this process? Was it a user shell, an Office macro, or an unmanaged background service?"* |
| **4** | `Parent Process → Device` | `/edr/endpoints/:id/process-tree` | Hostname Breadcrumb / "Device 360" button | `/edr/endpoints/:id/360` | `host_id`, `tenant_id` | *"What is the posture, criticality, operating system, and IP address of the machine hosting this execution?"* |
| **5** | `Device → User` | `/edr/endpoints/:id/360` | User Avatar / Identity Badge | `/edr/users-sessions` | `username`, `domain`, `host_id` | *"Who was logged into this machine at the time of execution, and was this session interactive or remote RDP?"* |
| **6** | `User → Network Connection` | `/edr/users-sessions` | "Filter Network by User/Session" action | `/edr/network` | `session_id`, `host_id`, `time_window` | *"Did this user session initiate any external outbound network connections immediately following the event?"* |
| **7** | `Network Connection → DNS` | `/edr/network` | "Lookup Associated DNS Query" button | `/edr/dns` | `destination_ip`, `host_id`, `timestamp` | *"What fully-qualified domain name (FQDN) resolved to this destination IP address prior to connection?"* |
| **8** | `DNS → IOC` | `/edr/dns` | "Check Threat Intel" badge on domain | `/edr/threat-intel` | `domain`, `query_type`, `resolved_ip` | *"Is this domain a known Command & Control (C2) endpoint, dynamic DNS, or newly registered domain (NRD)?"* |
| **9** | `IOC → Dropped File` | `/edr/threat-intel` | "Fleet File Matches" sub-tab | `/edr/files` | `associated_hashes`, `host_id` | *"Did this C2 communication result in a second-stage payload being dropped onto the local filesystem?"* |
| **10** | `Dropped File → Sandbox` | `/edr/files/:sha256` | **"Detonate in Dynamic Sandbox"** button | `/sandbox/submit` | `file_path`, `sha256`, `host_id`, `sample_name` | *"What does this binary do when allowed to execute dynamically in a hardened, anti-evasion sandbox?"* |
| **11** | `Sandbox → Dynamic Evidence` | `/sandbox/live/:jobId` | "Detonation Complete $\to$ View Report" | `/sandbox/reports/:jobId` | `job_id`, `sha256`, `execution_id` | *"What syscalls, child processes, registry changes, and memory allocations occurred during detonation?"* |
| **12** | `Dynamic Evidence → ATT&CK` | `/sandbox/reports/:jobId` | "View MITRE Techniques" badge strip | `/edr/attack-matrix` | `technique_ids` (`T1055`, `T1059.001`, `T1105`) | *"How do the observed sandbox behaviors map to standardized adversary tactics and techniques?"* |
| **13** | `ATT&CK → IKG` | `/edr/attack-matrix` | "Project onto Incremental Knowledge Graph" | `/xdr/investigations/:caseId#ikg` | `case_id`, `entity_nodes`, `technique_edges` | *"How does this behavioral technique link into the holistic attack graph connecting hosts and identities?"* |
| **14** | `IKG → Security State` | `/xdr/investigations/:caseId#ikg` | "Authoritative Security State" badge | `/xdr/investigations/:caseId#security-state` | `case_id`, `tenant_id` | *"What is the authoritative security state assessment (e.g. `CONFIRMED_ATTACK`, `SUSPICIOUS_UNMANAGED`)?"* |
| **15** | `Security State → Verdict` | `/xdr/investigations/:caseId#security-state` | "View Deterministic Verdict Proof" tab | `/xdr/investigations/:caseId#verdict` | `case_id`, `verdict_band`, `verdict_proof` | *"What is the mathematically verified verdict without fabricated proxy score weights?"* |
| **16** | `Verdict → Impact` | `/xdr/investigations/:caseId#verdict` | "Assess Enterprise Blast Radius" button | `/xdr/investigations/:caseId#impact` | `case_id`, `affected_assets`, `criticality` | *"Which business units, domain controllers, or sensitive data repositories are within the blast radius?"* |
| **17** | `Impact → Response` | `/xdr/investigations/:caseId#impact` | "Initiate Targeted Remediation" button | `/edr/response` | `host_id`, `process_guid`, `quarantine_hash` | *"What containment primitives must be executed immediately to halt adversary movement?"* |
| **18** | `Response → Isolation` | `/edr/response` | "Safety-Gated Host Isolation" modal | `/edr/response/isolation` | `host_id`, `operator_id`, `justification` | *"Can we safely isolate this host without severing critical Active Directory or ICU hospital controllers?"* |
| **19** | `Isolation → Execution` | `/edr/response/isolation` | "Confirm Network Isolation" button | `/edr/response` (Audit Ledger) | `job_id`, `status: SUCCESS`, `mtls_pinned: TRUE` | *"Has the sensor kernel driver applied packet drops while maintaining controller management connectivity?"* |
| **20** | `Execution → Verification` | `/edr/response` (Audit Ledger) | "Verify Containment Telemetry" button | `/edr/endpoints/:id/trajectory` | `host_id`, `containment_timestamp` | *"Does subsequent sensor telemetry prove zero outbound network traffic and process execution halt?"* |

---

## 3. Cross-Surface Special Pivots Specification

In addition to the sequential 20-step lifecycle, analysts frequently pivot across specialized analytical subsystems. The following 11 special pivots are fully defined in the interaction architecture:

### 1. EDR Endpoint $\longrightarrow$ Sandbox (`/edr/endpoints` $\to$ `/sandbox/submit`)
* **Trigger**: Action menu on endpoint row $\to$ "Detonate Host Artifact in Sandbox".
* **Context Passed**: Pre-populates endpoint hostname, recent file hashes observed on that host, and selects OS profile matching the host OS (e.g., Windows 11 Enterprise 23H2).
* **Cognitive Goal**: Detonate a payload within an environment configured identically to the compromised production host.

### 2. Sandbox Dropped File $\longrightarrow$ Static Analysis (59 Decoders) (`/sandbox/reports/:id` $\to$ `/api/decode/smart`)
* **Trigger**: "Send to 59-Decoder Pipeline" button on dropped script/payload row.
* **Context Passed**: Dropped file payload bytes, file type, file name, and SHA-256 hash.
* **Cognitive Goal**: Automatically unwrap multi-stage obfuscation, Base64 UTF-16LE payloads, reflection wrappers, and extract embedded C2 configs using the native 59-decoder suite.

### 3. Sandbox Dynamic Observation $\longrightarrow$ Canonical Evidence (`/sandbox/reports/:id` $\to$ `/edr/evidence`)
* **Trigger**: "Publish Detonation Evidence to Case" button.
* **Context Passed**: Execution ID, generated PCAP hash, memory dump hash, syscall trace JSON, child process list.
* **Cognitive Goal**: Commit dynamic hypervisor telemetry to the immutable case evidence ledger without creating shadow reasoning state.

### 4. Evidence $\longrightarrow$ Investigation (`/edr/evidence` $\to$ `/xdr/investigations/:caseId`)
* **Trigger**: "Attach Artifact to Active Investigation" context action.
* **Context Passed**: Evidence UUID, case ID, target entity linkage (host/user/process).
* **Cognitive Goal**: Bind raw telemetry artifacts directly to the active incident investigation dossier.

### 5. IOC $\longrightarrow$ Threat Intelligence (`/edr/dns` or `/edr/files` $\to$ `/edr/threat-intel`)
* **Trigger**: Threat badge click or "Enrich IOC" button.
* **Context Passed**: Observable value (Domain, IP, Hash), observable type.
* **Cognitive Goal**: Query internal and commercial threat feeds to determine actor attribution, campaign associations, and confidence score.

### 6. Process $\longrightarrow$ Device Trajectory (`/edr/process-tree` $\to$ `/edr/trajectory`)
* **Trigger**: "Jump to Event Timestamp in 5-Lane Trajectory" button in Process Context Menu.
* **Context Passed**: `host_id`, `timestamp`, `process_guid`.
* **Cognitive Goal**: Position the 5-lane timeline scrubber (internal target: microsecond-level replay) precisely at the moment the process spawned to observe concurrent network, file, and registry activity.

### 7. User $\longrightarrow$ UBAE / Entity 360 (`/edr/users-sessions` $\to$ `/edr/ubae-context`)
* **Trigger**: Username link with risk score badge.
* **Context Passed**: `username`, `domain`, `time_window`.
* **Cognitive Goal**: Evaluate whether the user account is exhibiting abnormal access patterns, lateral movement, or peer-group deviations.

### 8. Detection $\longrightarrow$ Detection Engineering (`/edr/detections/:id` $\to$ `/edr/detection-engineering`)
* **Trigger**: "Tune / Edit Detection Rule" button.
* **Context Passed**: `rule_id`, `rule_syntax`, `false_positive_telemetry_snippet`.
* **Cognitive Goal**: Modify the Sigma/YARA-L rule syntax, run historical backtesting, and suppress benign operational patterns without code changes.

### 9. ATT&CK Technique $\longrightarrow$ Supporting Evidence (`/edr/attack-matrix` $\to$ `/edr/evidence`)
* **Trigger**: Technique cell click (e.g. `T1055: Process Injection`) $\to$ "View Supporting Fleet Evidence".
* **Context Passed**: `technique_id: T1055`, `time_window`.
* **Cognitive Goal**: View every memory allocation, API call, and ETW event across all endpoints that substantiated this ATT&CK classification.

### 10. Security State $\longrightarrow$ Intervention (`/xdr/investigations/:caseId#security-state` $\to$ `/edr/response`)
* **Trigger**: "Authorize Recommended Containment" button on Authoritative Security State banner.
* **Context Passed**: Recommended action set (`ISOLATE_HOST`, `TERMINATE_PID_TREE`, `BLOCK_C2_IP`), target entity IDs, case ID.
* **Cognitive Goal**: Rapidly execute vetted interventions derived deterministically from the confirmed security state.

### 11. Response $\longrightarrow$ Verification (`/edr/response` $\to$ `/edr/endpoints/:id/trajectory`)
* **Trigger**: "Verify Containment Telemetry" button on completed response job.
* **Context Passed**: `host_id`, `containment_timestamp`, `filter: post_containment`.
* **Cognitive Goal**: Confirm that telemetry reflects zero unauthorized process executions or external sockets post-isolation.

---

## 4. UI/UX Interaction Design Standards for Pivots

To ensure seamless analyst flow, all cross-surface pivots adhere to the following interaction rules:

1. **Persistent Context Tray**: When deep-pivoting, a top banner indicates:  
   `[ Active Filter: Host WKS-EXEC-09 · Process powershell.exe (PID 4912) · Case #INC-2026-0841 ] [ Clear Context ]`
2. **Slide-Over Drawers vs. Full Navigation**:
   - Secondary inspection (Process Detail, File Detail, IOC Enrichment) opens in a **Slide-Over Drawer (600px)** without unmounting the primary working canvas.
   - Primary lifecycle transitions (Detection $\to$ Device Trajectory $\to$ Sandbox Detonation) perform **Full Canvas Routing** while updating browser URL history.
3. **Fail-Closed Presentation**: If a target pivot has no recorded evidence (e.g., DNS telemetry was disabled on an unmanaged host), the UI renders an honest:  
   `NO AUTHORITATIVE EVIDENCE RECORDED: Telemetry source 'ETW-DNS' was inactive on target host during the requested time window.`  
   No synthetic fallback or placeholder data is ever rendered.
