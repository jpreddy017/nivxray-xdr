# NIVXFORGE EDR: MASTER INFORMATION ARCHITECTURE (IA) SPECIFICATION
**Authoritative Structure, Taxonomy, Screen Hierarchy, and Interaction Design for NivXForge EDR & Native Dynamic Sandbox**  
**Document ID:** `NIVXFORGE-IA-SPEC-2026-09-05`  
**Classification:** Operational UI/UX Contract Baseline  
**Companion Artifacts:**
* Prototype: [`NIVXFORGE_EDR_SANDBOX_OPERATIONAL_PROTOTYPE.html`](file:///d:/Projects/docs/uiux/NIVXFORGE_EDR_SANDBOX_OPERATIONAL_PROTOTYPE.html)
* Parity Matrix: [`NIVXFORGE_EDR_EXHAUSTIVE_UIUX_PARITY_MATRIX.md`](file:///d:/Projects/docs/uiux/NIVXFORGE_EDR_EXHAUSTIVE_UIUX_PARITY_MATRIX.md)
* Attack Chain Matrix: [`NIVXFORGE_EDR_ATTACK_CHAIN_UX_MATRIX.md`](file:///d:/Projects/docs/uiux/NIVXFORGE_EDR_ATTACK_CHAIN_UX_MATRIX.md)
* UI/UX Spec: [`NIVXFORGE_EDR_SANDBOX_UIUX_SPEC.md`](file:///d:/Projects/docs/uiux/NIVXFORGE_EDR_SANDBOX_UIUX_SPEC.md)

---

## 1. Executive Summary & Design Principles

The NivXForge Endpoint Detection & Response (EDR) information architecture establishes a unified, single-pane operational plane designed to eliminate the cognitive friction of fragmented investigation workflows. The IA is architected to achieve complete operational and workflow parity with enterprise benchmark leaders (CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne Singularity, Palo Alto Cortex XDR, Cisco Secure Endpoint) while strictly preserving the proprietary causal reasoning advantages of **NivXRay XDR** across its canonical 8-stage causal pipeline:

$$\text{Telemetry} \longrightarrow \text{Canonical Evidence} \longrightarrow \text{IUE / ICE} \longrightarrow \text{IKG} \longrightarrow \text{Security State} \longrightarrow \text{Deterministic Verdict} \longrightarrow \text{Response} \longrightarrow \text{Verification}$$
*(with Impact assessment performed prior to Intervention).*

### 1.1 Structural Invariants
1. **Evidence-Producing Sandbox**: The Native Dynamic Sandbox is architected as an **evidence-producing subsystem**. It generates high-fidelity behavioral, syscall, network, and dropped file telemetry. It does **not** create a shadow reasoning, IKG, or verdict engine. All sandbox evidence flows directly into the canonical NivXRay evidence pipeline.
2. **Context-Preserving Deep Navigation**: Navigating between any of the 37 mandatory EDR surfaces preserves investigation tokens (`case_id`, `endpoint_id`, `process_guid`, `hash`, `timestamp_window`, `tenant_id`) in URL state and session cache.
3. **Fail-Closed Truthfulness**: Empty states, missing sensors, or uncollected artifacts display honest, non-synthetic `NO AUTHORITATIVE EVIDENCE RECORDED` indicators.
4. **Safety-Gated Remediation**: Critical actions (Host Isolation, Remote Process Termination, Quarantine, Memory Capture) require idempotent verification against critical infrastructure registries (Active Directory Domain Controllers, Healthcare Life-Safety Assets, SCADA/ICS nodes).
5. **Clear Prototype Demarcation**: All prototype interfaces display a persistent **"REPRESENTATIVE / PROTOTYPE DATA"** badge to prevent ambiguity.

---

## 2. Global Navigation Hierarchy & Functional Categorization

The 37 mandatory EDR surfaces and Sandbox surfaces are organized into seven (7) functional operational groups:

```text
NIVXRAY XDR / NIVXFORGE EDR
│
├── GROUP 1: STRATEGIC & FLEET GOVERNANCE
│   ├── [1]  EDR Overview (`/edr/overview`)
│   ├── [29] Agent / Sensor Management (`/edr/agents`)
│   ├── [30] Telemetry Health (`/edr/telemetry-health`)
│   └── [32] Policies & Configuration (`/edr/policies`)
│
├── GROUP 2: ENDPOINT ASSET & POSTURE INTELLIGENCE
│   ├── [2]  Endpoint Fleet / Inventory (`/edr/endpoints`)
│   ├── [3]  Endpoint Entity 360 (`/edr/endpoints/:id/360`)
│   ├── [17] Users & Sessions (`/edr/users-sessions`)
│   ├── [23] Vulnerabilities & Exposure (`/edr/vulnerabilities`)
│   └── [37] UBAE / UEBA Entity Context (`/edr/ubae-context`)
│
├── GROUP 3: DETECTION & ALERT TRIAGE
│   ├── [4]  Detections Queue (`/edr/detections`)
│   ├── [5]  Detection Detail (`/edr/detections/:alertId`)
│   ├── [6]  Incidents (`/edr/incidents`)
│   ├── [31] Detection Engineering (`/edr/detection-engineering`)
│   └── [33] MITRE ATT&CK Matrix Navigator (`/edr/attack-matrix`)
│
├── GROUP 4: FORENSIC INVESTIGATION & DEVICE ANALYTICS
│   ├── [7]  Device Timeline (`/edr/endpoints/:id/timeline`)
│   ├── [8]  Device Trajectory (`/edr/endpoints/:id/trajectory`)
│   ├── [9]  Process Tree (`/edr/endpoints/:id/process-tree`)
│   ├── [10] Process Detail (`/edr/processes/:processGuid`)
│   ├── [11] Files & PE Artifacts (`/edr/files`)
│   ├── [12] File Detail (`/edr/files/:sha256`)
│   ├── [13] Network Connections (`/edr/network`)
│   ├── [14] DNS Query Activity (`/edr/dns`)
│   ├── [15] Windows Registry (`/edr/registry`)
│   ├── [16] System Services & Daemons (`/edr/services`)
│   ├── [18] Persistence Mechanisms (`/edr/persistence`)
│   ├── [21] Forensics Artifacts & Triage (`/edr/forensics`)
│   ├── [22] Memory / Volatile Evidence (`/edr/memory`)
│   ├── [34] Attack Story Canvas (`/edr/attack-story/:caseId`)
│   ├── [35] Evidence Vault (`/edr/evidence`)
│   └── [36] Investigation Pivots (`/edr/investigation-pivots`)
│
├── GROUP 5: THREAT HUNTING & DISTRIBUTED LIVE QUERY
│   ├── [19] Threat Hunting Workspace (`/edr/hunting`)
│   ├── [20] Distributed Live Query (`/edr/live-query`)
│   └── [24] Threat Intelligence & IOC Vault (`/edr/threat-intel`)
│
├── GROUP 6: CONTAINMENT, RESPONSE & REMEDIATION
│   ├── [25] Response Command Center (`/edr/response`)
│   ├── [26] Host Isolation (`/edr/response/isolation`)
│   ├── [27] Quarantine Vault (`/edr/response/quarantine`)
│   └── [28] Remote Response Console (`/edr/response/terminal`)
│
└── GROUP 7: NATIVE DYNAMIC SANDBOX SUBSYSTEM
    ├── Detonation Intake & Profiling (`/sandbox/submit`)
    ├── Live Hypervisor Console & Syscall Feed (`/sandbox/live/:jobId`)
    ├── Dynamic Detonation Report (`/sandbox/reports/:jobId`)
    ├── Behavioral Process Graph (`/sandbox/reports/:jobId/graph`)
    ├── Dropped Artifacts & PCAP Store (`/sandbox/reports/:jobId/artifacts`)
    └── Closed-Loop Convergence Bridge (`/sandbox/bridge/:jobId`)
```

---

## 3. Exhaustive Surface Specifications (Surfaces 1 to 37)

### Surface 1: EDR Overview (`/edr/overview`)
* **Primary Purpose**: Executive and SOC Tier 3 operational posture dashboard summarizing endpoint health, detection velocity, active isolations, and telemetry throughput.
* **Sub-Tabs**:
  - `Executive Posture`: Risk index, mean time to detect (MTTD), mean time to contain (MTTC), active isolated hosts count.
  - `Detection Velocity`: 24-hour detection trend, top MITRE techniques observed, top targeted endpoints.
  - `Fleet Streaming Health`: Total streaming agents, aggregate EPS, telemetry pipeline latency ($p99$).
* **Secondary Panels**:
  - `Critical Active Threats`: Slide-over card of currently uncontained Tier-1 alerts.
  - `Safety Guardrail Status`: Quick view of registered Domain Controllers and Healthcare critical devices.
* **Analyst Controls & Filters**: Time selector (`1h`, `6h`, `24h`, `7d`), OS filter (`Windows`, `Linux`, `macOS`), Tenant switcher.
* **Pivots**: Click on "Active Isolated Hosts" $\to$ Surface 26; click on "Unresolved Detections" $\to$ Surface 4.

### Surface 2: Endpoint Fleet / Inventory (`/edr/endpoints`)
* **Primary Purpose**: Authoritative inventory of all registered endpoints, OS builds, agent versions, and live connection status.
* **Sub-Tabs**: `All Endpoints`, `Workstations`, `Servers`, `Domain Controllers & Infrastructure`, `Isolated Hosts`, `Offline / Stale`.
* **Columns**: Hostname, Machine GUID, IP Address, OS / Kernel, Sensor Version, Streaming EPS, Isolation Status, Last Heartbeat, Action Menu.
* **Filters & Search**: Hostname wildcard, Subnet CIDR, Sensor version match, Health status dropdown, Tag filter (`CORP`, `DMZ`, `PCI-DSS`).
* **Context Actions (per host)**:
  - Pivot to Endpoint Entity 360 (Surface 3)
  - Pivot to Device Trajectory (Surface 8)
  - Launch Live Query against host (Surface 20)
  - Initiate Safety-Gated Isolation (Surface 26)
  - Trigger Volatile Memory Dump (Surface 22)
* **States**:
  - Loading: Skeleton table rows with pulsing pulse shimmer.
  - Empty: "No matching endpoints registered for current tenant filter."
  - Error: "Failed to query fleet registry: Gateway timeout (504)."

### Surface 3: Endpoint Entity 360 (`/edr/endpoints/:id/360`)
* **Primary Purpose**: Comprehensive 360-degree forensic dossier of a single endpoint.
* **Sub-Tabs**:
  - `Overview`: Hardware UUID, BIOS serial, CPU, RAM, disk encryption status, primary logged-in user.
  - `Detections & Incidents`: Historical alert ledger bound to this machine.
  - `Software & Vulnerabilities`: Installed applications, missing CVE patches (Surface 23).
  - `Network Interfaces`: Routing tables, active MACs, DNS resolvers, active socket counts.
  - `Active Sessions`: Logged-on users, RDP sessions, SSH keys (Surface 17).
  - `Configuration & Baseline`: Applied security policy, audit logging level, driver signatures.
* **Pivots**: Deep link to Device Trajectory (Surface 8), Process Tree (Surface 9), UBAE Context (Surface 37).

### Surface 4: Detections Queue (`/edr/detections`)
* **Primary Purpose**: Real-time triage stream of all endpoint behavioral and signature-based detection events.
* **Sub-Tabs**: `Unassigned / New`, `In Triage`, `Confirmed Malicious`, `False Positive / Suppressed`, `Resolved`.
* **Columns**: Severity Badge (`CRITICAL`, `HIGH`, `MED`, `LOW`), Alert Title, Target Host, Process Name, Trigger Rule ID, ATT&CK ID, Timestamp, Status.
* **Filters**: Severity multi-select, Technique ID search, Sensor detection engine (`Kernel Behavioral`, `YARA`, `LOLBAS Engine`, `AMSI / ETW`), Hostname.
* **Actions**: Promote to Incident (Surface 6), Suppress / Tune Rule (Surface 31), Pivot to Detection Detail (Surface 5).

### Surface 5: Detection Detail (`/edr/detections/:alertId`)
* **Primary Purpose**: Deep-dive investigation workspace for a specific alert instance.
* **Sub-Tabs**:
  - `Alert Overview`: Rule logic, matched trigger telemetry, rule severity justification.
  - `Execution Context`: Parent-child process lineage snapshot, command-line flags, working directory.
  - `Entity Evidence`: Target user account, machine state at execution, loaded modules.
  - `MITRE Alignment`: Technique description, tactic stage, detection data sources.
* **Analyst Action Buttons**:
  - `Inspect Process Ancestry` $\to$ Surface 9
  - `View 5-Lane Trajectory at Event Time` $\to$ Surface 8
  - `Send Target Binary to Sandbox` $\to$ Sandbox Intake
  - `Isolate Host` $\to$ Surface 26

### Surface 6: Incidents (`/edr/incidents`)
* **Primary Purpose**: Multi-signal correlated incident management plane combining multiple detections, endpoints, and identities.
* **Sub-Tabs**: `Open Incidents`, `Investigating`, `Awaiting Response`, `Closed`.
* **Panels**: Incident Summary, Scope of Compromise (hosts count, accounts count), Blast Radius Graph, Timeline.
* **Pivots**: "Full Investigation" $\to$ NivXRay Core Investigation Workspace (`/xdr/investigations/:caseId`).

### Surface 7: Device Timeline (`/edr/endpoints/:id/timeline`)
* **Primary Purpose**: Unified chronological log of all operating system events on an endpoint.
* **Sub-Tabs**: `All Events`, `Security Events (4624/4625/4688)`, `Process Events`, `Network Events`, `File System`, `System Errors`.
* **Features**: Dynamic zoom ($1\text{m}$, $10\text{m}$, $1\text{h}$, $24\text{h}$), event density histogram, search regex bar.

### Surface 8: Device Trajectory (`/edr/endpoints/:id/trajectory`)
* **Primary Purpose**: Multi-lane behavioral replay of endpoint telemetry across 5 distinct execution lanes (internal target: microsecond-level replay).
* **Sub-Tabs / Execution Lanes**:
  - `Process Lane`: Process spawn, injection, token impersonation, termination (`#5cc0a5`).
  - `Network Lane`: Inbound/outbound TCP/UDP, TLS handshakes, DNS queries (`#38bdf8`).
  - `File Lane`: File create, write, rename, delete, alternate data streams (`#fbbf24`).
  - `Registry Lane`: Key create, value set, persistence modification (`#a855f7`).
  - `System Lane`: Driver load, service change, authentication ticket requests (`#9198a1`).
* **Controls**: Scrubber bar, playback speed ($1\times, 5\times, 20\times$), auto-center on alert timestamp.
* **Event Drawer**: Clicking any event displays full canonical JSON, ETW event ID, stack trace, and hashes.

### Surface 9: Process Tree / Ancestry (`/edr/endpoints/:id/process-tree`)
* **Primary Purpose**: Hierarchical visual canvas depicting process ancestry and lateral process spawning.
* **Visual Elements**: Tree nodes with process icon, PID, parent PID, user integrity badge (`SYSTEM`, `High`, `Medium`), LOLBAS tag, memory injection indicator.
* **Sub-Panels / Drawers**:
  - Node Context Menu: `Detonate in Sandbox`, `Inspect File Hash`, `Terminate Process`, `View Handles`, `Copy Command Line`.
  - Filter Bar: Hide benign system processes (`svchost`, `smss`), highlight suspicious binaries.

### Surface 10: Process Detail (`/edr/processes/:processGuid`)
* **Primary Purpose**: Complete forensic dissection of an individual process instance.
* **Sub-Tabs**:
  - `Metadata`: Image path, command line, current working directory, hash (MD5, SHA-1, SHA-256), authenticode signature.
  - `Threads & Modules`: Loaded DLLs with signature verification status, active thread IDs, start addresses.
  - `Handles & Sockets`: Open file handles, registry keys locked, listening/connected TCP sockets.
  - `Memory Map`: Virtual memory segment allocations (`PAGE_EXECUTE_READWRITE` flags).
  - `Parent/Child Lineage`: Exact ancestry with timestamps.

### Surface 11: Files & PE Artifacts (`/edr/files`)
* **Primary Purpose**: Searchable repository of all binary and script artifacts observed across the fleet.
* **Sub-Tabs**: `Executable Binaries (.exe, .dll)`, `Scripts (.ps1, .vbs, .bat, .sh)`, `Documents (.docm, .pdf)`, `Archive Drops (.zip, .iso)`.
* **Columns**: File Name, SHA-256, Size, Prevalence in Fleet (e.g. "1 of 48 hosts"), First Seen, Last Seen, Authenticode Signer, Reputation.

### Surface 12: File Detail (`/edr/files/:sha256`)
* **Primary Purpose**: Deep forensic dossier for an individual file hash.
* **Sub-Tabs**:
  - `Static Properties`: PE headers, entropy score, imphash, ssdeep, sections table.
  - `Fleet Prevalence`: List of all endpoints where this hash resides or has executed.
  - `Signature & Certificate`: Signer name, counter-signer, certificate validity, revoked status.
  - `Sandbox Reports`: Historical detonation reports for this hash.
* **Actions**: `Send to Sandbox for Dynamic Detonation`, `Add to Fleet Blocklist`, `Quarantine on All Hosts`.

### Surface 13: Network Connections (`/edr/network`)
* **Primary Purpose**: Fleet-wide socket telemetry recording all inbound and outbound network flows.
* **Sub-Tabs**: `Active Sockets`, `Historical Flows`, `Listening Ports`, `External C2 Connections`.
* **Columns**: Timestamp, Hostname, Source IP:Port, Dest IP:Port, Protocol, Process Name & PID, Direction, Bytes Sent/Received, Geo-IP / ASN.
* **Filters**: Public IPs only, RFC1918 internal only, Non-standard HTTP ports, Destination country.

### Surface 14: DNS Query Activity (`/edr/dns`)
* **Primary Purpose**: Record of all domain lookups originating from endpoint processes.
* **Sub-Tabs**: `All DNS Queries`, `NXDOMAIN Spikes`, `DGA Suspects`, `External Resolvers`.
* **Columns**: Query Timestamp, Hostname, Process PID/Name, Query Name, Record Type (A, AAAA, TXT), Response IP / CNAME, TTL.
* **Analyst Action**: Pivot to Threat Intelligence (Surface 24) to check domain reputation.

### Surface 15: Windows Registry Activity (`/edr/registry`)
* **Primary Purpose**: Telemetry stream tracking modifications to the Windows Registry.
* **Sub-Tabs**: `All Modifications`, `Run & RunOnce Keys`, `Service Definitions`, `LSA / Security Providers`, `User Init / Shell`.
* **Columns**: Timestamp, Hostname, Action (`SetValue`, `CreateKey`, `DeleteValue`), Key Path, Value Name, Value Data (Base64 decoded), Modifying Process.

### Surface 16: System Services & Daemons (`/edr/services`)
* **Primary Purpose**: Tracking creation, modification, and startup state of OS background services.
* **Sub-Tabs**: `All Services`, `Newly Installed Services (<24h)`, `Non-Standard Binaries`, `Disabled Services`.
* **Columns**: Service Name, Display Name, Binary Path, Startup Type (`Auto`, `Demand`, `Disabled`), Service Account, Host Count.

### Surface 17: Users & Sessions (`/edr/users-sessions`)
* **Primary Purpose**: Monitoring interactive, network, and remote desktop logon sessions.
* **Sub-Tabs**: `Active Sessions`, `Interactive Logons (Type 2)`, `Network Logons (Type 3)`, `RDP / Remote Sessions (Type 10)`, `Failed Logons (4625)`.
* **Columns**: Hostname, Username, Domain, Logon Type, Session ID, Client Name, Client IP, Logon Time, Duration.
* **Pivot**: 1-click pivot to UBAE Entity Context (Surface 37).

### Surface 18: Persistence Mechanisms (`/edr/persistence`)
* **Primary Purpose**: Dedicated matrix of autostart execution points (ASEPs) discovered across fleet endpoints.
* **Sub-Tabs**: `Scheduled Tasks`, `Registry Run Keys`, `WMI Event Subscriptions`, `Startup Folders`, `Browser Extensions`, `Linux Cron & Systemd`.
* **Filters**: Unsigned binaries only, newly created in last 48 hours, high entropy paths.

### Surface 19: Threat Hunting Workspace (`/edr/hunting`)
* **Primary Purpose**: Advanced query environment for hypothesis-driven threat hunting across historical telemetry.
* **Sub-Tabs**: `Query Builder`, `Saved Hunts`, `Hunt Results`, `Scheduled Hunts`.
* **Features**: KQL / SQL multi-syntax editor, schema auto-completion, time range selector, result visualization (charts, timelines).
* **Actions**: Save as Detection Rule $\to$ Surface 31.

### Surface 20: Distributed Live Query (`/edr/live-query`)
* **Primary Purpose**: Real-time distributed osquery-compatible SQL execution against active online sensors.
* **Sub-Tabs**: `Query Console`, `Query Templates`, `Active Fleet Executions`, `Execution History`.
* **Templates**: Encoded PowerShell, Listening ports by unsigned processes, Open SSH sessions, Stored browser credentials access.
* **Execution Progress**: Real-time progress bar ($n/m$ sensors completed), execution time, error count, CSV/JSON export.

### Surface 21: Forensics Artifacts & Triage (`/edr/forensics`)
* **Primary Purpose**: On-demand DFIR triage collector for remote endpoints.
* **Sub-Tabs**: `Triage Packages`, `Prefetch Files`, `Shimcache / Amcache`, `MFT / USN Journal`, `Event Log Dumps (.evtx)`.
* **Actions**: `Collect Full DFIR Triage Package`, `Download Decrypted Evidence Vault`.

### Surface 22: Memory / Volatile Evidence (`/edr/memory`)
* **Primary Purpose**: Live endpoint volatile memory inspection and memory artifact acquisition.
* **Sub-Tabs**: `Injected Threads`, `Hollowed PE Headers`, `Unbacked Executable Memory`, `Memory Dumps`.
* **Actions**: `Acquire Full Physical Memory Dump`, `Scan Process Memory with YARA`.

### Surface 23: Vulnerabilities & Exposure (`/edr/vulnerabilities`)
* **Primary Purpose**: Continuous endpoint vulnerability management and exposure scoring.
* **Sub-Tabs**: `Discovered CVEs`, `Affected Hosts`, `Exploit-in-the-Wild (KEV)`, `Missing OS Patches`.
* **Columns**: CVE ID, Severity (CVSS v3), Affected Software, Host Count, CISA KEV Status, Remediation Guidance.

### Surface 24: Threat Intelligence & IOC Vault (`/edr/threat-intel`)
* **Primary Purpose**: Curated repository of threat actor indicators, feeds, and campaign intelligence.
* **Sub-Tabs**: `IOC Database (Hashes, IPs, Domains)`, `Threat Actor Profiles`, `Feed Integrations`, `Fleet Match History`.
* **Actions**: `Push IOC to Fleet Blocklist` (Surface 25).

### Surface 25: Response Command Center (`/edr/response`)
* **Primary Purpose**: Central orchestration center for executing and auditing containment and remediation commands.
* **Sub-Tabs**: `Active Containment Actions`, `Pending Approvals`, `Action History & Audit Log`, `Automated Playbooks`.
* **Audit Ledger**: Cryptographically hashed audit records with operator identity, target machine GUID, action type, justification note.

### Surface 26: Host Isolation (`/edr/response/isolation`)
* **Primary Purpose**: Network-level containment of compromised endpoints with strict safety verification.
* **Safety Gate Modal Requirements**:
  1. Mandatory verification that target is NOT a registered Active Directory Domain Controller.
  2. Mandatory verification that target is NOT an ICU, Healthcare Life-Safety, or SCADA controller.
  3. Pinned mTLS management channel check (ensures host remains reachable by NivXForge controller).
  4. Operator reason input and two-factor confirmation.
* **Action Types**: `Full Network Isolation`, `Isolated with DNS Exception`, `Un-Isolate Host`.

### Surface 27: Quarantine Vault (`/edr/response/quarantine`)
* **Primary Purpose**: Management of encrypted malicious files quarantined by EDR sensor agents.
* **Sub-Tabs**: `Quarantined Files`, `Restoration Requests`, `Permanent Purge`.
* **Attributes**: File Name, Original Path, Hostname, SHA-256, Quarantine Date, Sensor Encryption Status.
* **Actions**: `Download for Offline Reverse Engineering`, `Restore to Original Path`, `Permanently Delete`.

### Surface 28: Remote Response Console (`/edr/response/terminal`)
* **Primary Purpose**: Interactive live shell (PowerShell / Bash) direct to endpoint sensor for emergency incident response.
* **Features**: Audited session recording, restricted command safelist, file upload/download primitive, live process kill capability.
* **Security Controls**: Session timeout (15m idle), mandatory dual-custody authorization for high-privilege scripts.

### Surface 29: Agent / Sensor Management (`/edr/agents`)
* **Primary Purpose**: Sensor lifecycle management, deployment packages, and version compliance.
* **Sub-Tabs**: `Deployed Sensors`, `Installer Packages (MSI, Deb, RPM, PKG)`, `Sensor Update Rings (Canary, General, Delayed)`, `Uninstalled / Orphaned`.
* **Actions**: `Generate Sensor Installation Token`, `Trigger Over-The-Air Sensor Upgrade`.

### Surface 30: Telemetry Health (`/edr/telemetry-health`)
* **Primary Purpose**: Telemetry pipeline diagnostics, event loss detection, and ingestion throughput monitoring.
* **Sub-Tabs**: `Pipeline EPS Metrics`, `Event Queue Latency`, `Dropped Events / Backpressure`, `Sensor CPU / RAM Consumption`.
* **Alerts**: Alerts when an endpoint sensor exceeds 2% CPU or 150 MB RAM threshold.

### Surface 31: Detection Engineering (`/edr/detection-engineering`)
* **Primary Purpose**: Authoring, testing, and lifecycle management of behavioral detection rules and decoders.
* **Sub-Tabs**: `Active Detection Rules`, `Rule Editor (Sigma / YARA-L)`, `Backtest Engine (Test on historical telemetry)`, `False Positive Tuning`.
* **Pivots**: Direct bridge to 615 Content Fabric and 59 Decoders.

### Surface 32: Policies & Configuration (`/edr/policies`)
* **Primary Purpose**: Endpoint prevention, behavioral monitoring, and sensor configuration policies.
* **Sub-Tabs**: `Prevention Policies (Block / Detect)`, `Telemetry Collection Profiles`, `Exclusions & Allow-lists`, `Tamper Protection`.
* **Policy Assignment**: Granular assignment by Host Group, AD Organizational Unit (OU), or Tag.

### Surface 33: MITRE ATT&CK Matrix Navigator (`/edr/attack-matrix`)
* **Primary Purpose**: Enterprise ATT&CK matrix visualization mapped to observed fleet detections and coverage.
* **Sub-Tabs**: `Observed Fleet Tactics`, `Detection Coverage Heatmap`, `Technique Breakdown`.
* **Interactive Cells**: Clicking any technique cell filters detections and displays supporting evidence.

### Surface 34: Attack Story Canvas (`/edr/attack-story/:caseId`)
* **Primary Purpose**: Visual causal graph illustrating multi-stage attack propagation across processes, files, and network nodes.
* **Features**: Directed acyclic graph (DAG) layout, time slider, blast radius highlighting, root-cause identification.

### Surface 35: Evidence Vault (`/edr/evidence`)
* **Primary Purpose**: Forensic custody store containing all canonical evidence artifacts linked to active cases.
* **Sub-Tabs**: `All Evidence`, `Process Evidence`, `Network Artifacts`, `Memory Captures`, `Sandbox Traces`.
* **Metadata**: Immutable SHA-256 hash, acquisition timestamp, acquiring sensor ID, chain of custody ledger.

### Surface 36: Investigation Pivots (`/edr/investigation-pivots`)
* **Primary Purpose**: Matrix of pre-computed multidimensional pivots connecting entities, indicators, and cases.
* **Pivot Dimensions**: Host $\leftrightarrow$ User, Hash $\leftrightarrow$ Host, Domain $\leftrightarrow$ IP, Process $\leftrightarrow$ Network.

### Surface 37: UBAE / UEBA Entity Context (`/edr/ubae-context`)
* **Primary Purpose**: User and Entity Behavior Analytics contextual plane tracking identity anomalies and peer group deviations.
* **Sub-Tabs**: `Risk Scores`, `Anomalous Logons`, `Privilege Escalations`, `Data Exfiltration Indicators`, `Peer Group Baselines`.
* **Pivots**: Connects host processes to user identity risk profiles.

---

## 4. Native Dynamic Sandbox Subsystem Architecture

The Native Dynamic Sandbox is architected as an **evidence-producing subsystem** that executes suspicious artifacts inside isolated hypervisor guests and emits structured evidence directly to the NivXRay canonical evidence pipeline:

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│                    NIVXFORGE NATIVE DYNAMIC SANDBOX                          │
├──────────────────────────┬───────────────────────────────────────────────────┤
│ Detonation Intake        │ MicroVM (Firecracker) / Full QEMU/KVM Hardware    │
├──────────────────────────┼───────────────────────────────────────────────────┤
│ Live Hypervisor Console  │ Interactive Screen + Live Kernel Syscall Stream  │
├──────────────────────────┼───────────────────────────────────────────────────┤
│ Forensic Dissection      │ 6 Forensic Tabs: Processes, Net, Files, Reg, Mem, │
│ Report                   │ Extracted Configs & Decrypted C2                  │
├──────────────────────────┼───────────────────────────────────────────────────┤
│ Closed-Loop Convergence  │ Deploy Sigma Rules, Fleet Blocklist, Case Link,   │
│ Bridge                   │ Forward Payloads to 59-Decoder Pipeline          │
└──────────────────────────┴───────────────────────────────────────────────────┘
```

---

## 5. Summary of Standardized Component States Across All Surfaces

To satisfy enterprise operational standards, every surface in the architecture implements six (6) standardized states:

1. **Active Data State**: Fully populated tabular or visual canvas with sorting, column customization, and micro-actions.
2. **Loading State**: High-fidelity skeleton screens preserving exact layout dimensions (no jarring content jumps).
3. **Empty State**: Explicit, non-synthetic empty explanation with context-specific action (e.g. "No alerts match filter. Clear filters or adjust time range.").
4. **Error State**: Actionable error message with HTTP status, retry button, and copyable trace ID.
5. **Permission State**: Clear indication of RBAC restrictions (e.g. "Host Isolation requires Tier-3 SOC Analyst or Incident Commander role.").
6. **Dangerous-Action Confirmation State**: Two-stage safety verification modal with domain controller exclusion checks and cryptographic audit trail.
