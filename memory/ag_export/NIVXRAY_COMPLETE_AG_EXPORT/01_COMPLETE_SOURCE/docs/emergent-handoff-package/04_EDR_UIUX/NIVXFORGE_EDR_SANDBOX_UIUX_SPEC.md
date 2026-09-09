# NIVXFORGE EDR & NATIVE DYNAMIC SANDBOX: MASTER UI/UX SPECIFICATION
**Exhaustive 37-Surface Operational Experience Architecture, Interaction Design System, and Visual Contract**  
**Document ID:** `NIVXFORGE-UIUX-SPEC-2026-09-05`  
**Status:** Approved Governing Design Baseline  
**Companion Artifacts:**
* Prototype: [`NIVXFORGE_EDR_SANDBOX_OPERATIONAL_PROTOTYPE.html`](file:///d:/Projects/docs/uiux/NIVXFORGE_EDR_SANDBOX_OPERATIONAL_PROTOTYPE.html)
* Information Architecture: [`NIVXFORGE_EDR_INFORMATION_ARCHITECTURE.md`](file:///d:/Projects/docs/uiux/NIVXFORGE_EDR_INFORMATION_ARCHITECTURE.md)
* Attack Chain Matrix: [`NIVXFORGE_EDR_ATTACK_CHAIN_UX_MATRIX.md`](file:///d:/Projects/docs/uiux/NIVXFORGE_EDR_ATTACK_CHAIN_UX_MATRIX.md)
* Parity Matrix: [`NIVXFORGE_EDR_EXHAUSTIVE_UIUX_PARITY_MATRIX.md`](file:///d:/Projects/docs/uiux/NIVXFORGE_EDR_EXHAUSTIVE_UIUX_PARITY_MATRIX.md)

---

## 1. Vision & Architectural Contract

### 1.1 The Operational Mandate
Modern SOC analysts and incident responders require an exhaustive, single-pane operational plane that integrates live endpoint detection, device trajectory replay, distributed live querying, deep memory forensics, and native dynamic hypervisor detonation without cognitive friction.

**NivXForge EDR and the Native Dynamic Sandbox** form a cohesive, unified endpoint security experience within **NivXRay XDR**. The user experience strictly honors the canonical 8-stage causal pipeline:

$$\text{Telemetry} \longrightarrow \text{Canonical Evidence} \longrightarrow \text{IUE / ICE} \longrightarrow \text{IKG} \longrightarrow \text{Security State} \longrightarrow \text{Deterministic Verdict} \longrightarrow \text{Response} \longrightarrow \text{Verification}$$
*(Note: Enterprise Impact Assessment functions as an integral analytical facet preceding intervention).*

### 1.2 Non-Negotiable UX Invariants
1. **Persistent Representative Data Indicator**: All prototype views and mock data sources display a persistent, visible banner:  
   `⚠️ REPRESENTATIVE / PROTOTYPE DATA — Operational UI/UX Contract for Future EDR & Sandbox Implementation`.
2. **Sandbox as an Evidence Producer**: The Sandbox executes suspicious artifacts in isolated microVM/QEMU guests and produces canonical evidence (syscalls, network flows, dropped payloads). It does **not** host a shadow reasoning engine, IKG, or verdict engine.
3. **Safety-Gated Interventions**: High-impact actions (Host Isolation, Remote Process Kill, Volatile Memory Dumps) require automated safety checks (Active Directory Domain Controller verification, ICU/Healthcare life-safety exclusion) and idempotent confirmation.
4. **Fail-Closed Truthfulness**: When authoritative telemetry is unavailable or uncollected, the interface renders explicit `NO AUTHORITATIVE EVIDENCE RECORDED` empty states rather than synthetic fallback data.
5. **Context-Preserving Bidirectional Pivots**: Every entity badge (Hostname, PID, File Hash, IP, Domain, User) provides 1-click context-preserving pivots across all 37 surfaces.

---

## 2. Design Tokens & Visual Language

### 2.1 Low-Eyestrain Dark Cybersecurity Palette
```css
:root {
  /* Canvas & Backgrounds */
  --bg-app:          #07090e; /* Deep space navy (root canvas) */
  --bg-surface:      #0d1117; /* Secondary panels, headers, navigation rail */
  --bg-card:         #131822; /* Interactive cards, table rows, tree nodes */
  --bg-card-hover:   #1a2233; /* Hover highlights */
  --bg-input:        #090d14; /* Input fields, code editors, terminals */
  
  /* Borders & Dividers */
  --border-subtle:   #161c28; /* Subtle row dividers */
  --border-card:     #1e2638; /* Card outlines, tab strips */
  --border-strong:   #2a364f; /* Focus rings, active states */
  
  /* Text & Typography */
  --text-primary:    #e6edf3; /* High-contrast headers, active labels */
  --text-secondary:  #9198a1; /* Metadata labels, timestamps, lane names */
  --text-muted:      #656d76; /* Disabled states, placeholders */
  
  /* Telemetry & Severity Accents */
  --accent-teal:     #5cc0a5; /* NivXRay signature teal (processes, causality) */
  --accent-cyan:     #38bdf8; /* Network sockets, live query, links */
  --accent-purple:   #a855f7; /* Windows Registry, hooks, persistence */
  --accent-amber:    #fbbf24; /* File I/O, medium severity, warnings */
  --accent-rose:     #f87171; /* Critical alerts, memory injection, malicious verdicts */
  --accent-emerald:  #4ade80; /* Online status, benign, verified integrity */
  
  /* Status Gradients */
  --grad-critical:   linear-gradient(135deg, rgba(239, 68, 68, 0.2), rgba(239, 68, 68, 0.05));
  --grad-teal:       linear-gradient(135deg, rgba(92, 192, 165, 0.2), rgba(92, 192, 165, 0.05));
  --grad-cyan:       linear-gradient(135deg, rgba(56, 189, 248, 0.2), rgba(56, 189, 248, 0.05));
}
```

### 2.2 Typography Hierarchy
* **Primary Interface**: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif.
* **Monospace Code / Terminal / Hashes / PIDs**: "JetBrains Mono", "Fira Code", Consolas, monospace.
* **Scale**:
  - Main Page Title: `20px` / `700` weight
  - Section Header: `14px` / `700` weight / `uppercase` / `letter-spacing: 0.05em`
  - Body Text: `12.5px` / `400` weight
  - Small / Monospace Metadata: `11px` / `600` weight
  - Micro Badges: `10px` / `700` weight / `font-mono`

---

## 3. The 37 Mandatory EDR Operational Surfaces

The complete operational surface model is categorized into six functional EDR groups plus the Native Dynamic Sandbox subsystem:

```text
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                 NivXRay XDR Unified Shell Header                                 │
├──────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Persistent Prototype Indicator:                                                                  │
│ ⚠️ REPRESENTATIVE / PROTOTYPE DATA — Operational UI/UX Contract for Future EDR & Sandbox        │
├──────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Main Navigation Rail (7 Groups):                                                                 │
│ [1. Overview & Health] [2. Asset & Entity 360] [3. Detection & Triage] [4. Device Analytics]     │
│ [5. Hunting & Live Query] [6. Containment & Response] [7. Native Dynamic Sandbox]               │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### Group 1: Strategic & Fleet Governance
1. **EDR Overview (`/edr/overview`)**: Fleet risk score, MTTD/MTTC metrics, 24h detection velocity, streaming EPS graph, active isolated hosts widget.
2. **Agent / Sensor Management (`/edr/agents`)**: Agent deployment drawer (PowerShell/Bash scripts), sensor version compliance tracker ($\ge \text{v2.4.0}$), update rings (Canary, Production).
3. **Telemetry Health (`/edr/telemetry-health`)**: Ingestion pipeline telemetry, sensor CPU/memory usage, event queue backpressure, dropped event counts.
4. **Policies & Configuration (`/edr/policies`)**: Behavioral prevention policies, sensor telemetry collection levels, exclusion rules, tamper protection toggles.

### Group 2: Asset & Posture Intelligence
5. **Endpoint Fleet / Inventory (`/edr/endpoints`)**: Authoritative machine inventory, OS distribution, IP/MAC, streaming status, quick response actions.
6. **Endpoint Entity 360 (`/edr/endpoints/:id/360`)**: Comprehensive dossier covering hardware, open sockets, missing patches, applied policies, and user logon history.
7. **Users & Sessions (`/edr/users-sessions`)**: Interactive (Type 2), Network (Type 3), and RDP (Type 10) sessions, active session duration, failed logons.
8. **Vulnerabilities & Exposure (`/edr/vulnerabilities`)**: Discovered CVEs, CISA Known Exploited Vulnerabilities (KEV) flags, CVSS v3 scores, patch status.
9. **UBAE Entity Context (`/edr/ubae-context`)**: User risk scoring, abnormal working hours, peer group deviation baselines, anomalous authentication alerts.

### Group 3: Detection & Alert Triage
10. **Detections Queue (`/edr/detections`)**: Real-time behavioral alert triage stream, severity filters (`CRITICAL`, `HIGH`, `MED`, `LOW`), suppression actions.
11. **Detection Detail (`/edr/detections/:alertId`)**: Slide-over drawer with rule rationale, trigger telemetry, inline process hierarchy snippet, and MITRE mapping.
12. **Incidents (`/edr/incidents`)**: Multi-signal correlated incident cards, blast radius scope, deep-link to NivXRay Core Investigation Workspace.
13. **Detection Engineering (`/edr/detection-engineering`)**: Sigma and YARA-L rule editor, syntax validation, backtesting against historical telemetry.
14. **MITRE ATT&CK Matrix (`/edr/attack-matrix`)**: Interactive enterprise matrix heatmap showing detected techniques and supporting evidence drilldowns.

### Group 4: Forensic Investigation & Device Analytics
15. **Device Timeline (`/edr/endpoints/:id/timeline`)**: Chronological log of OS events with time-range zooming (internal target: sub-second density histogram).
16. **Device Trajectory (`/edr/endpoints/:id/trajectory`)**: 5-lane behavioral replay across Process (`#5cc0a5`), Network (`#38bdf8`), File (`#fbbf24`), Registry (`#a855f7`), and System (`#9198a1`) lanes (internal target: microsecond-level replay).
17. **Process Tree / Ancestry (`/edr/endpoints/:id/process-tree`)**: SVG hierarchical canvas showing parent-child lineage, LOLBAS tags, and memory injection alerts.
18. **Process Detail (`/edr/processes/:processGuid`)**: Dissection of image path, command line, loaded DLLs, open handles, and virtual memory segments.
19. **Files & PE Artifacts (`/edr/files`)**: Fleet-wide binary inventory with SHA-256 hashes, prevalence tracking, and signature verification.
20. **File Detail (`/edr/files/:sha256`)**: Static PE properties, entropy, sections table, authenticode certificate details, and sandbox reports.
21. **Network Connections (`/edr/network`)**: Inbound and outbound TCP/UDP sockets, destination IPs, ASN/Geo-IP, and bound process names.
22. **DNS Query Activity (`/edr/dns`)**: Fleet DNS resolutions, NXDOMAIN spike detection, and DGA anomaly scoring.
23. **Windows Registry (`/edr/registry`)**: Monitored registry modifications, Run/RunOnce keys, and Base64 value decodes.
24. **System Services (`/edr/services`)**: Background services, newly created services ($<24\text{h}$), and binary paths.
25. **Persistence Mechanisms (`/edr/persistence`)**: Autostart execution points (Scheduled Tasks, WMI subscriptions, startup folders).
26. **Forensic Artifacts (`/edr/forensics`)**: On-demand DFIR triage packages (Prefetch, Shimcache, Amcache, MFT, EVTX).
27. **Memory / Volatiles (`/edr/memory`)**: Injected threads, hollowed PE headers, unbacked executable segments, physical memory dump controls.
28. **Attack Story Canvas (`/edr/attack-story/:caseId`)**: Causal directed acyclic graph (DAG) showing attack propagation across endpoints.
29. **Evidence Vault (`/edr/evidence`)**: Immutable SHA-256 custody ledger for all case-linked evidence artifacts.
30. **Investigation Pivots (`/edr/investigation-pivots`)**: Multidimensional pivot matrix (Host $\leftrightarrow$ User $\leftrightarrow$ Hash $\leftrightarrow$ Domain $\leftrightarrow$ IP).

### Group 5: Threat Hunting & Live Query
31. **Threat Hunting (`/edr/hunting`)**: Advanced hypothesis-driven query editor (KQL/SQL), saved hunts, and telemetry visualizations.
32. **Distributed Live Query (`/edr/live-query`)**: osquery-compatible distributed query console with syntax templates, fleet progress bar, and tabular results.
33. **Threat Intelligence (`/edr/threat-intel`)**: Threat actor dossiers, feed integrations, and automated fleet IOC matching.

### Group 6: Containment & Response
34. **Response Command Center (`/edr/response`)**: Unified remediation dashboard, pending approvals, and cryptographically sealed audit ledger.
35. **Host Isolation (`/edr/response/isolation`)**: Network containment with mandatory Active Directory Domain Controller and ICU healthcare safety gate checks.
36. **Quarantine Vault (`/edr/response/quarantine`)**: Encrypted malicious file repository (`.nvxvault`) with restoration and permanent purge controls.
37. **Remote Response Console (`/edr/response/terminal`)**: Interactive live shell (PowerShell/Bash) direct to endpoint sensor for emergency incident response.

---

## 4. Native Dynamic Sandbox Subsystem

The Native Dynamic Sandbox is architected as an **evidence-producing subsystem**:

1. **Detonation Intake & Profiling (`/sandbox/submit`)**:
   - File/URL upload zone with sample presets (Cobalt Strike loader, DarkGate VBS, AgentTesla stealer).
   - Target environment: Windows 11 Enterprise 23H2 (x64), Windows 10 Pro 22H2, Ubuntu 22.04 LTS (eBPF).
   - Hypervisor profiles: MicroVM (Firecracker, internal target: $<300\text{ms}$ spinup) vs Full QEMU/KVM with anti-evasion hardening.
   - Network simulation: Isolated Airgap, INETSim Emulated Services, Restricted Outbound Bridge.
2. **Live Hypervisor Console & Syscall Feed (`/sandbox/live/:jobId`)**:
   - Interactive HTML5 Canvas screen preview of guest desktop (internal target: up to 30 FPS; not a production SLA guarantee).
   - Live Windows kernel instrumentation feed streaming low-level syscalls (`NtAllocateVirtualMemory`, `CreateRemoteThread`, `InternetConnectA`).
   - Analyst controls: Extend time ($+60\text{s}$), acquire volatile memory dump, emergency terminate.
3. **Dynamic Detonation Analysis Report (`/sandbox/reports/:jobId`)**:
   - Circular threat score gauge ($96 / 100 \cdot \text{CRITICAL THREAT}$), anti-debug/anti-VM evasion indicators, sample hashes.
   - **6 Forensic Dissection Tabs**:
     1. Behavioral Process Hierarchy (spawned guest tree, memory unhooking).
     2. Network Activity & Sockets (DNS queries, HTTP/HTTPS sessions, C2 endpoints, PCAP download).
     3. File System Modifications (dropped payloads with 1-click **"Send to 59-Decoder Pipeline"**).
     4. Windows Registry & Persistence (Run keys, service creation).
     5. Memory Forensics & Code Injection (`PAGE_EXECUTE_READWRITE`, process hollowing, YARA hits).
     6. Extracted Config & Threat Intel (parsed C2 endpoints, RSA public keys, SMTP credentials).
4. **Closed-Loop Convergence Bridge (`/sandbox/bridge/:jobId`)**:
   - 1-click push to EDR fleet blocklists.
   - 1-click deployment of Sigma/YARA-L detection rules.
   - Direct link of detonation evidence to active XDR investigation cases.
   - Direct handoff of dropped scripts to the native 59-Decoder suite.

---

## 5. Standardized UI Interaction States

Every screen across the 37 surfaces enforces six (6) standardized UX states:

1. **Active Data State**: Populated grid, tree, or timeline with column sorting, filters, search, and action menus.
2. **Loading State**: CSS pulse skeleton screens mirroring target layout dimensions (prevents layout shift).
3. **Empty State**: Context-specific explanation with clear user action (e.g. "No alerts match the active severity filter. Reset filters to view all detections.").
4. **Error State**: Error banner detailing error code, failing API route, copyable trace ID, and retry button.
5. **Permission State**: Clear visual badge and explanation when an analyst lacks RBAC privileges (e.g., Tier-1 analyst attempting Host Isolation).
6. **Dangerous-Action Confirmation State**: Two-step modal requiring explicit rationale input, safety gate validation, and confirmation before execution.
