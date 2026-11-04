# NIVXFORGE EDR & NATIVE DYNAMIC SANDBOX: EMERGENT INTEGRATION MASTER HANDOFF
**Governing Architecture, Truth Contracts, Implementation Boundaries, and Engineering Backlog**  
**Document ID:** `NIVXFORGE-EMERGENT-README-2026-09-05`  
**Classification:** Primary Handoff Readme for Emergent Engineering  
**Handoff Status:** 🟢 APPROVED & READY FOR EMERGENT INTEGRATION REVIEW  

---

## A. Purpose of the Package

This package delivers the complete, authoritative engineering contract for **NivXForge EDR** and the **Native Dynamic Sandbox** within **NivXRay XDR**. It provides Emergent with the exact architectural, integration, dataflow, and UI/UX boundaries required to transition the platform from design specification into production implementation without duplicating existing core platform capabilities.

---

## B. What Emergent is Receiving

This handoff package contains seven (7) structured directories comprising 22 authoritative files:

```text
emergent-handoff-package/
├── 00_README/                  <- Master Readme, Manifest & Checksums
├── 01_TRUTH_CONTRACT/          <- Baseline Truth Contracts (615 Content & 59 Decoders)
├── 02_EDR_TRUTH/               <- Read-Only EDR Codebase Truth Audit
├── 03_EDR_ARCHITECTURE/        <- 12-Platform Industry Benchmark & Target Architecture
├── 04_EDR_UIUX/                <- 37-Surface IA, Parity Matrix & Operational Prototype
├── 05_INTEGRATION_CONTRACTS/   <- Code Map, Schemas, Tenancy & Response State Machine
├── 06_IMPLEMENTATION/          <- Actionable Backlog (P0–P4) & Acceptance Test Plan
└── 07_REFERENCE/               <- Scope Boundaries & Document Authority Precedence
```

---

## C. Current NivXRay XDR Truth

NivXRay XDR is an established, production-grade security reasoning platform:
* **The 615-Object Content Fabric**: 100% verified, active-certified rules across Sigma, YARA-L, and native detection logic (`backend/run_content_truth_audit.py` passes 100%, 0 duplicates, 0 quarantined).
* **The 59-Decoder Deobfuscation Suite**: 59 registered codecs providing multi-stage recursive unpacking, Cobalt Strike config extraction, and normalized recovery (`backend/verify_decoder_truth_e2e.py` passes 100%).
* **Phase 0 Truthfulness Closed**:
  - Security State is strictly decoupled from Verdict score bands and fails closed.
  - Verdict calculation operates deterministically without manufactured proxy weights.
  - Evidence Explorer and Investigation Workspace are bound strictly to real authoritative evidence APIs without synthetic demo fallbacks.

---

## D. Current NivXForge EDR Truth

The forensic audit of the existing codebase establishes:
* **Implemented**: Basic endpoint registration API (`/api/v2/endpoints`), XDR alerts queue, incidents correlation, evidence explorer, and investigation workspace tabs.
* **Scaffold / Partial**: Device timeline, basic host metadata, perimeter network flows, SIEM query builders.
* **Missing (To Be Built by Emergent)**: Cross-platform sensor agent daemon (Windows kernel minifilter / Linux eBPF), microsecond 5-lane trajectory streaming, distributed live query daemon (osquery), kernel network isolation driver with Domain Controller/ICU safety checks, and memory dump acquisition.

---

## E. Native Sandbox Target

The Native Dynamic Sandbox is architected strictly as an **evidence-producing execution subsystem**:
$$\text{Suspicious Artifact} \longrightarrow \text{MicroVM / QEMU Execution} \longrightarrow \text{Dynamic Telemetry} \longrightarrow \text{Canonical Evidence Vault} \longrightarrow \text{NivXRay Core}$$

The sandbox detonates samples in isolated microVMs/QEMU guests and emits low-level execution telemetry (syscalls, network flows, dropped payloads, memory anomalies) directly into the Canonical Evidence Vault. It does **NOT** build or maintain its own reasoning, correlation, IKG, or verdict calculation engine.

---

## F. What Already Exists and MUST BE REUSED

Emergent **MUST REUSE** the following existing components without replacement or duplication:

* **Canonical Evidence Store & Provenance Ledger**: (`backend/routers/artifacts.py`)
* **Identity Understanding Engine (IUE)**: Lanes A, B, and C (`backend/routers/iue_lane_*.py`)
* **Investigation Correlation Engine (ICE)**: (`backend/routers/correlations.py`, `xdr_correlation.py`)
* **Detection Engine & 615 Content Fabric**: (`backend/detection_content/`)
* **Incremental Knowledge Graph (IKG)**: (`backend/routers/attack_graph.py`, `attack_story.py`)
* **Authoritative Security State Engine**: (`backend/security_state/contracts.py`)
* **Deterministic Verdict Engine**: (`backend/routers/verdict_stage2.py`, `backend/reasoning/`)
* **59-Decoder Deobfuscation Suite**: (`backend/decoders/`, `backend/routers/analyze.py`)
* **Evidence Explorer & Investigation Workspace**: (`apps/nivxray-xdr/src/xdr/pages/`)
* **Response Ingestion Framework**: (`apps/nivxray-xdr-response/main.py`, `backend/routers/xdr_cortex_actions.py`)

---

## G. What Emergent is Expected to Integrate/Build

Emergent's implementation scope covers:

### 1. EDR Subsystem:
* Endpoint sensor daemon (Windows C++/Rust driver, Linux eBPF daemon).
* Endpoint enrollment and mutual TLS (mTLS 1.3) PKI infrastructure.
* Telemetry Ingestion Gateway (:8443) and schema normalization to Canonical Evidence.
* 5-lane device trajectory historical replay engine.
* Interactive process ancestry tree with living-off-the-land (LOLBAS) anomaly tagging.
* Distributed live query daemon (osquery).
* On-demand DFIR forensic triage package acquisition.
* Kernel response drivers (Network Isolation with safety gates, Process Kill, File Quarantine).

### 2. UBAE Subsystem:
* Entity 360 dossiers for users, hosts, and service accounts.
* Behavioral baselines and anomalous logon detection.
* Peer group deviation scoring and lateral movement detection.
* Direct projection of identity anomaly edges into the IKG.

### 3. Native Dynamic Sandbox Subsystem:
* Virtualization runner hosting disposable MicroVMs (Firecracker) and hardened QEMU/KVM guests.
* Rapid VM snapshot, execution, and memory rollback.
* Network simulation environments (Airgap, INETSim, WireGuard Egress Bridge).
* Real-time interactive guest display (HTML5 Canvas stream) and kernel syscall instrumentation feed.
* Closed-loop convergence bridge: automated forwarding of dropped scripts to the 59-Decoder Pipeline.

---

## H. What Emergent MUST NOT Rebuild

* ❌ DO NOT build a parallel verdict or scoring engine.
* ❌ DO NOT build an independent reasoning, IKG, or verdict engine inside the Sandbox.
* ❌ DO NOT replace or refactor the 615 Content Fabric rules.
* ❌ DO NOT replace or refactor the 59 deobfuscation decoders.
* ❌ DO NOT replace the core XDR investigation workspace or evidence explorer.
* ❌ DO NOT alter the canonical 8-stage causal pipeline:
  $$\text{Telemetry} \longrightarrow \text{Canonical Evidence} \longrightarrow \text{IUE / ICE} \longrightarrow \text{IKG} \longrightarrow \text{Security State} \longrightarrow \text{Deterministic Verdict} \longrightarrow \text{Response} \longrightarrow \text{Verification}$$

---

## I. Implementation Phases

* **P0 — Integration Foundation**: XDR shell routing, Telemetry Gateway skeleton, server-side tenant enforcement, evidence binding.
* **P1 — EDR Sensor Agent & Telemetry**: Windows/Linux sensor agents, mTLS enrollment, kernel minifilter/eBPF streaming, local SQLite ring-buffer.
* **P2 — EDR Investigation & Analytics**: 5-lane trajectory replay, interactive process tree, distributed live query (osquery).
* **P3 — UBAE Plane**: Entity 360 dossiers, behavioral baselining, anomalous logon detection, IKG identity enrichment.
* **P4 — Native Dynamic Sandbox**: MicroVM/QEMU hypervisor runner, live syscall stream, 6-subtab forensic report, 1-click convergence bridge to 59 decoders.

---

## J. Acceptance & Verification Requirements

Before certifying any milestone, Emergent must execute the automated test scenarios specified in `06_IMPLEMENTATION/NIVXFORGE_EDR_ACCEPTANCE_TEST_PLAN.md`:
1. **EDR Lifecycle**: Live sensor enrolls, streams $\ge 1{,}000\text{ EPS}$, fires a 615 Content Fabric detection, updates trajectory and process tree, correlates into an incident, and updates the workspace.
2. **Sandbox Lifecycle**: Submitting a sample boots a MicroVM in $<500\text{ms}$, streams syscalls, decodes dropped payloads in the 59-decoder suite, and projects findings onto the IKG.
3. **Response Lifecycle**: Host isolation refuses containment of Domain Controllers and Healthcare nodes, drops packets via kernel driver while maintaining controller mTLS:443, and generates cryptographic telemetry proof.
4. **Multi-Tenant Boundary**: Cross-tenant data access is strictly blocked; queries rely exclusively on server-side token claims.

---

## K. Document Authority Hierarchy

When resolving technical discrepancies, apply this strict precedence order:

1. **Runtime / Code Evidence**: Executable tests (`backend/run_content_truth_audit.py`, `backend/verify_decoder_truth_e2e.py`) and verified production schemas.
2. **NivXRay Current-State Truth Contract**: `01_TRUTH_CONTRACT/NIVXRAY_CURRENT_STATE_TRUTH.md`.
3. **EDR Truth Audit**: `02_EDR_TRUTH/NIVXFORGE_EDR_TRUTH_AUDIT.md`.
4. **Integration Contracts**: `05_INTEGRATION_CONTRACTS/` (Handoff, Code Map, Schemas, Tenancy, Response).
5. **Architecture Documents**: `03_EDR_ARCHITECTURE/` (Target Architecture, Benchmark).
6. **UI/UX Specifications**: `04_EDR_UIUX/` (Information Architecture, Parity Matrix, Attack-Chain Matrix, UI/UX Spec).
7. **Operational Prototype HTML**: `04_EDR_UIUX/NIVXFORGE_EDR_SANDBOX_OPERATIONAL_PROTOTYPE.html`  
   > *Note: The HTML prototype is an interactive UX reference only. It demonstrates the visual contract and interaction flow; it is NOT evidence that a capability is implemented in production backend code.*

---

## L. The Canonical 20-Step Attack-Chain Contract

Emergent must preserve the unbroken, bidirectional attack-chain traversal model across all 20 steps:

$$\begin{aligned}
\text{Detection} &\xrightarrow{\text{alert\_id}} \text{Alert Detail} \xrightarrow{\text{process\_guid}} \text{Process} \xrightarrow{\text{parent\_process\_guid}} \text{Parent Process} \xrightarrow{\text{device\_id}} \text{Device} \\
&\xrightarrow{\text{user\_id}} \text{User} \xrightarrow{\text{network\_flow\_id}} \text{Network Connection} \xrightarrow{\text{dns\_event\_id}} \text{DNS} \xrightarrow{\text{ioc}} \text{IOC} \xrightarrow{\text{artifact\_sha256}} \text{Dropped File} \\
&\xrightarrow{\text{sandbox\_job\_id}} \text{Sandbox} \xrightarrow{\text{dynamic\_evidence\_ids}} \text{Dynamic Evidence} \xrightarrow{\text{attck\_technique\_id}} \text{ATT\&CK} \xrightarrow{\text{ikg\_node\_edge\_ids}} \text{IKG} \\
&\xrightarrow{\text{security\_state\_version}} \text{Security State} \xrightarrow{\text{verdict\_id}} \text{Verdict} \xrightarrow{\text{impact\_assessment\_id}} \text{Impact} \xrightarrow{\text{response\_action\_id}} \text{Response} \\
&\xrightarrow{\text{verification\_evidence\_id}} \text{Verification}
\end{aligned}$$
