# NIVXFORGE EDR & NATIVE DYNAMIC SANDBOX: MASTER EMERGENT INTEGRATION HANDOFF
**Authoritative Architectural Blueprint, Integration Contracts, Repository Grounding, and Phase Backlog for Emergent Engineering**  
**Document ID:** `NIVXFORGE-EMERGENT-HANDOFF-2026-09-05`  
**Classification:** Governing Engineering Handoff Pack  
**Handoff Status:** 🟢 APPROVED & READY FOR EMERGENT INTEGRATION REVIEW  

---

## Table of Contents
1. [Executive Summary](#1-executive-summary)
2. [Current NivXRay XDR Truth](#2-current-nivxray-xdr-truth)
3. [NivXForge EDR Current-State Truth](#3-nivxforge-edr-current-state-truth)
4. [Native Sandbox Current/Target Boundary](#4-native-sandbox-currenttarget-boundary)
5. [Target Architecture Overview](#5-target-architecture-overview)
6. [Existing NivXRay Engines to Reuse (DO NOT REBUILD)](#6-existing-nivxray-engines-to-reuse-do-not-rebuild)
7. [EDR → NivXRay Integration Contract](#7-edr--nivxray-integration-contract)
8. [Sandbox → NivXRay Integration Contract](#8-sandbox--nivxray-integration-contract)
9. [API Contract Architecture](#9-api-contract-architecture)
10. [Canonical Evidence Contract](#10-canonical-evidence-contract)
11. [Entity and Identity Contract](#11-entity-and-identity-contract)
12. [Tenant and Security Boundary](#12-tenant-and-security-boundary)
13. [Response, Approval, and Verification Contract](#13-response-approval-and-verification-contract)
14. [UI/UX Integration Contract](#14-uiux-integration-contract)
15. [37 EDR Surface Implementation Map](#15-37-edr-surface-implementation-map)
16. [Attack-Chain Pivot Map](#16-attack-chain-pivot-map)
17. [Industry Parity Matrix Summary](#17-industry-parity-matrix-summary)
18. [Phase 1 Implementation Scope (EDR Sensor & Telemetry)](#18-phase-1-implementation-scope-edr-sensor--telemetry)
19. [Phase 2 Implementation Scope (EDR Investigation & Analytics)](#19-phase-2-implementation-scope-edr-investigation--analytics)
20. [Phase 3 Implementation Scope (UBAE / UEBA Plane)](#20-phase-3-implementation-scope-ubae--ueba-plane)
21. [Phase 4 Implementation Scope (Native Dynamic Sandbox)](#21-phase-4-implementation-scope-native-dynamic-sandbox)
22. [System Dependencies & Prerequisites](#22-system-dependencies--prerequisites)
23. [Architectural Risks & Mitigations](#23-architectural-risks--mitigations)
24. [Non-Goals / Explicit "DO NOT REBUILD" List](#24-non-goals--explicit-do-not-rebuild-list)
25. [Engineering Acceptance Criteria](#25-engineering-acceptance-criteria)
26. [Validation & Test Plan](#26-validation--test-plan)
27. [Rollback & Failure Recovery Strategy](#27-rollback--failure-recovery-strategy)

---

## 1. Executive Summary

This document serves as the formal **Emergent Integration Handoff Pack** for **NivXForge EDR** and the **Native Dynamic Sandbox** within the **NivXRay XDR** ecosystem.

### The Emergent Mandate: Review → Reconcile → Integrate → Productionize
Emergent is tasked with transitioning NivXForge from approved architectural, UI/UX, and data contracts into production implementation. Emergent's mandate is explicitly **NOT to redesign or rebuild the NivXRay Core platform**, but to:
1. **Review and Reconcile**: Verify existing repository contracts, schemas, and endpoints against the handoff specifications.
2. **Integrate**: Connect the endpoint telemetry stream, live query engine, and dynamic sandbox runner into the existing canonical evidence pipeline.
3. **Productionize**: Implement the cross-platform sensor agent (Windows/Linux) and virtualization runner while strictly preserving the existing 615-object Content Fabric, 59 decoders, and deterministic reasoning engines.

---

## 2. Current NivXRay XDR Truth

NivXRay XDR possesses a battle-tested, mature reasoning and investigation backend:
* **The 615-Object Content Fabric**: 100% verified, active-certified rules across Sigma, YARA-L, and native behavioral logic (`backend/run_content_truth_audit.py` exits 0 with 0 semantic duplicates and 0 quarantined).
* **The 59-Decoder Deobfuscation Suite**: 59 active codecs registered across CIPHER, COMPRESSION, ENCODING, ENCRYPTION, INTELLIGENCE, NORMALIZE, and RECONSTRUCT (`backend/verify_decoder_truth_e2e.py` passes 100% E2E).
* **Phase 0 Truthfulness Closed**: 
  - Authoritative Security State is strictly decoupled from Verdict bands and fails closed (`NO AUTHORITATIVE SECURITY STATE RECORDED`).
  - Verdict calculation does not fabricate proxy score weights.
  - Evidence Explorer (`XdrEvidenceExplorerPage.jsx`) and Investigation Workspace (`XdrInvestigationWorkspacePage.jsx`) are bound strictly to real authoritative evidence APIs without synthetic demo fallbacks.

---

## 3. NivXForge EDR Current-State Truth

A comprehensive forensic audit of the existing repository reveals:
* **Implemented**: Basic endpoint registration API (`/api/v2/endpoints`), XDR alerts queue, incidents correlation, evidence explorer, and investigation workspace tabs.
* **Scaffold / Partial**: Device timeline, basic host metadata, network flows from perimeter sources, SIEM query builders.
* **Missing (To Be Built by Emergent)**:
  - Cross-platform endpoint sensor agent daemon (Windows kernel minifilter / Linux eBPF).
  - Microsecond 5-lane device trajectory streaming pipeline.
  - Distributed osquery-compatible live fleet query daemon.
  - Kernel-level network isolation driver with AD Domain Controller and ICU healthcare safety gates.
  - Encrypted file quarantine vault (`.nvxvault`) and volatile memory acquisition driver.

---

## 4. Native Sandbox Current/Target Boundary

### The Non-Negotiable Subsystem Boundary
The Native Dynamic Sandbox is architected strictly as an **evidence-producing execution subsystem**:
$$\text{Suspicious Artifact} \longrightarrow \text{MicroVM / QEMU Execution} \longrightarrow \text{Dynamic Telemetry} \longrightarrow \text{Canonical Evidence Vault} \longrightarrow \text{NivXRay Core}$$

> [!CRITICAL]
> **No Parallel Reasoning**: The Sandbox does **NOT** build its own reasoning engine, IKG graph, security state engine, or verdict calculator. All syscall traces, network flows, dropped payloads, and memory anomalies generated in the sandbox are serialized as **Canonical Evidence** and processed by the existing NivXRay Core pipeline.

---

## 5. Target Architecture Overview

The unified platform operates across an unbroken **8-stage causal reasoning pipeline**:

$$\text{Telemetry} \longrightarrow \text{Canonical Evidence} \longrightarrow \text{IUE / ICE} \longrightarrow \text{IKG} \longrightarrow \text{Security State} \longrightarrow \text{Deterministic Verdict} \longrightarrow \text{Response} \longrightarrow \text{Verification}$$

* **IUE (Identity Understanding Engine)**: Resolves process, user, and device identities across Lanes A, B, and C.
* **ICE (Investigation Correlation Engine)**: Evaluates multi-signal correlations across host, network, and cloud telemetry.
* **IKG (Incremental Knowledge Graph)**: Maintains a dynamic causal directed acyclic graph (DAG) linking processes, files, sockets, and adversary techniques.
* **Security State**: Authoritative, persistent assessment of compromised posture.
* **Deterministic Verdict**: Mathematically verifiable verdict without fabricated weights.
* **Intervention & Response**: Safety-gated containment and remediation.
* **Verification**: Subsequent sensor telemetry proof confirming containment effectiveness.

---

## 6. Existing NivXRay Engines to Reuse (DO NOT REBUILD)

Emergent **MUST REUSE** the following existing components without replacement or duplication:

| Engine / Component | Repository Path | Action Required |
|---|---|---|
| **Identity Understanding (IUE)** | `backend/routers/iue_lane_a.py`, `iue_lane_b.py`, `iue_lane_c.py` | **REUSE AS-IS** |
| **Correlation Engine (ICE)** | `backend/routers/correlations.py`, `xdr_correlation.py` | **REUSE AS-IS** |
| **Knowledge Graph (IKG)** | `backend/routers/attack_graph.py`, `attack_story.py` | **REUSE AS-IS** |
| **Security State Engine** | `backend/security_state/contracts.py`, `detection_bridge.py` | **REUSE & INTEGRATE** |
| **Deterministic Verdict Engine** | `backend/routers/verdict_stage2.py`, `backend/reasoning/` | **REUSE AS-IS** |
| **59-Decoder Deobfuscation Suite** | `backend/decoders/`, `backend/routers/analyze.py` | **REUSE AS-IS** |
| **615 Content Fabric** | `backend/detection_content/`, `backend/routers/xdr_detection_content.py` | **REUSE AS-IS** |
| **Evidence Explorer** | `apps/nivxray-xdr/src/xdr/pages/XdrEvidenceExplorerPage.jsx` | **REUSE AS-IS** |
| **Investigation Workspace** | `apps/nivxray-xdr/src/xdr/pages/XdrInvestigationWorkspacePage.jsx` | **REUSE AS-IS** |
| **Response Framework** | `apps/nivxray-xdr-response/main.py`, `backend/routers/xdr_cortex_actions.py` | **EXTEND WITH EDR DRIVERS** |

---

## 7. EDR → NivXRay Integration Contract

```text
[ NivXForge Sensor Agent (Win/Linux) ]
               │ (mTLS Streaming Telemetry)
               ▼
[ Telemetry Ingestion Gateway (:8443) ]
               │ (Raw JSON / Protobuf)
               ▼
[ Normalizer & Schema Validator ]
               │ (Canonical Schema)
               ▼
[ Evidence Vault (Immutable Hash Ledger) ]
               │ (UUID References)
               ▼
[ NivXRay Core Reasoning (IUE / ICE / IKG) ]
```

1. **Protocol**: Mutual TLS 1.3 over HTTPS/gRPC.
2. **Batching**: Telemetry flushes every $500\text{ms}$ or upon reaching $100$ events.
3. **Backpressure**: Sensor maintains a local SQLite ring-buffer (up to $250\text{ MB}$) during network disconnection.

---

## 8. Sandbox → NivXRay Integration Contract

1. **Job Dispatch**: NivXRay Core dispatches detonation jobs via `POST /api/v2/sandbox/detonate` with sample hash, execution parameters, and case ID.
2. **Guest Telemetry Streaming**: Syscalls, spawned processes, network sockets, and dropped files stream in real-time to the Telemetry Ingestion Gateway.
3. **Artifact Forwarding**: Dropped secondary payloads automatically pass to the **59-Decoder Pipeline** (`/api/decode/smart`) for recursive unwrapping.
4. **Evidence Commitment**: On job completion, the sandbox runner commits all PCAPs, memory dumps, and execution logs to the **Evidence Vault** and binds them to the active investigation case.

---

## 9. API Contract Architecture

* Detailed specification located in: [`NIVXFORGE_EDR_INTEGRATION_CONTRACT.md`](file:///d:/Projects/docs/handoff/NIVXFORGE_EDR_INTEGRATION_CONTRACT.md).
* Core endpoints to expose and wire:
  - `POST /api/v2/edr/telemetry/stream` (Sensor event ingestion)
  - `POST /api/v2/edr/fleet/live-query` (Distributed osquery dispatch)
  - `POST /api/v2/edr/actions/isolate` (Safety-gated containment)
  - `POST /api/v2/sandbox/detonate` (Dynamic detonation job submission)
  - `GET  /api/v2/sandbox/jobs/:id/trace` (Live syscall telemetry stream)

---

## 10. Canonical Evidence Contract

* Detailed specification located in: [`NIVXFORGE_EDR_CANONICAL_EVIDENCE_CONTRACT.md`](file:///d:/Projects/docs/handoff/NIVXFORGE_EDR_CANONICAL_EVIDENCE_CONTRACT.md).
* Enforces standard schema across all 11 EDR telemetry types and 15 Sandbox event types.
* Mandatory Common Envelope fields: `tenant_id`, `event_id`, `timestamp`, `source`, `device_id`, `user_id`, `process_id`, `parent_process_id`, `file_hash`, `network_endpoint`, `artifact_id`, `provenance`, `confidence`, `raw_event`, `canonical_event`.

---

## 11. Entity and Identity Contract

1. **Device Identity**: Immutable hardware UUID bound to X.509 client certificate subject key identifier.
2. **User Identity**: Canonical resolution across Active Directory SID, UPN (`jdoe@corp.internal`), and local UID.
3. **Process Identity**: Globally unique Process GUID (`{device_id}:{pid}:{create_time_epoch}`).

---

## 12. Tenant and Security Boundary

* Detailed specification located in: [`NIVXFORGE_EDR_SECURITY_TENANCY_CONTRACT.md`](file:///d:/Projects/docs/handoff/NIVXFORGE_EDR_SECURITY_TENANCY_CONTRACT.md).
* **Strict Invariant**:
  $$\text{Client} \longrightarrow \text{XDR API} \longrightarrow \text{Authorization Middleware} \longrightarrow \text{Server-Side Tenant Context} \longrightarrow \text{Database}$$
  **Never** trust or execute queries based on client-supplied `tenant_id` parameters.

---

## 13. Response, Approval, and Verification Contract

* Detailed specification located in: [`NIVXFORGE_EDR_RESPONSE_INTEGRATION_CONTRACT.md`](file:///d:/Projects/docs/handoff/NIVXFORGE_EDR_RESPONSE_INTEGRATION_CONTRACT.md).
* **State Machine**:
  $$\text{Recommendation} \longrightarrow \text{Intervention Plan} \longrightarrow \text{Approval} \longrightarrow \text{Action Requested} \longrightarrow \text{Action Executed} \longrightarrow \text{Action Acknowledged} \longrightarrow \text{Action Verified}$$
* **Safety Gate Invariant**: Host isolation enforces verification that the target is **NOT an Active Directory Domain Controller or tagged Healthcare Life-Safety Node**, while pinning controller mTLS channel:443.

---

## 14. UI/UX Integration Contract

* Detailed specification located in: [`NIVXFORGE_EDR_UI_INTEGRATION_MAP.md`](file:///d:/Projects/docs/handoff/NIVXFORGE_EDR_UI_INTEGRATION_MAP.md).
* All screens reside under the unified **NivXRay XDR Shell** (`apps/nivxray-xdr/src/xdr/XdrShell.jsx`).
* Standardized component states: Active Data, Loading Skeleton, Honest Empty State, Actionable Error State, RBAC Permission State, and Two-Step Dangerous Action Confirmation Modal.

---

## 15. 37 EDR Surface Implementation Map

Complete mapping of all 37 surfaces across Groups 1–7 detailing route, component, API, data source, and status is codified in [`NIVXFORGE_EDR_UI_INTEGRATION_MAP.md`](file:///d:/Projects/docs/handoff/NIVXFORGE_EDR_UI_INTEGRATION_MAP.md).

---

## 16. Attack-Chain Pivot Map

Complete 20-step canonical chain (`Detection → Alert → Process → Parent → Device → User → Network → DNS → IOC → Dropped File → Sandbox → Dynamic Evidence → ATT&CK → IKG → Security State → Verdict → Impact → Response → Verification`) and 11 special pivots are fully mapped in [`NIVXFORGE_EDR_ATTACK_CHAIN_IMPLEMENTATION_MAP.md`](file:///d:/Projects/docs/handoff/NIVXFORGE_EDR_ATTACK_CHAIN_IMPLEMENTATION_MAP.md).

---

## 17. Industry Parity Matrix Summary

Audit against 12 platforms (CrowdStrike, MDE, SentinelOne, Cortex XDR, Cisco, Trellix, Sophos, Trend Micro, Carbon Black, Elastic, Cybereason, Bitdefender) is codified in [`NIVXFORGE_EDR_EXHAUSTIVE_UIUX_PARITY_MATRIX.md`](file:///d:/Projects/docs/uiux/NIVXFORGE_EDR_EXHAUSTIVE_UIUX_PARITY_MATRIX.md).

---

## 18. Phase 1 Implementation Scope (EDR Sensor & Telemetry)
* Cross-platform sensor agent (Windows C++/Rust driver, Linux eBPF).
* Endpoint enrollment with X.509 mTLS certificates.
* Streaming telemetry gateway for Process, File, Network, DNS, and Registry events.
* Local SQLite ring-buffer for offline resilience.

---

## 19. Phase 2 Implementation Scope (EDR Investigation & Analytics)
* 5-lane device trajectory historical replay engine.
* Interactive process ancestry tree with living-off-the-land (LOLBAS) anomaly tagging.
* Distributed osquery-compatible live query daemon.
* On-demand DFIR triage package acquisition.

---

## 20. Phase 3 Implementation Scope (UBAE / UEBA Plane)
* Entity 360 dossiers for users, hosts, and service accounts.
* Behavioral baselining and anomalous logon detection (interactive vs network vs RDP).
* Direct projection of identity risk scores into the Incremental Knowledge Graph (IKG).

---

## 21. Phase 4 Implementation Scope (Native Dynamic Sandbox)
* Virtualization runner hosting MicroVMs (Firecracker) and hardened QEMU/KVM guests.
* Anti-evasion countermeasures (fake mouse/typing jitter, uptime virtualization, ACPI hiding).
* INETSim emulated network services and WireGuard egress bridge.
* Dynamic execution reports with 1-click convergence handoff to the 59-decoder pipeline.

---

## 22. System Dependencies & Prerequisites
* Host OS: Linux (Ubuntu 22.04 LTS recommended for server components).
* Kernel: Linux Kernel $\ge 5.15$ with eBPF support enabled (`CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`).
* Virtualization: Intel VT-x / AMD-V hardware virtualization enabled on sandbox runners.
* Runtimes: Python 3.11+, Node.js v20+, Rust 1.75+ (for high-performance agent components).

---

## 23. Architectural Risks & Mitigations
1. **Risk: Kernel Driver Instability (BSOD / Kernel Panic)**:
   - *Mitigation*: Sensor enforces hardware watchdog, CPU throttling ($<2\%$), and crash isolation.
2. **Risk: Telemetry Ingestion Backpressure**:
   - *Mitigation*: Gateway implements Kafka/Redis streaming queue with consumer group scaling.
3. **Risk: Destructive Isolation of Critical Servers**:
   - *Mitigation*: Hard-coded, automated safety gate refuses containment of Domain Controllers and Healthcare nodes.

---

## 24. Non-Goals / Explicit "DO NOT REBUILD" List
Emergent is explicitly instructed **NOT** to rebuild:
* ❌ DO NOT build a custom verdict calculation engine.
* ❌ DO NOT build a custom causal knowledge graph.
* ❌ DO NOT build an independent reasoning engine inside the Sandbox.
* ❌ DO NOT replace or refactor the 615 Content Fabric rules.
* ❌ DO NOT replace or refactor the 59 deobfuscation decoders.
* ❌ DO NOT re-architect the core XDR investigation workspace or evidence explorer.

---

## 25. Engineering Acceptance Criteria
1. Sensor agent successfully enrolls via mTLS and streams $\ge 1{,}000\text{ EPS}$ without dropping packets.
2. Process execution events populate the 5-lane trajectory and process tree within $1\text{s}$ of occurrence.
3. Host isolation immediately drops non-management packets while maintaining controller mTLS connection.
4. Dropped malware in sandbox successfully detonates and passes secondary payloads to the 59-decoder pipeline.
5. All 615 content objects and 59 decoders pass truth audits 100%.

---

## 26. Validation & Test Plan
* Codified in [`NIVXFORGE_EDR_ACCEPTANCE_TEST_PLAN.md`](file:///d:/Projects/docs/handoff/NIVXFORGE_EDR_ACCEPTANCE_TEST_PLAN.md).
* Covers automated end-to-end integration test batteries for EDR telemetry, Live Query, Sandbox detonation, and Response containment.

---

## 27. Rollback & Failure Recovery Strategy
* **Sensor Rollback**: Over-the-air downgrade to previous stable sensor version ring within 60 seconds.
* **Isolation Failsafe**: In the event of controller connectivity loss exceeding 15 minutes, isolated sensor automatically reverts network filters to restore emergency connectivity.
* **Code Rollback**: Clean git commit boundary preserving existing Phase 0 frozen state.
