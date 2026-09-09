# NIVXFORGE EDR & NATIVE DYNAMIC SANDBOX: SCOPE & BOUNDARIES REFERENCE
**Document ID:** `NIVXFORGE-REF-BOUNDARIES-2026-09-05`  
**Classification:** Reference Document for Emergent Engineering  
**Handoff Status:** 🟢 APPROVED & READY FOR EMERGENT INTEGRATION REVIEW  

---

## 1. Document Authority Hierarchy

When interpreting requirements, resolving design ambiguities, or reconciling differences between artifacts, Emergent must strictly apply the following order of precedence:

1. **Runtime / Code Evidence**: Executable tests (`backend/run_content_truth_audit.py`, `backend/verify_decoder_truth_e2e.py`) and verified production schemas.
2. **NivXRay Current-State Truth Contract**: [`01_TRUTH_CONTRACT/NIVXRAY_CURRENT_STATE_TRUTH.md`](file:///d:/Projects/docs/emergent-handoff-package/01_TRUTH_CONTRACT/NIVXRAY_CURRENT_STATE_TRUTH.md).
3. **EDR Truth Audit**: [`02_EDR_TRUTH/NIVXFORGE_EDR_TRUTH_AUDIT.md`](file:///d:/Projects/docs/emergent-handoff-package/02_EDR_TRUTH/NIVXFORGE_EDR_TRUTH_AUDIT.md).
4. **Integration Contracts**:
   - Master Handoff: [`05_INTEGRATION_CONTRACTS/NIVXFORGE_EDR_EMERGENT_HANDOFF.md`](file:///d:/Projects/docs/emergent-handoff-package/05_INTEGRATION_CONTRACTS/NIVXFORGE_EDR_EMERGENT_HANDOFF.md)
   - Code-to-Capability Map: [`05_INTEGRATION_CONTRACTS/NIVXFORGE_EDR_CODE_CAPABILITY_MAP.md`](file:///d:/Projects/docs/emergent-handoff-package/05_INTEGRATION_CONTRACTS/NIVXFORGE_EDR_CODE_CAPABILITY_MAP.md)
   - Integration Pipeline: [`05_INTEGRATION_CONTRACTS/NIVXFORGE_EDR_INTEGRATION_CONTRACT.md`](file:///d:/Projects/docs/emergent-handoff-package/05_INTEGRATION_CONTRACTS/NIVXFORGE_EDR_INTEGRATION_CONTRACT.md)
   - Canonical Evidence Contract: [`05_INTEGRATION_CONTRACTS/NIVXFORGE_EDR_CANONICAL_EVIDENCE_CONTRACT.md`](file:///d:/Projects/docs/emergent-handoff-package/05_INTEGRATION_CONTRACTS/NIVXFORGE_EDR_CANONICAL_EVIDENCE_CONTRACT.md)
   - UI Integration Map: [`05_INTEGRATION_CONTRACTS/NIVXFORGE_EDR_UI_INTEGRATION_MAP.md`](file:///d:/Projects/docs/emergent-handoff-package/05_INTEGRATION_CONTRACTS/NIVXFORGE_EDR_UI_INTEGRATION_MAP.md)
   - Attack-Chain Implementation: [`05_INTEGRATION_CONTRACTS/NIVXFORGE_EDR_ATTACK_CHAIN_IMPLEMENTATION_MAP.md`](file:///d:/Projects/docs/emergent-handoff-package/05_INTEGRATION_CONTRACTS/NIVXFORGE_EDR_ATTACK_CHAIN_IMPLEMENTATION_MAP.md)
   - Security & Tenancy: [`05_INTEGRATION_CONTRACTS/NIVXFORGE_EDR_SECURITY_TENANCY_CONTRACT.md`](file:///d:/Projects/docs/emergent-handoff-package/05_INTEGRATION_CONTRACTS/NIVXFORGE_EDR_SECURITY_TENANCY_CONTRACT.md)
   - Response Integration: [`05_INTEGRATION_CONTRACTS/NIVXFORGE_EDR_RESPONSE_INTEGRATION_CONTRACT.md`](file:///d:/Projects/docs/emergent-handoff-package/05_INTEGRATION_CONTRACTS/NIVXFORGE_EDR_RESPONSE_INTEGRATION_CONTRACT.md)
5. **Architecture Documents**:
   - Target Architecture & Plan: [`03_EDR_ARCHITECTURE/NIVXFORGE_EDR_TARGET_ARCHITECTURE_AND_IMPLEMENTATION_PLAN.md`](file:///d:/Projects/docs/emergent-handoff-package/03_EDR_ARCHITECTURE/NIVXFORGE_EDR_TARGET_ARCHITECTURE_AND_IMPLEMENTATION_PLAN.md)
   - Industry Benchmark: [`03_EDR_ARCHITECTURE/NIVXFORGE_EDR_SANDBOX_INDUSTRY_BENCHMARK.md`](file:///d:/Projects/docs/emergent-handoff-package/03_EDR_ARCHITECTURE/NIVXFORGE_EDR_SANDBOX_INDUSTRY_BENCHMARK.md)
6. **UI/UX Specifications & Parity Matrices**:
   - 37-Surface Information Architecture: [`04_EDR_UIUX/NIVXFORGE_EDR_INFORMATION_ARCHITECTURE.md`](file:///d:/Projects/docs/emergent-handoff-package/04_EDR_UIUX/NIVXFORGE_EDR_INFORMATION_ARCHITECTURE.md)
   - Exhaustive Parity Matrix: [`04_EDR_UIUX/NIVXFORGE_EDR_EXHAUSTIVE_UIUX_PARITY_MATRIX.md`](file:///d:/Projects/docs/emergent-handoff-package/04_EDR_UIUX/NIVXFORGE_EDR_EXHAUSTIVE_UIUX_PARITY_MATRIX.md)
   - Attack-Chain UX Matrix: [`04_EDR_UIUX/NIVXFORGE_EDR_ATTACK_CHAIN_UX_MATRIX.md`](file:///d:/Projects/docs/emergent-handoff-package/04_EDR_UIUX/NIVXFORGE_EDR_ATTACK_CHAIN_UX_MATRIX.md)
   - UI/UX Spec: [`04_EDR_UIUX/NIVXFORGE_EDR_SANDBOX_UIUX_SPEC.md`](file:///d:/Projects/docs/emergent-handoff-package/04_EDR_UIUX/NIVXFORGE_EDR_SANDBOX_UIUX_SPEC.md)
7. **Prototype HTML**:
   - Operational Prototype: [`04_EDR_UIUX/NIVXFORGE_EDR_SANDBOX_OPERATIONAL_PROTOTYPE.html`](file:///d:/Projects/docs/emergent-handoff-package/04_EDR_UIUX/NIVXFORGE_EDR_SANDBOX_OPERATIONAL_PROTOTYPE.html)  
   > *Note: The HTML prototype is an interactive UX reference only. It demonstrates the visual contract and interaction flow; it is NOT evidence that a capability is implemented in production backend code.*

---

## 2. Emergent Implementation Boundaries

Emergent's engineering scope is strictly focused on building the endpoint sensor, ingestion infrastructure, analytics, UBAE, and dynamic sandbox runner:

### EDR Engineering Scope:
* Cross-platform endpoint sensor (Windows kernel minifilter / Linux eBPF daemon).
* Endpoint enrollment and mutual TLS (mTLS 1.3) PKI infrastructure.
* Telemetry collection (Process, File, Network, DNS, Registry, Services).
* Ingestion Gateway (:8443) and schema normalization to Canonical Evidence.
* Real-time 5-lane device trajectory historical replay engine.
* Interactive process ancestry tree with living-off-the-land (LOLBAS) anomaly tagging.
* Distributed live query daemon (osquery).
* On-demand DFIR forensic triage package acquisition.
* Kernel-level endpoint response drivers (Network Isolation with safety gates, Process Kill, File Quarantine).

### UBAE (User & Entity Behavior Analytics) Scope:
* Entity 360 dossiers for users, hosts, and service accounts.
* Behavioral baselining and anomalous logon detection (Interactive Type 2, Network Type 3, RDP Type 10).
* Peer group deviation scoring and lateral movement indicators.
* Direct projection of identity anomaly edges into the Incremental Knowledge Graph (IKG).

### Native Dynamic Sandbox Scope:
* Virtualization runner hosting disposable MicroVMs (Firecracker) and hardened QEMU/KVM guests.
* Rapid VM snapshot, execution, and memory rollback.
* Network simulation environments (Isolated Airgap, INETSim Emulated Services, WireGuard Egress Bridge).
* Real-time interactive guest display (HTML5 Canvas stream) and kernel syscall instrumentation feed.
* Dynamic extraction of dropped payloads, PCAP captures, memory allocations, and configuration blocks.
* Closed-loop convergence bridge: automated forwarding of dropped scripts to the 59-Decoder Pipeline.

---

## 3. Explicit "DO NOT REBUILD" Non-Goals

Emergent **MUST REUSE** the existing NivXRay Core engines and **MUST NOT** duplicate or re-implement:

1. **Canonical Evidence Store & Provenance Ledger**: Maintain the existing immutable hash architecture (`backend/routers/artifacts.py`).
2. **Identity Understanding Engine (IUE)**: Lanes A, B, and C remain authoritative (`backend/routers/iue_lane_*.py`).
3. **Investigation Correlation Engine (ICE)**: Existing correlation engine remains authoritative (`backend/routers/correlations.py`).
4. **Detection Engine & 615 Content Fabric**: The 615 active-certified Sigma and YARA-L rules are frozen and must not be altered (`backend/detection_content/`).
5. **Incremental Knowledge Graph (IKG)**: The causal directed acyclic graph engine remains authoritative (`backend/routers/attack_graph.py`, `attack_story.py`).
6. **Authoritative Security State Engine**: The security state contract remains strictly decoupled from verdict score bands (`backend/security_state/contracts.py`).
7. **Deterministic Verdict Engine**: Mathematical calculation without proxy weights remains authoritative (`backend/routers/verdict_stage2.py`, `backend/reasoning/`).
8. **59-Decoder Deobfuscation Suite**: The 59 registered codecs remain active and frozen (`backend/decoders/`, `backend/routers/analyze.py`).
9. **Evidence Explorer & Investigation Workspace**: The existing 8-stage causal investigation UI remains authoritative (`apps/nivxray-xdr/src/xdr/pages/`).
10. **Approval & Response Framework**: The existing response manager and ledger remain authoritative (`apps/nivxray-xdr-response/main.py`, `backend/routers/xdr_cortex_actions.py`).
