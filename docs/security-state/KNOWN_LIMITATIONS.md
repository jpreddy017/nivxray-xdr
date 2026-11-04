# NivXRay Security State Core: Known Limitations & Future Roadmap

> **Document Type:** Engineering Disclosure & Implementation Truth  
> **Status:** Authoritative  

---

## 1. Current Implementation Truth

| Subsystem Component | Implementation Status | Notes / Limitations |
| :--- | :--- | :--- |
| **Security State Engine** | **IMPLEMENTED** | Full 20-entity coverage, deterministic facts, epistemic tagging. |
| **State Transition Engine** | **IMPLEMENTED** | Cryptographic hash chaining, property mutation tracking. |
| **Causal Security Engine** | **IMPLEMENTED** | 7-level distinction, competing hypothesis tracking, kernel spawn mechanisms. |
| **Trusted Capability Abuse** | **IMPLEMENTED** | 11-dimensional context model for RMM, admin binaries, and cloud tools. |
| **Attack State Machine** | **IMPLEMENTED** | 18 explicit causal attack states, non-linear progression rules. |
| **Enterprise Reachability** | **IMPLEMENTED** | Multi-hop Identity, Credential, Network, Cloud, and Data reachability. |
| **Counterfactual Engine** | **IMPLEMENTED** | Parallel world simulation (World A vs B/C/D). |
| **Impact Engine** | **IMPLEMENTED** | Decoupled blast radius, Tier-0 exposure, and ransomware risk. |
| **Intervention Optimizer** | **IMPLEMENTED** | Multi-objective graph-cut optimization algorithm. |
| **Response Safety Gate** | **IMPLEMENTED** | Tenancy boundaries, Tier-0 protected asset rules, role verification. |
| **Response Verification** | **IMPLEMENTED** | Closed-loop environmental re-observation engine. |
| **Security State Ledger** | **IMPLEMENTED** | Append-only, SHA-256 block-chained tamper-evident audit log. |
| **Adversarial Simulator** | **IMPLEMENTED** | Multi-step trajectory projection using shared production models. |
| **FastAPI REST Router** | **IMPLEMENTED** | 10 canonical endpoints mounted under `/api/v2/security-state/...`. |
| **Golden Validation Corpus** | **IMPLEMENTED** | 18 test scenarios passing with 100% determinism. |
| **Performance Profiler** | **IMPLEMENTED** | Automated benchmark capturing p50, p95, p99, throughput, and memory. |

---

## 2. Known Limitations & Planned Extensions

1. **Topology Graph Scale**:
   - *Current*: Graph traversals use in-memory DAG representations suitable for up to 10,000 entities per case.
   - *Planned (Phase 15)*: Connect to persistent graph storage for enterprise deployments exceeding 100,000 active endpoints.
2. **Dynamic Live Agent Probes**:
   - *Current*: Response verification evaluates fresh telemetry streams delivered to the backend via standard ingestion.
   - *Planned (Phase 16)*: Direct bidirectional socket heartbeat with endpoint sensors (eBPF / Windows Minifilters) for sub-second verification.
3. **UI Investigation Workspace Overlay**:
   - *Current*: All data models, REST endpoints, and schemas are fully operational.
   - *Planned (Phase 17)*: Visual timeline graph component for React 19 / shadcn investigation workspace exposing the causal chain and parallel counterfactual worlds.
