# NivXRay XDR — Rule, Correlation & Playbook Data Flow Architecture
**Document Version:** 1.0.0  
**Status:** DELIVERED & OPERATIONAL  

---

## 1. End-to-End Data Flow Architecture

The data pipeline connects raw telemetry ingestion directly through canonical evidence, detection rule evaluation, multi-stage correlation, Security State synthesis, and down to playbook orchestration.

```mermaid
sequenceDiagram
    autonumber
    participant T as Ingestion Telemetry
    participant C as Canonical Evidence (SSOT)
    participant D as Enterprise Detection Library
    participant K as Correlation Engine (ICE)
    participant S as Security State Sidecar
    participant O as Intervention Optimizer
    participant P as Playbook Orchestrator
    participant G as Safety Gate & Approver
    participant V as Closed-Loop Verification

    T->>C: Normalize raw event (process/auth/network)
    C->>D: evaluate_detection(canonical)
    D-->>C: Match DET-EX-001 (OBSERVATION)
    C->>K: Emit signal to sliding entity window
    K->>K: Evaluate stateful operators (TEMPORAL_ORDERED)
    K-->>C: Emit CORRELATION_SUPPORTED (CORR-ENT-001)
    
    C->>S: Hydrate Security State Vector (Read-Only)
    S->>S: Causal DAG + Reachability Analysis over IKG
    S->>O: Formulate Counterfactual Worlds A-E
    O->>O: Rank minimal effective containment
    O-->>P: Recommended Plan (InterventionPlan)
    
    P->>P: Stage Playbook (PB-RAN-01)
    P->>G: Check Execution Safety Gate
    Note over G: AUTO_RESPONSE = FALSE<br/>APPROVAL_REQUIRED
    G-->>P: Analyst Grants Approval
    P->>P: Execute Actions (dry_run = True)
    P->>V: Trigger Post-Action Verification
    V-->>C: Insert Actioned Observation (hash protected)
    V-->>S: Reassess State Vector & Decrement Residual Risk
```

---

## 2. In-Flight Data Contracts

| Stage | Input Data Object | Output Data Object | Storage Collection |
| :--- | :--- | :--- | :--- |
| **Ingestion** | Raw Syslog / EVE / WinEvent JSON | Canonical Event Dict | `xdr_canonical_evidence` |
| **Detection** | Canonical Event Dict | `DetectionOutcome` (Rule ID, Tactic, Severity) | Memory / Audit Trail |
| **Correlation** | Signal (`detection_id`, `host_id`, `at`) | `CorrelationMatch` (Evidence Chain, ATT&CK) | `xdr_correlation_matches` |
| **Security State** | Canonical Evidences + Correlation Matches | `SecurityStateVector` (Stage, Caps, Residual Risk) | `xdr_security_state_ledger` |
| **Intervention** | `SecurityStateVector` + Reachability Paths | `InterventionPlan` (Actions, World A-E scores) | Memory / Cache |
| **Playbook** | `InterventionPlan` + `PlaybookDefinition` | `PlaybookExecutionTrace` (Stages, Steps, Timestamps)| `xdr_playbook_traces` |
| **Verification** | `PlaybookExecutionTrace` + Telemetry Check | Post-Action Intelligence Observation | `xdr_intelligence_observations` |

---
*End of Rule, Correlation & Playbook Data Flow Specification.*
