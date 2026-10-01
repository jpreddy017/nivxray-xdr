# NivXRay Security State & Causal Intelligence Architecture

> **Document Type:** Phase 0 Architecture Specification  
> **Status:** Authoritative Blueprint  
> **Truth Commit:** `d3f7a0a000892131abc9a32ee97009338dd38d79`  
> **Target Package:** `backend/security_state/`  
> **Integration Surface:** `backend/v2/` & `backend/canonical/`

---

## 1. Executive Summary & Foundational Paradigm

Traditional SIEM/EDR/XDR platforms operate on an alert-centric, rule-matching paradigm:
```
TELEMETRY / LOGS ──→ DETECTION RULE ──→ ALERT ──→ INCIDENT ──→ MANUAL / SOAR RESPONSE
```
This paradigm suffers from severe structural flaws: alert fatigue, brittle detections, high false positives, lack of causal grounding, post-execution reactivity, and dangerous automated responses without verified safety or containment validation.

NivXRay evolves to an **Evidence-First, Deterministic, State-Aware, Causal Control Substrate**:
```
OBSERVE
   ↓
EVIDENCE (Canonical Evidence Model & SSOT)
   ↓
SECURITY STATE (Entities, Observed Facts, Epistemic States)
   ↓
CAUSAL MODEL (Temporal vs Statistical vs Supported vs Contradicted Causality)
   ↓
ATTACK STATE (18-Stage Causal Attack State Machine)
   ↓
ATTACKER CAPABILITY (Trusted Capability Abuse Modeling)
   ↓
REACHABILITY (Identity, Privilege, Network, Data, Control-Plane Paths)
   ↓
COUNTERFACTUAL FUTURES (World A: Do Nothing vs World B/C: Interventions)
   ↓
IMPACT PROJECTION (Decoupled from Verdict: Criticality, Blast Radius, Ransomware Risk)
   ↓
INTERVENTION OPTIMIZATION (Minimum Effective Intervention to sever attack graph)
   ↓
POLICY / SAFETY (Multi-Gate Approval, Scope, Reversibility, Evidence Preservation)
   ↓
RESPONSE (Execution via Response Engine)
   ↓
VERIFICATION (Re-observation: Did capability disappear? Did attacker relocate?)
   ↓
NEW SECURITY STATE (Auditable Ledgered Transition)
```

---

## 2. Core Principles & Non-Negotiable Invariants

1. **NO EVIDENCE → NO CLAIM**:
   Every state property, capability classification, reachability assertion, causal link, and impact projection must have direct, verifiable provenance to canonical evidence. Speculation is prohibited.
2. **Epistemic Honesty**:
   Confidence is never collapsed into an opaque 0–100 integer. Every claim carries an explicit epistemic status:
   `OBSERVED` | `SUPPORTED` | `DERIVED` | `LIKELY` | `POSSIBLE` | `UNSUPPORTED` | `CONTRADICTED` | `DISPROVEN`.
3. **Causality ≠ Correlation**:
   The engine strictly differentiates temporal sequence and statistical co-occurrence from supported causal mechanisms with explicit causal bases and tracked competing explanations.
4. **Verdict Separated From Impact**:
   - **Verdict** answers: *"What does the evidence establish occurred?"*
   - **Impact** answers: *"What business assets, data, or services are exposed or affected?"*
   High impact never artificially inflates low-confidence evidence into a malicious verdict.
5. **No Blind Containment (Response Safety & Verification)**:
   Response execution is never assumed successful from an HTTP 200 return code. Containment is valid only when verified by subsequent environmental observation proving the attack path is severed.
6. **AI Boundary (Advisory Only)**:
   AI/LLMs may summarize, explain, hypothesize, and assist human threat hunting. AI is **NEVER** the source of truth, cannot create authoritative evidence, cannot alter verdicts, cannot mutate security states, and cannot approve response actions.
7. **Deterministic Replayability**:
   Given identical evidence, configuration, knowledge version, and engine version, all computations produce byte-identical outputs verified by SHA-256 fingerprinting.

---

## 3. High-Level Subsystem Topology

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                                 NivXRay Authoritative Core                                  │
│                                                                                             │
│  ┌───────────────────────┐   ┌───────────────────────────┐   ┌───────────────────────────┐  │
│  │ Ingestion & Decoders  │   │  Canonical Evidence Model │   │   Authoritative SSOT      │  │
│  │ (26 plugins, recursive│──→│  (CEM, Normalized Events, │──→│   (Append-Only Ledger,    │  │
│  │  AST / de-obfuscation)│   │   Artifact Store)         │   │    Deterministic Hashes)  │  │
│  └───────────────────────┘   └───────────────────────────┘   └─────────────┬─────────────┘  │
└────────────────────────────────────────────────────────────────────────────┼────────────────┘
                                                                             │ SSOT Ref / Read
                                                                             ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                          New Security State & Causal Core Package                           │
│                                `backend/security_state/`                                    │
│                                                                                             │
│  ┌─────────────────────────────────┐             ┌───────────────────────────────────────┐  │
│  │ 1. Security State Engine        │────────────→│ 2. Security State Transitions         │  │
│  │    Entities, Observed/Derived   │             │    What changed? Causal trigger?      │  │
│  │    Facts, Epistemic States      │             │    Reversibility mechanism?           │  │
│  └────────────────┬────────────────┘             └───────────────────┬───────────────────┘  │
│                   │                                                  │                      │
│                   ▼                                                  ▼                      │
│  ┌─────────────────────────────────┐             ┌───────────────────────────────────────┐  │
│  │ 3. Causal Security Engine       │             │ 4. Trusted Capability Abuse Engine    │  │
│  │    Temporal vs Supported Causal │────────────→│    Capability + Identity + Context    │  │
│  │    Competing Explanations       │             │    Legitimate vs Abused vs Attack     │  │
│  └────────────────┬────────────────┘             └───────────────────┬───────────────────┘  │
│                   │                                                  │                      │
│                   ▼                                                  ▼                      │
│  ┌─────────────────────────────────┐             ┌───────────────────────────────────────┐  │
│  │ 5. Attack State Machine         │             │ 6. Enterprise Reachability Engine     │  │
│  │    18-Stage Causal Lifecycle    │────────────→│    Identity, Privilege, Network,      │  │
│  │    Evidence-Gated Progression   │             │    Data, Cloud Path Graph             │  │
│  └────────────────┬────────────────┘             └───────────────────┬───────────────────┘  │
│                   │                                                  │                      │
│                   ▼                                                  ▼                      │
│  ┌─────────────────────────────────┐             ┌───────────────────────────────────────┐  │
│  │ 7. Impact Engine                │             │ 8. Counterfactual Security Engine     │  │
│  │    Decoupled from Verdict;      │────────────→│    World A (Do Nothing) vs Worlds     │  │
│  │    Blast Radius & Criticality   │             │    B/C/D (Intervention Projections)   │  │
│  └────────────────┬────────────────┘             └───────────────────┬───────────────────┘  │
│                   │                                                  │                      │
│                   ▼                                                  ▼                      │
│  ┌─────────────────────────────────┐             ┌───────────────────────────────────────┐  │
│  │ 9. Intervention Optimizer       │             │ 10. Response Safety & Verification    │  │
│  │    Min. Effective Disruption    │────────────→│     Policy/Tenancy Multi-Gate;        │  │
│  │    Sever Attack Path Graph      │             │     Post-Action Observation Loop      │  │
│  └────────────────┬────────────────┘             └───────────────────┬───────────────────┘  │
│                   │                                                  │                      │
│                   ▼                                                  ▼                      │
│  ┌─────────────────────────────────┐             ┌───────────────────────────────────────┐  │
│  │ 11. Security State Ledger       │             │ 12. Adversarial Simulator             │  │
│  │     Auditable, Tamper-Evident,  │             │     Deterministic Attacker Next-Step  │  │
│  │     Cryptographically Chained   │             │     Simulation on Shared Models       │  │
│  └─────────────────────────────────┘             └───────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼ External Contract
                 ┌───────────────────────────────────────────┐
                 │ Response Execution Engine (`executions.db`)│
                 │ 18 Canonical Response Actions             │
                 └───────────────────────────────────────────┘
```

---

## 4. Subsystem Specifications

### 4.1 Security State Engine
- **Entity Model**: Covers 20 distinct security entities:
  `USER`, `IDENTITY`, `DEVICE`, `PROCESS`, `FILE`, `SERVICE`, `NETWORK_CONNECTION`, `ACCOUNT`, `CREDENTIAL`, `CLOUD_RESOURCE`, `SAAS_RESOURCE`, `APPLICATION`, `WORKLOAD`, `SERVER`, `ENDPOINT`, `SECURITY_CONTROL`, `DATA_STORE`, `BACKUP_SYSTEM`, `VIRTUALIZATION_HOST`, `TRUST_RELATIONSHIP`.
- **State Structure**: Each entity state maintains:
  `state_id`, `tenant_id`, `entity_ref`, `timestamp`, `previous_state_hash`, `evidence_refs`, `provenance`, `observed_facts`, `derived_facts`, `epistemic_status`, `assumptions`, `contradictions`, `missing_evidence`, `classification`, `state_hash`.

### 4.2 Security State Transition Model
- Captures state deltas:
  `transition_id`, `from_state_hash`, `to_state_hash`, `timestamp`, `trigger_evidence_ids`, `causal_link_id`, `property_mutated`, `new_capability_unlocked`, `attack_state_delta`, `potential_impact_unlocked`, `recommended_reversal_action`.

### 4.3 Causal Security Engine
- Classifies relations into 7 explicit levels:
  `TEMPORAL_CORRELATION`, `STATISTICAL_CORRELATION`, `SUPPORTED_CAUSALITY`, `STRONG_CAUSAL_EVIDENCE`, `INFERRED_CAUSALITY`, `POSSIBLE_CAUSALITY`, `CONTRADICTED_CAUSALITY`.
- Every edge stores: `cause_node`, `effect_node`, `evidence_refs`, `provenance`, `temporal_delta_ms`, `causal_mechanism`, `competing_hypotheses`, `falsification_conditions`.

### 4.4 Trusted Capability Abuse Engine
- Models dual-use administrative and management tools (RMM, WMI, PowerShell, PsExec, cloud CLIs, hypervisor APIs, backup utilities).
- Evaluates:
  `Capability + Identity + Authorization + Source + Destination + TimeWindow + BusinessContext + BehaviorPattern + Sequence + Privilege + Reachability → CapabilityStatus`.
- Produces 7 capability verdicts:
  `LEGITIMATE_CAPABILITY`, `AUTHORIZED_USE`, `ANOMALOUS_USE`, `SUSPICIOUS_USE`, `ABUSED_CAPABILITY`, `ATTACK_CAPABLE`, `CONFIRMED_ATTACK`.

### 4.5 Attack State Machine
- 18 explicit, evidence-gated states:
  `NO_ATTACK_EVIDENCE` &rarr; `RECONNAISSANCE` &rarr; `INITIAL_ACCESS` &rarr; `EXECUTION` &rarr; `PERSISTENCE` &rarr; `PRIVILEGE_ESCALATION` &rarr; `DEFENSE_EVASION` &rarr; `CREDENTIAL_ACCESS` &rarr; `DISCOVERY` &rarr; `LATERAL_MOVEMENT` &rarr; `COMMAND_AND_CONTROL` &rarr; `COLLECTION` &rarr; `EXFILTRATION` &rarr; `IMPACT` &rarr; `CONTAINED` &rarr; `ERADICATED` &rarr; `RECOVERING` &rarr; `VERIFIED_SAFE`.
- Progression is strictly constrained by causal state transitions, not technique keyword presence.

### 4.6 Enterprise Reachability Engine
- Models multidimensional reachability:
  `IDENTITY_REACHABILITY`, `CREDENTIAL_REACHABILITY`, `PRIVILEGE_REACHABILITY`, `NETWORK_REACHABILITY`, `APPLICATION_REACHABILITY`, `DATA_REACHABILITY`, `CONTROL_PLANE_REACHABILITY`, `ADMINISTRATIVE_REACHABILITY`.
- Labels each path: `CURRENTLY_REACHABLE`, `POTENTIALLY_REACHABLE`, `CONDITIONALLY_REACHABLE`, `BLOCKED`, `UNKNOWN`.

### 4.7 Counterfactual Security Engine
- Projects parallel futures for a given state:
  - **World A**: Do Nothing (Attacker baseline progression).
  - **World B, C, D**: Specific intervention options.
- For each world, calculates:
  `continuation_probability`, `reachable_asset_delta`, `expected_next_transitions`, `projected_impact_score`, `residual_attack_paths`, `business_disruption_cost`, `reversibility_index`, `evidence_preservation_score`.

### 4.8 Impact Engine
- Strictly decoupled from Verdict:
  - Evaluates `asset_criticality`, `identity_privilege_tier`, `data_classification`, `business_service_tier`, `blast_radius_nodes`, `ransomware_susceptibility`, `data_destruction_potential`, `backup_exposure_tier`, `recovery_complexity`.
  - Computes `BlastRadiusSummary` and `ImpactScoreCard`.

### 4.9 Intervention Optimizer
- Solves a graph cut / path-blocking optimization problem:
  Finds the subset of available response actions that minimizes `residual_attack_risk` and maximizes `attack_path_interruption` subject to `business_disruption_limit` and `reversibility_constraints`.
- Outputs a ranked, deterministic `InterventionPlan`.

### 4.10 Response Safety & Verification Engine
- **Safety Gate**: Verifies `TenantScope`, `RequiredPermissions`, `ConfidenceThreshold`, `ReversibilityPolicy`, `CriticalServiceProtection`, `EvidencePreservationHold`.
- **Verification Loop**: Following execution, orchestrates post-action telemetry observation:
  Checks: Did target process die? Did session terminate? Did credential rotation invalidate tokens? Did network rule block traffic? Did attacker pivot to secondary persistence?
  Transitions execution state from `EXECUTED` &rarr; `VERIFIED_EFFECTIVE` or `VERIFIED_FAILED`.

### 4.11 Security State Ledger
- Cryptographically chained audit ledger (SHA-256):
  `Entry(index, timestamp, tenant_id, entity_id, previous_hash, transition_ref, causal_ref, verdict_ref, impact_ref, intervention_ref, verification_ref, signature)`.

### 4.12 Adversarial Simulator
- Simulates attacker progression using the production capability and reachability models.
- Provides threat hunting and "what-if" containment simulation without divergent or synthetic rules.
