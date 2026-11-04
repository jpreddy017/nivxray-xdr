# NivXRay Security State: Master Implementation Plan

> **Document Type:** Phase 0 Implementation Plan  
> **Status:** Approved for Execution  
> **Guiding Principle:** Deterministic First · Build Core First · Integrate Second · Visualize Third  

---

## 1. Phase Breakdown & Execution Sequence

```
PHASE 0: Architecture Reconciliation (COMPLETED)
   ↓
PHASE 1: Security State Core (Models, State Engine, Transitions, Epistemic States, APIs)
   ↓
PHASE 2: Causal Security Engine (Causality vs Correlation, Competing Explanations)
   ↓
PHASE 3: Trusted Capability Abuse Engine (RMM, Dual-Use, Contextual Verification)
   ↓
PHASE 4: Attack State Machine (18-Stage Causal Lifecycle, State Transitions)
   ↓
PHASE 5: Enterprise Reachability Engine (Identity, Credential, Network, Data Paths)
   ↓
PHASE 6: Counterfactual Security Engine (World A: Do Nothing vs Worlds B/C/D)
   ↓
PHASE 7: Impact Engine (Decoupled from Verdict, Blast Radius, Criticality)
   ↓
PHASE 8: Intervention Optimizer (Minimal Effective Disruption Graph Cut)
   ↓
PHASE 9: Response Safety & Verification (Safety Gates, Re-observation Loop)
   ↓
PHASE 10: Security State Ledger (Tamper-evident, Cryptographic Chaining)
   ↓
PHASE 11: Adversarial Simulator (Shared Model Next-Step Simulation)
   ↓
PHASE 12: Evidence Graph & Analyst UI Integration (Visualizing Transitions)
   ↓
PHASE 13: Deterministic Validation, Replay & Benchmarks (18-Category Golden Corpus)
   ↓
PHASE 14: NivXRay Platform Integration (Feature Flag Promotion & Wire Tests)
```

---

## 2. Detailed Phase Specifications

### Phase 1: Security State Core
- **Directory**: `backend/security_state/model/`, `backend/security_state/state_engine/`, `backend/security_state/transitions/`
- **Deliverables**:
  - `contracts.py`: Epistemic status enums (`OBSERVED`, `SUPPORTED`, `DERIVED`, `LIKELY`, `POSSIBLE`, `UNSUPPORTED`, `CONTRADICTED`, `DISPROVEN`), entity references, and base dataclasses.
  - `security_state.py`: Complete `SecurityState` model for 20 entity types.
  - `state_engine.py`: Deterministic evaluator constructing state from canonical evidence.
  - `transitions.py`: `SecurityStateTransition` computing exact deltas, causal references, property changes, and reversibility mechanisms.
  - `test_security_state_core.py`: Unit tests validating determinism, epistemic tagging, and state hashing.

### Phase 2: Causal Security Engine
- **Directory**: `backend/security_state/causal/`
- **Deliverables**:
  - `engine.py`: Distinguishes 7 levels of causality from correlation.
  - `models.py`: `CausalEdge`, `CausalGraph`, `CausalMechanism`, `CompetingHypothesis`.
  - `rules.py`: Deterministic causal knowledge base (e.g. process spawn &rarr; network beacon &rarr; payload drop).
  - `test_causal_engine.py`: Falsification and competing explanation validation.

### Phase 3: Trusted Capability Abuse Engine
- **Directory**: `backend/security_state/capability/`
- **Deliverables**:
  - `engine.py`: Contextual capability evaluator across 11 dimensions (identity, auth, source, dest, time, business context, sequence, privilege, reachability).
  - `vocabulary.py`: Canonical capability registry (RMM, WMI, PowerShell, PsExec, cloud APIs, hypervisor tools).
  - `test_capability_abuse.py`: Benign vs abused RMM/admin verification tests.

### Phase 4: Attack State Machine
- **Directory**: `backend/security_state/attack_state/`
- **Deliverables**:
  - `machine.py`: 18-stage explicit state machine.
  - `transitions.py`: Causal transition logic enforcing that kill-chain states require causal proof.
  - `test_attack_state_machine.py`: Multi-stage attack progression tests.

### Phase 5: Enterprise Reachability Engine
- **Directory**: `backend/security_state/reachability/`
- **Deliverables**:
  - `engine.py`: Multidimensional graph reachability (Identity, Credential, Network, Cloud, Data).
  - `models.py`: `ReachabilityGraph`, `ReachabilityPath`, `ReachabilityStatus`.
  - `test_reachability_engine.py`: Lateral movement and privilege escalation path calculations.

### Phase 6: Counterfactual Security Engine
- **Directory**: `backend/security_state/counterfactual/`
- **Deliverables**:
  - `engine.py`: Parallel world projection (World A vs B/C/D).
  - `models.py`: `CounterfactualProjection`, `ResidualAttackPath`, `DisruptionCost`.
  - `test_counterfactual_engine.py`: Account disable / host isolation path interruption tests.

### Phase 7: Impact Engine
- **Directory**: `backend/security_state/impact/`
- **Deliverables**:
  - `engine.py`: Blast radius and enterprise exposure evaluator.
  - `models.py`: `BlastRadiusReport`, `RansomwareExposureIndex`, `ServiceCriticalityScore`.
  - `test_impact_engine.py`: Decoupling validation proving verdict remains unchanged despite varying impact.

### Phase 8: Intervention Optimizer
- **Directory**: `backend/security_state/intervention/`
- **Deliverables**:
  - `optimizer.py`: Minimal effective intervention graph-cut algorithm.
  - `models.py`: `InterventionPlan`, `ActionRecommendation`, `DisruptionEstimate`.
  - `test_intervention_optimizer.py`: Optimization benchmark tests.

### Phase 9: Response Safety & Verification Engine
- **Directory**: `backend/security_state/response_safety/`
- **Deliverables**:
  - `safety_gate.py`: Multi-gate policy validation (scopes, reversibility, evidence hold).
  - `verification.py`: Post-response telemetry observation and efficacy verification.
  - `test_response_safety_and_verification.py`: Verification success/failure scenario tests.

### Phase 10: Security State Ledger
- **Directory**: `backend/security_state/ledger/`
- **Deliverables**:
  - `ledger.py`: Cryptographically chained, append-only ledger.
  - `store.py`: Persistence and deterministic replay store.
  - `test_security_state_ledger.py`: Tamper-evidence and replay verification tests.

### Phase 11: Adversarial Simulator
- **Directory**: `backend/security_state/simulation/`
- **Deliverables**:
  - `simulator.py`: Attacker next-step simulation on production state models.
  - `test_adversarial_simulator.py`: Kill-chain simulation tests.

### Phase 12: API Routers & Contracts
- **Directory**: `backend/security_state/routers/`
- **Deliverables**:
  - FastAPI routers under `/api/v2/security-state/` for evaluate, transitions, causality, capabilities, reachability, counterfactual, interventions, verify, and ledger.
  - Gated by `NIVX_FLAG_SECURITY_STATE`.

### Phase 13: Golden Validation Corpus & Replay Suite
- **Directory**: `backend/security_state/validation/`
- **Deliverables**:
  - 18 validation scenarios covering benign admin, abused RMM, credential abuse, cloud identity, lateral movement, backup targeting, and response verification.
  - Benchmark profiler capturing p50, p95, p99 latencies and throughput.
