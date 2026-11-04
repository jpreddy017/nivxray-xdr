# NivXRay Security State: Engine Boundaries & Lifecycle Model

> **Document Type:** Phase 0 Engine Boundaries Specification  
> **Status:** Authoritative  
> **Core Principle:** ENGINE &ne; CAPABILITY &ne; EXECUTION PATH  

---

## 1. Engine Lifecycle Model

Every engine in `backend/security_state/` adheres to a strict formal lifecycle:

```
DISCOVERED
   ↓
REGISTERED
   ↓
CAPABILITY_DECLARED
   ↓
BOUND
   ↓
EXECUTION_TESTED
   ↓
EXECUTION_READY
   ↓
ENABLED (via Feature Flag)
```

No engine is considered active merely because its code exists or is imported. It must pass self-test and contract validation gates before binding to the execution pipeline.

---

## 2. Formal Engine Boundary Contracts

### 2.1 Security State Engine (`SecurityStateEngine`)
- **Responsibility**: Maintain and evaluate the current security state of enterprise entities.
- **Inputs**:
  - `tenant_id: str`
  - `entity_ref: EntityRef` (type, identifier)
  - `evidence_stream: list[CanonicalEvidence]` (from SSOT / CEM)
  - `previous_state: Optional[SecurityState]`
- **Outputs**:
  - `SecurityState`: Epistemic status, observed facts, derived facts, confidence, state hash, contradictions, missing evidence.
- **Guarantees**:
  - Pure function given `(previous_state, evidence_stream)`.
  - Zero I/O, zero global mutable state.
  - Epistemic states (`OBSERVED`, `SUPPORTED`, `DERIVED`, `LIKELY`, `POSSIBLE`, `UNSUPPORTED`, `CONTRADICTED`, `DISPROVEN`).

### 2.2 Security State Transition Engine (`StateTransitionEngine`)
- **Responsibility**: Compute delta between security states and capture the causal mechanism.
- **Inputs**:
  - `state_before: SecurityState`
  - `state_after: SecurityState`
  - `triggering_evidence: list[EvidenceRef]`
- **Outputs**:
  - `SecurityStateTransition`: What changed, when, evidence basis, causal basis, capability unlocked, attack state delta, potential impact delta, reversal action.
- **Guarantees**:
  - Transition hashes are cryptographically chained (`prev_state_hash` &rarr; `curr_state_hash`).

### 2.3 Causal Security Engine (`CausalSecurityEngine`)
- **Responsibility**: Distinguish temporal/statistical correlation from evidence-backed causality.
- **Inputs**:
  - `events: list[CanonicalEvent]`
  - `transitions: list[SecurityStateTransition]`
  - `domain_rules: CausalKnowledgeBase`
- **Outputs**:
  - `CausalGraph`: Directed acyclic graph of `CausalEdge` entries with causal basis, temporal delta, confidence, assumptions, and competing explanations.
- **Guarantees**:
  - Differentiates 7 causal levels (Temporal correlation &ne; Supported causality).
  - Explicit tracking of competing hypotheses and falsification criteria.

### 2.4 Trusted Capability Abuse Engine (`TrustedCapabilityAbuseEngine`)
- **Responsibility**: Evaluate legitimate enterprise capabilities (RMM, WMI, PowerShell, cloud APIs, etc.) for malicious abuse.
- **Inputs**:
  - `capability_id: str`
  - `identity_context: IdentityContext` (roles, normal working hours, normal source/destination)
  - `execution_context: ExecutionContext` (command line, parent process, network connection)
  - `behavioral_sequence: list[StateTransition]`
- **Outputs**:
  - `CapabilityAbuseEvaluation`:
    `LEGITIMATE_CAPABILITY`, `AUTHORIZED_USE`, `ANOMALOUS_USE`, `SUSPICIOUS_USE`, `ABUSED_CAPABILITY`, `ATTACK_CAPABLE`, `CONFIRMED_ATTACK`.
- **Guarantees**:
  - Never flags dual-use administrative software simply because it is present.
  - Requires context deviation (identity, source, time, sequence, privilege) to flag abuse.

### 2.5 Attack State Machine (`AttackStateMachine`)
- **Responsibility**: Track the macro attack lifecycle across 18 explicit states.
- **Inputs**:
  - `current_attack_state: AttackState`
  - `transitions: list[SecurityStateTransition]`
  - `capability_evaluations: list[CapabilityAbuseEvaluation]`
  - `causal_graph: CausalGraph`
- **Outputs**:
  - `AttackStateEvaluation`: New attack state, transition rationale, evidence justification, required containment steps.
- **Guarantees**:
  - Progression is monotonic unless an explicit reversal/remediation event is verified.
  - MITRE techniques serve as supporting context, not authoritative state triggers.

### 2.6 Enterprise Reachability Engine (`EnterpriseReachabilityEngine`)
- **Responsibility**: Compute attacker reachability graph across identities, credentials, privileges, networks, and data stores.
- **Inputs**:
  - `compromised_entities: list[EntityRef]`
  - `enterprise_topology: EnterpriseTopologyGraph`
  - `credentials_harvested: list[CredentialRef]`
  - `active_capabilities: list[CapabilityAbuseEvaluation]`
- **Outputs**:
  - `ReachabilityMatrix`:
    Categorizes every target asset as `CURRENTLY_REACHABLE`, `POTENTIALLY_REACHABLE`, `CONDITIONALLY_REACHABLE`, `BLOCKED`, or `UNKNOWN`.
- **Guarantees**:
  - No reachability claim without verifiable topological path or valid credential path.

### 2.7 Counterfactual Security Engine (`CounterfactualEngine`)
- **Responsibility**: Project parallel outcomes for "Do Nothing" vs candidate intervention actions.
- **Inputs**:
  - `current_state: SecurityState`
  - `reachability: ReachabilityMatrix`
  - `attack_state: AttackState`
  - `candidate_interventions: list[ResponseAction]`
- **Outputs**:
  - `CounterfactualProjections`:
    World A (Baseline / Do Nothing) vs World B/C/D (Intervention variants) detailing attack continuation probability, residual paths, projected damage, and business disruption.
- **Guarantees**:
  - Fully deterministic projection based on graph path cuts.

### 2.8 Impact Engine (`ImpactEngine`)
- **Responsibility**: Calculate enterprise exposure, blast radius, and business impact independently of the verdict.
- **Inputs**:
  - `reachability: ReachabilityMatrix`
  - `affected_entities: list[EntityRef]`
  - `asset_catalog: AssetMetadataCatalog`
- **Outputs**:
  - `ImpactScoreCard`:
    Blast radius node count, tier-1 service exposure, ransomware exposure index, backup survivability risk, data exfiltration exposure.
- **Guarantees**:
  - Does NOT alter Verdict Engine v3 scores or labels. Strictly informational / operational.

### 2.9 Intervention Optimizer (`InterventionOptimizer`)
- **Responsibility**: Recommend the minimal effective response plan to sever attack reachability.
- **Inputs**:
  - `counterfactual_projections: CounterfactualProjections`
  - `available_actions: list[ResponseActionRegistryEntry]`
  - `safety_policy: SafetyPolicy`
- **Outputs**:
  - `InterventionPlan`:
    Ranked action sequence, targeted entities, expected attack graph cut, estimated business impact, reversibility score.
- **Guarantees**:
  - Recommendation only. Never executes actions autonomously without passing the Response Safety Gate.

### 2.10 Response Safety & Verification Engine (`ResponseSafetyEngine`)
- **Responsibility**: Enforce authorization/safety gates prior to action and orchestrate post-action verification.
- **Inputs**:
  - Pre-Action: `InterventionPlan`, `tenant_id`, `actor_token`, `safety_policy`.
  - Post-Action: `execution_id`, `action_result`, `fresh_telemetry_stream`.
- **Outputs**:
  - Pre-Action: `SafetyGateDecision` (`APPROVED`, `REJECTED`, `REQUIRES_HUMAN_CONFIRMATION`).
  - Post-Action: `VerificationReport` (`VERIFIED_EFFECTIVE`, `VERIFIED_INEFFECTIVE`, `ATTACKER_PIVOT_DETECTED`).
- **Guarantees**:
  - Never accepts "HTTP 200" as proof of containment. Requires fresh evidence that target capability is nullified.

### 2.11 Security State Ledger (`SecurityStateLedger`)
- **Responsibility**: Record all transitions, verdicts, impact evaluations, responses, and verification results in an immutable cryptographic audit log.
- **Inputs**:
  - `LedgerRecord`: Timestamp, tenant_id, actor, previous_hash, payload, signature.
- **Outputs**:
  - `LedgerEntry`: Cryptographically hashed block (SHA-256) with tamper-evident chain.
- **Guarantees**:
  - Append-only, verifiable historical replay, zero mutation of prior records.

### 2.12 Adversarial Simulator (`AdversarialSimulator`)
- **Responsibility**: Simulate attacker decision trees on the live security state model.
- **Inputs**:
  - `initial_state: SecurityState`
  - `attacker_objective: AttackerObjective`
  - `step_limit: int`
- **Outputs**:
  - `SimulationTrajectory`:
    Sequence of simulated transitions, capability invocations, and reachability expansions.
- **Guarantees**:
  - Uses the identical logic, state models, and reachability constraints as the production reasoning engines.
