# NivXRay Architecture Delta: Current State vs Security State Substrate

> **Document Type:** Phase 0 Architecture Delta & Gap Reconciliation  
> **Status:** Authoritative  
> **Reference Baseline:** Truth Commit `d3f7a0a000892131abc9a32ee97009338dd38d79`  

---

## 1. System Comparison Matrix

| Architectural Domain | Current NivXRay Implementation (v2 / RC5 / Base) | New Security State & Causal Substrate (`backend/security_state/`) | Architectural Relationship |
| :--- | :--- | :--- | :--- |
| **Central Primitive** | `Evidence`, `Artifact`, `Commandline`, `NormalizedEvent` | `SecurityState` & `SecurityStateTransition` | **EXTENSION**: Security state sits above evidence and tracks continuous entity state evolution. |
| **Evidence Foundation** | `backend/canonical/ssot/` (`AuthoritativeSSOT`, `EvidenceGraph`, `Provenance`) | Consumes `AuthoritativeSSOT` and canonical evidence without modification | **REUSE**: SSOT remains the single authoritative source of raw/derived evidence. |
| **Telemetry Ingestion & Normalization** | `backend/v2/ingestion/`, `backend/v2/cem/` | Consumes CEM events as state mutation inputs | **REUSE**: Ingestion and parsing remain entirely untouched. |
| **Decoding & De-obfuscation** | 26 plugins in `backend/decoders/`, recursive orchestrator in `backend/engine/` | Consumes decoded outputs from artifact store | **REUSE**: Decoding engine is authoritative and preserved. |
| **Verdict Scoring** | `backend/v2/verdict/` (v3/v3.1b canonical verdict with 5 analyst labels, monotonic Noisy-OR) | Deterministic Verdict Engine is preserved; Verdict is decoupled from Impact | **PRESERVED**: Verdict establishes *what happened*; Impact evaluates *what is exposed*. |
| **Causal Modeling** | Temporal sequencing in timeline / events (`backend/l2_investigation/services/attack_story.py`) | Formal causal inference engine (`CausalSecurityEngine`) distinguishing correlation from causal mechanisms | **NEW**: Formal mathematical causal graph with competing hypotheses and falsification. |
| **Capability Modeling** | Hardcoded LOLBAS and family signatures (`backend/lolbas.py`, `backend/decoders/families/`) | Generalized `TrustedCapabilityAbuseEngine` across 11 contextual dimensions | **NEW**: Covers RMM, remote admin, PowerShell, WMI, cloud APIs, hypervisor tools generically. |
| **Attack Progression** | MITRE technique tagging (`backend/mitre_catalogue/`, `backend/v2/routers/mitre_coverage.py`) | 18-stage explicit `AttackStateMachine` driven by causal state transitions | **NEW**: State machine driven by evidence-backed capability transitions, not technique keywords. |
| **Reachability Analysis** | None (Static topology / device trajectory) | Multidimensional `EnterpriseReachabilityEngine` (Identity, Credential, Network, Cloud, Backup) | **NEW**: Calculates currently, potentially, and conditionally reachable assets. |
| **Counterfactual Futures** | None | `CounterfactualEngine` projecting World A (Do Nothing) vs Worlds B/C/D (Interventions) | **NEW**: Deterministic projection of residual attack paths and business impact. |
| **Impact Evaluation** | Implicit in verdict band (Low &rarr; Critical) | Explicit `ImpactEngine` evaluating blast radius, service criticality, ransomware risk, backup safety | **NEW**: Separate impact scoring card that never distorts evidence verdicts. |
| **Response Recommendation** | Manual playbooks / predefined rules | Deterministic `InterventionOptimizer` calculating minimal effective disruption | **NEW**: Optimal graph cut to sever attack reachability. |
| **Response Execution** | `apps/nivxray-xdr-response/` (18 canonical actions, SQLite, approvals) | Integrated via clean contract: optimizer feeds response plane; results re-observed | **REUSE & WRAP**: Response engine executes; new layer validates and verifies. |
| **Response Verification** | Basic status checks (API return code) | Closed-loop `ResponseVerificationEngine` (Re-observation: Did attacker capability vanish?) | **NEW**: Enforces `RESPONSE → OBSERVE → NEW EVIDENCE → NEW STATE → VERIFY`. |
| **Audit & Lineage** | SSOT execution trace and reasoning steps | Cryptographic, tamper-evident `SecurityStateLedger` with state chaining | **NEW**: Complete state lifecycle audit trail. |
| **Simulation** | None | `AdversarialSimulator` using shared production state, capability, and reachability models | **NEW**: Foundation for "what happens next" and pre-response dry-runs. |

---

## 2. What Must NOT Be Rebuilt (Strict Re-Use Invariants)

Under no circumstances should any of the following components be duplicated, modified incompatibly, or rewritten:

1. **`backend/canonical/ssot/`**:
   - `AuthoritativeSSOT`, `Provenance`, `EvidenceGraph`, `GraphNode`, `GraphEdge`, `ReasoningStep`.
   - The security state core will read from SSOT and reference SSOT nodes via `ssot_ref` and `evidence_ids`.
2. **`backend/v2/verdict/`**:
   - `canonical.py`, `engine.py`, `signals.py`, `weights.py`.
   - The 5-label vocabulary (`Undetermined`, `Informational`, `Runtime Dependent`, `Suspicious`, `Malicious`), monotonic Noisy-OR aggregation, and `Suspicious-as-floor` policy must remain the definitive verdict scoring authority.
3. **`backend/decoders/` & `backend/engine/`**:
   - All 26 de-obfuscation plugins, recursive orchestrator, fingerprinting utilities, and format exporters.
4. **`backend/v2/trajectory/`**:
   - Device Trajectory graph algorithms.
5. **`backend/l2_investigation/services/attack_story.py`**:
   - Attack Story generator and chapter narrative.
6. **`apps/nivxray-xdr-response/`**:
   - Response execution service, 18 canonical actions, SQLite database, and approval state machine.
7. **`backend/v2/flags.py`**:
   - Tri-state feature flag mechanism (`DISABLED`, `SHADOW`, `ENABLED`).

---

## 3. What Genuinely Needs to Be Built

The new technology constitutes a new modular package located at:
```
backend/security_state/
    __init__.py
    contracts/          # Schema contracts & epistemic types
    model/              # Security state entity and property schemas
    state_engine/       # Security state computing & evaluation engine
    transitions/        # Security state transition engine
    causal/             # Causal inference and evidence correlation engine
    capability/         # Trusted capability abuse engine
    attack_state/       # 18-stage causal attack state machine
    reachability/       # Enterprise multidimensional reachability engine
    counterfactual/     # Counterfactual futures engine (World A vs B/C/D)
    impact/             # Decoupled impact and blast radius engine
    intervention/       # Deterministic intervention optimizer
    response_safety/    # Multi-gate response safety & verification engine
    ledger/             # Cryptographic security state ledger
    simulation/         # Adversarial simulator
    adapters/           # Adapters to existing SSOT, CEM, and Verdict engines
    routers/            # FastAPI endpoints under /api/v2/security-state/
```

---

## 4. Architectural Guarantees

1. **Zero Impact on Current Production**:
   All new routers, engines, and evaluators are strictly gated behind `NIVX_FLAG_SECURITY_STATE`. When the flag is `disabled`, zero CPU cycles or memory overhead are consumed.
2. **Byte-Identical Replay**:
   Every computation is deterministic: no non-deterministic RNG, no wall-clock time in hashing, sorted keys in JSON serialization, and reproducible state hashes.
3. **Strict Multi-Tenant Isolation**:
   Every state, transition, causal edge, reachability path, intervention plan, and ledger block is tenant-scoped with cryptographically enforced boundaries.
