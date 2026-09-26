# NivXRay Security State — Phase 8 Component Boundaries & Contract Interfaces

> **Document Type:** Component Boundary & Interface Specification  
> **Status:** Authoritative  
> **Target Subsystem:** `backend/security_state/`  
> **Target Release:** Phase 8  

---

## 1. Boundary Architecture Overview

The Phase 8 architecture enforces strict component decoupling, explicit input/output contracts, and immutable boundary rules across the entire intelligence pipeline:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. AUTHORITATIVE PIPELINE BOUNDARY                                          │
│    • Authoritative Verdict Engine v3 (Case Malicious / Suspicious / Benign) │
│    • Authoritative Attack Story Builder (Timeline of Record)               │
│    • Authoritative Single Source of Truth (SSOT / CEM)                      │
│    • Authoritative Investigation Knowledge Graph (IKG)                      │
│    >>> GUARANTEE: READ-ONLY & IMMUTABLE. ZERO SHADOW MUTATION.             │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ Read-Only Stream (Canonical Events & IKG Edges)
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 2. SECURITY STATE & REACHABILITY BOUNDARY (`reachability/engine.py`)        │
│    • Inputs: Footholds, Active Capabilities, IKG Topology, Asset Valuation  │
│    • Traversal: Multidimensional, capability-aware, protocol-constrained    │
│    • Outputs: Immutable `ReachabilityMatrix`, `ReachabilityPath`             │
│    >>> GUARANTEE: ZERO DUPLICATE GRAPH TABLES. DETERMINISTIC HASHEST.       │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ Pure Function Contract (`ReachabilityMatrix`)
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 3. COUNTERFACTUAL SIMULATION BOUNDARY (`counterfactual/engine.py`)          │
│    • Inputs: `ReachabilityMatrix`, `SecurityState`, Intervention Actions    │
│    • Simulation: Parallel immutable forks (Worlds A, B, C, D, E)            │
│    • Provenance: P8-13 lineage (`CounterfactualSimulationProvenance`)       │
│    >>> GUARANTEE: PROJECTED != OBSERVED. STRICT EPISTEMIC SEPARATION.       │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ Pure Function Contract (`CounterfactualAnalysis`)
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 4. IMPACT & COMPARATIVE MATRIX BOUNDARY (`impact/engine.py`, `matrix`)      │
│    • Inputs: World Projections, Asset Valuation Catalog                     │
│    • Scoring: Attack Interruption %, Tier-0/1 Protected, Business Disruption│
│    • Outputs: Cryptographically signed `ComparativeInterventionMatrix`      │
│    >>> GUARANTEE: ZERO ARBITRARY BUSINESS VALUATION. DERIVED MATH ONLY.    │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ Scored Matrix Contract
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 5. INTERVENTION OPTIMIZER & SAFETY BOUNDARY (`intervention/optimizer.py`)   │
│    • Optimization: Pareto multi-objective solver                            │
│    • Safety Gate: Tenant scope, critical asset locks, dual approval gates   │
│    • Outputs: Staged `InterventionPlan` in Cockpit UI format                │
│    >>> GUARANTEE: AUTO_RESPONSE = FALSE. EXECUTION HARD-LOCKED.             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Authoritative Pipeline Boundary & Immutability Contract

### 2.1 The Invariance Rule
The Authoritative Pipeline constitutes the legal and compliance System of Record. Under no circumstances may Phase 8 engines alter, modify, hook, or mutate authoritative records.

| Authoritative Component | Allowed Access in Phase 8 | Prohibited Operations |
| :--- | :--- | :--- |
| **Verdict Engine v3** | None (Isolated) | Mutating verdict scores, altering case classification |
| **Attack Story Builder** | None (Isolated) | Appending unobserved speculative events to the story |
| **Authoritative SSOT** | Read-Only | Writing simulation states, altering evidence hashes |
| **Authoritative IKG** | Read-Only Graph Query | Adding synthetic nodes, deleting edges, shadow tables |

### 2.2 Formal Enforcement
- Regression test `P8-11` continuously validates that processing a case through the reachability and counterfactual engines leaves the Case Verdict, Attack Story, and IKG byte-for-byte identical.
- Data access uses read-only database connections and immutable dataclass views.

---

## 3. Authoritative IKG Boundary & Graph Non-Duplication Contract

### 3.1 Zero Graph Duplication
Phase 8 does **not** create a second Graph of Record.
- **Prohibited**: Creating secondary graph database schemas (e.g. `reachability_nodes`, `reachability_edges`).
- **Prohibited**: Mirroring the authoritative IKG into an external graph database (e.g. Neo4j or Amazon Neptune).
- **Mandated**: Direct read traversal of existing IKG entities (`device`, `server`, `account`, `cloud_resource`, `backup_system`, `data_store`).

### 3.2 Ephemeral Graph Traversal Interface
```python
class EnterpriseReachabilityEngine:
    def analyze_reachability(
        self,
        tenant_id: str,
        case_id: str,
        foothold_entities: List[EntityRef],
        active_capabilities: List[str],
        ikg_graph: InvestigationKnowledgeGraph,  # Read-Only Reference
        asset_valuations: Optional[Dict[str, AssetValuation]] = None,
    ) -> ReachabilityMatrix:
        """Pure function: queries IKG read-only; returns immutable ReachabilityMatrix."""
```

---

## 4. Enterprise Reachability Engine (`reachability/engine.py` v1.1.0)

### 4.1 Interface Contract
- **Inputs**:
  - `tenant_id: str`
  - `case_id: str`
  - `foothold_entities: List[EntityRef]` (verified compromised assets)
  - `active_capabilities: List[str]` (e.g., `CAP_DCSYNC`, `CAP_CLOUD_METADATA_ACCESS`)
  - `ikg_graph: InvestigationKnowledgeGraph` (read-only)
  - `asset_valuations: Dict[str, AssetValuation]` (optional catalog)
- **Outputs**:
  - `ReachabilityMatrix`: Immutable snapshot containing paths, hops, capability prereqs, and summary counts.
- **Guarantees**:
  - Pure function given inputs; zero side effects.
  - Generates deterministic `matrix_id` and SHA-256 fingerprint.
  - Multi-hop traversal strictly constrained by capability activation (P8-02).

---

## 5. Counterfactual Security Engine (`counterfactual/engine.py` v1.1.0)

### 5.1 Interface Contract
- **Inputs**:
  - `current_state: SecurityState`
  - `reachability: ReachabilityMatrix`
  - `attack_state: AttackState`
  - `candidate_interventions: Optional[List[InterventionType]]`
- **Outputs**:
  - `CounterfactualAnalysis`: Contains World A (Baseline) and Worlds B, C, D, E projections.
- **Guarantees**:
  - Parallel state forks: Computing World B does not mutate World A or the observed state.
  - Epistemic status of all world projections is strictly `EpistemicStatus.PROJECTED`.
  - Embeds `CounterfactualSimulationProvenance` satisfying P8-13 for every world.

---

## 6. Impact & Comparative Matrix Boundary (`impact/engine.py` v1.1.0)

### 6.1 Interface Contract
- **Inputs**:
  - `world_projections: List[WorldProjection]`
  - `reachability_matrix: ReachabilityMatrix`
  - `asset_valuations: Dict[str, AssetValuation]`
- **Outputs**:
  - `ComparativeInterventionMatrix`: Deterministic trade-off scorecard across Worlds A–E.
  - `ImpactScoreCard`: Crown-jewel exposure, ransomware susceptibility index, regulatory impact scope.
- **Guarantees**:
  - Decoupled from Verdict: Security impact is calculated independently of detection confidence.
  - Mathematical derivation: Scores derived strictly from severed paths, asset disruption weights, and surviving capabilities.

---

## 7. Intervention Optimizer & Safety Boundary (`intervention/optimizer.py` v1.1.0)

### 7.1 Interface Contract
- **Inputs**:
  - `comparative_matrix: ComparativeInterventionMatrix`
  - `safety_policy: SafetyPolicy`
  - `tenant_id: str`
- **Outputs**:
  - `InterventionPlan`: Ranked, minimal effective response actions.
- **Guarantees**:
  - Recommendation only: Plans are marked `is_locked = True`, `execution_status = "STAGED_FOR_HUMAN_APPROVAL"`.
  - Tier-0 Protection Lock: Any plan touching Tier-0 assets automatically sets `requires_dual_approval = True`.
  - Zero live network transmission: No execution commands dispatched to EDR, firewalls, or identity providers.

---

## 8. Tenant Isolation & Security Boundary

### 8.1 Multi-Tenant Invariants
- **Scope Enforcement**: Every entity ID is qualified with its `tenant_id`.
- **Query Scoping**: Reachability traversal algorithms are strictly bounded to the requesting tenant's partition. Cross-tenant traversal is physically impossible.
- **Intervention Isolation**: Any response recommendation targeting an entity with a mismatched `tenant_id` is immediately rejected by the `ResponseSafetyGate`.

---

## 9. Cryptographic Ledger & Deterministic Fingerprint Boundary

### 9.1 Reproducibility Invariant
Given identical canonical evidence, identical IKG topology, and identical model version:
$$\text{SHA-256}(\text{Run}_1) \equiv \text{SHA-256}(\text{Run}_2)$$

### 9.2 Chained Fields
- `matrix_hash`: Digest of `ReachabilityMatrix` payload.
- `analysis_hash`: Digest of `CounterfactualAnalysis` payload.
- `card_hash`: Digest of `ImpactScoreCard` payload.
- `plan_hash`: Digest of `InterventionPlan` payload.

---

## 10. Phase 8 vs. Phase 9 Boundary (Closed-Loop Response Safety)

The Phase 8 and Phase 9 operational boundaries are explicitly delineated to avoid scope creep:

| Capability | Phase 8 Scope (CLOSED) | Phase 9 Scope (ON HOLD) |
| :--- | :--- | :--- |
| **Reachability Analysis** | Multi-hop capability-aware traversal | Re-evaluated dynamically post-action |
| **Asset Valuation** | Decoupled business & compliance catalog | Real-time SLA impact tracking |
| **Counterfactual Projections** | Deterministic Worlds A–E simulation | Live replay vs counterfactual ground truth |
| **Comparative Matrix** | Pareto-optimal scoring & recommendation | Automated multi-criteria policy weighting |
| **Response Actions** | Staged & simulated; execution locked | **Closed-Loop Verification Loop** |
| **Post-Action Telemetry** | Not observed (simulation only) | **Mandatory re-observation & pivot check** |
| **Safety Governance** | Static policy gate + dual approval flag | **Cryptographic dual-analyst token signing** |
| **Execution Status** | `AUTO_RESPONSE = FALSE`, `is_locked = True` | Production authorization workflow |
