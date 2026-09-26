# NivXRay Security State — Phase 8 Architecture Decision Records (ADRs)

> **Document Type:** Architecture Decision Records (ADRs)  
> **Status:** Authoritative  
> **Subsystem:** `backend/security_state/`  
> **Phase:** Phase 8 (Dynamic Enterprise Reachability, Crown-Jewel Valuation & Counterfactual Worlds A–E)  

---

## Index of Architectural Decisions

- [ADR-P8-001: Single Graph of Record — Authoritative IKG Direct Reuse](#adr-p8-001-single-graph-of-record--authoritative-ikg-direct-reuse)
- [ADR-P8-002: Decoupling Asset Valuation and Regulatory Scopes from Technical Reachability](#adr-p8-002-decoupling-asset-valuation-and-regulatory-scopes-from-technical-reachability)
- [ADR-P8-003: Epistemic Boundary Invariance — Absolute Separation of PROJECTED vs OBSERVED](#adr-p8-003-epistemic-boundary-invariance--absolute-separation-of-projected-vs-observed)
- [ADR-P8-004: Parallel Counterfactual Worlds as Immutable State Forks](#adr-p8-004-parallel-counterfactual-worlds-as-immutable-state-forks)
- [ADR-P8-005: Deterministic Derived Scoring vs Opaque Machine Learning Estimators](#adr-p8-005-deterministic-derived-scoring-vs-opaque-machine-learning-estimators)
- [ADR-P8-006: Hard-Locked Autonomous Response Execution in Shadow Mode](#adr-p8-006-hard-locked-autonomous-response-execution-in-shadow-mode)
- [ADR-P8-007: P8-13 Counterfactual Integrity Lineage Tracking](#adr-p8-007-p8-13-counterfactual-integrity-lineage-tracking)
- [ADR-P8-008: Deterministic Identifiers & Canonical JSON Fingerprinting](#adr-p8-008-deterministic-identifiers--canonical-json-fingerprinting)
- [ADR-P8-009: Pareto Multi-Objective Optimization for World E Recommendation](#adr-p8-009-pareto-multi-objective-optimization-for-world-e-recommendation)
- [ADR-P8-010: Prohibition of Uncalibrated Probabilities & Speculative Dollar Losses](#adr-p8-010-prohibition-of-uncalibrated-probabilities--speculative-dollar-losses)

---

### ADR-P8-001: Single Graph of Record — Authoritative IKG Direct Reuse

#### Status
**Accepted & Authoritative**

#### Context
Enterprise XDR platforms frequently suffer from "graph fragmentation," where the incident investigation system maintains one graph, the attack path analysis module builds a second graph, and the asset inventory maintains a third. This leads to conflicting graph state, synchronization latency, excessive memory utilization, and irreconcilable discrepancies between what the analyst sees in the investigation graph and what the reachability engine projects.

#### Decision
NivXRay XDR shall have **exactly one Graph of Record**: the Authoritative Investigation Knowledge Graph (IKG).
- The `EnterpriseReachabilityEngine` directly queries the existing IKG nodes (`device`, `server`, `account`, `cloud_resource`, `backup_system`, `data_store`) and edges (`NETWORK_ADJACENT`, `ADMINISTERS`, `AUTHENTICATED_TO`, `CAN_REPLICATE`).
- Phase 8 strictly prohibits creating a second graph database, duplicate SQLite/PostgreSQL graph tables, or shadow graph models.
- All graph queries performed by Phase 8 are **read-only** and ephemeral.

#### Consequences
- **Positive**: Guarantees zero graph drift between the Case Attack Story and Reachability paths. Eliminates memory overhead of maintaining duplicate enterprise topologies.
- **Positive**: Authoritative IKG remains 100% invariant and protected from mutation.
- **Negative**: The reachability engine must adapt its traversal algorithms to the existing schema of the authoritative IKG rather than defining a custom, specialized graph schema.

---

### ADR-P8-002: Decoupling Asset Valuation and Regulatory Scopes from Technical Reachability

#### Status
**Accepted & Authoritative**

#### Context
In legacy vulnerability and exposure management systems, asset criticality is often conflated with network distance or exploitability. For example, if an offline immutable backup repository or air-gapped domain controller is not directly reachable over TCP/IP, the system scores its risk as zero or negligible. When an attacker then breaches a jump host or exploits an MFA bypass, defenders are caught unprepared because the asset's true value was never modeled.

#### Decision
We explicitly decouple **Business & Regulatory Valuation** from **Technical Reachability**:
1. `AssetValuation` is modeled as an independent business and compliance entity containing:
   - `AssetCriticalityTier`: `TIER_0` (Identity Roots, PKI, Backup, KeyVault), `TIER_1` (Core DB/ERP), `TIER_2` (Workstations), `NORMAL`.
   - `DataSensitivityTier`: `RESTRICTED`, `CONFIDENTIAL`, `INTERNAL`, `PUBLIC`.
   - `FinancialImpactCategory`: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`.
   - `regulatory_scope`: `PCI-DSS`, `HIPAA`, `SOX`, `GDPR`.
2. An asset retains its sovereign valuation regardless of whether its technical reachability status is `CURRENTLY_REACHABLE`, `CONDITIONALLY_REACHABLE`, `POTENTIALLY_REACHABLE`, or `BLOCKED`.
3. The `ImpactEngine` calculates exposure as the intersection of technical reachability and asset valuation, ensuring that an unreachable Tier-0 asset remains identified as a high-stakes crown jewel.

#### Consequences
- **Positive**: Prevents false complacency. Security analysts immediately recognize that high-value crown jewels are targeted even if network firewalls are currently holding.
- **Positive**: Enables compliance-aware blast-radius calculations (e.g. counting how many PCI-DSS or HIPAA systems are exposed).
- **Negative**: Requires maintaining an asset valuation catalog alongside the topological graph.

---

### ADR-P8-003: Epistemic Boundary Invariance — Absolute Separation of PROJECTED vs OBSERVED

#### Status
**Accepted & Authoritative**

#### Context
A severe risk in predictive cybersecurity systems is "epistemic contamination," where simulated futures or probabilistic guesses are presented to human analysts in a manner that blurs them with ground-truth forensic evidence. This leads to analyst confusion, flawed incident reporting, and compromised audit trails.

#### Decision
All Phase 8 data models and interfaces enforce the **10-term NivXRay Epistemic Vocabulary**:
`OBSERVED`, `SUPPORTED`, `DERIVED`, `LIKELY`, `POSSIBLE`, `PROJECTED`, `ASSUMED`, `UNSUPPORTED`, `CONTRADICTED`, `DISPROVEN`.

- Telemetry ingested from sensors is strictly `OBSERVED`.
- Causal mechanisms corroborated by evidence are `SUPPORTED`.
- Active attacker capabilities and deterministic states are `DERIVED`.
- **ALL Counterfactual World outcomes, reachable paths, and future impact scores are strictly `PROJECTED`.**
- Unproven operational priors (e.g., ticket lifetimes) are strictly `ASSUMED`.
- Contract assertions explicitly enforce `epistemic_status != EpistemicStatus.OBSERVED` for any simulation output.

#### Consequences
- **Positive**: Completely eliminates the risk of an analyst or auditor mistaking a simulated containment outcome for a real-world event.
- **Positive**: Preserves forensic integrity for legal and regulatory compliance.
- **Negative**: Requires explicit tagging and validation across all dataclasses and serialization layers.

---

### ADR-P8-004: Parallel Counterfactual Worlds as Immutable State Forks

#### Status
**Accepted & Authoritative**

#### Context
Defenders evaluating containment options often want to ask: *"What happens if we isolate the host versus revoking the user's credentials versus blocking specific ports?"* If these scenarios are computed as sequential mutations of the live state, state pollution and order-of-operation dependencies occur.

#### Decision
Counterfactual simulations are modeled as **pure, immutable parallel state forks** branching simultaneously from the same observed security state:
- **World A (`world-a-do-nothing`)**: Unconstrained baseline progression with zero interventions.
- **World B (`world-b-isolate-host`)**: Network containment of the foothold host.
- **World C (`world-c-revoke-identity`)**: Surgical credential/session invalidation for the compromised identity.
- **World D (`world-d-targeted-microsegmentation`)**: Targeted port/route blocks (e.g., blocking SMB 445 / RPC 135 to Tier-0).
- **World E (`world-e-composite-containment`)**: Combined surgical intervention achieving optimal graph severance.

Each world is projected independently without mutating the observed state or any other world.

#### Consequences
- **Positive**: Parallel projection is pure, stateless, and safe for concurrent multi-threaded computation.
- **Positive**: Guarantees fair, side-by-side comparison across identical initial conditions.
- **Negative**: Multiple world projections increase transient computational cycles during evaluation.

---

### ADR-P8-005: Deterministic Derived Scoring vs Opaque Machine Learning Estimators

#### Status
**Accepted & Authoritative**

#### Context
Many commercial systems use black-box Machine Learning (ML) models to generate response scores. This results in non-reproducible outputs, unexplained recommendation logic ("the AI scored it 82"), and model drift over time.

#### Decision
Phase 8 strictly requires all comparative metrics to be **mathematically derived from concrete model inputs**:
- **Attack Interruption %**: $\frac{\text{Count of Severed Active Paths}}{\text{Total Count of Active Paths}} \times 100$.
- **Business Disruption Score**: Sum of entity disruption weights for affected assets (e.g., Tier-0 DC = 40, Tier-1 DB = 25, Workstation = 10), capped at 100.
- **Residual Risk Score**: Computed based on surviving reachable Tier-0/1 assets and unsevered attacker capabilities.
- Every score must expose its exact mathematical rationale and constituent entity IDs.

#### Consequences
- **Positive**: Full auditability and explainability. A security engineer can inspect exactly why World E was recommended over World B.
- **Positive**: 100% deterministic replayability across independent test runs.
- **Negative**: Requires deliberate, transparent heuristics rather than delegating complexity to black-box ML models.

---

### ADR-P8-006: Hard-Locked Autonomous Response Execution in Shadow Mode

#### Status
**Accepted & Authoritative**

#### Context
Premature automation of response actions in an enterprise environment can lead to widespread business outages (e.g., isolating an Active Directory domain controller or core database cluster).

#### Decision
In Phase 8:
- The system operates strictly under `NIVX_FLAG_SECURITY_STATE = SHADOW`.
- Automated response execution is **HARD-LOCKED**: `AUTO_RESPONSE = FALSE`, `is_locked = True`, `EXECUTE = LOCKED`.
- The `InterventionOptimizer` and `ResponseSafetyGate` compute, rank, and stage recommendations for human presentation in the Cockpit UI, but cannot transmit execution commands to live EDR, network controllers, or identity providers.

#### Consequences
- **Positive**: Zero risk of unintended operational disruption or accidental containment during technology laboratory development and staging.
- **Positive**: Adheres to strict safety boundaries requested by enterprise customers.
- **Negative**: Closed-loop post-action verification cannot execute against live production systems in Phase 8 (deferred to Phase 9).

---

### ADR-P8-007: P8-13 Counterfactual Integrity Lineage Tracking

#### Status
**Accepted & Authoritative**

#### Context
To satisfy the P8-13 acceptance gate, simulated outcomes must demonstrate full traceability from concrete evidence to projected impact.

#### Decision
Every `WorldProjection` must embed a `CounterfactualSimulationProvenance` record capturing the 8-step causal lineage:
1. `observed_inputs`: List of canonical evidence IDs backing the current state.
2. `current_security_state`: Identifier and state hash of the originating entity state.
3. `assumptions`: Explicit list of simulation priors (e.g. Kerberos ticket lifetime).
4. `intervention`: Identifier and type of simulated intervention.
5. `simulated_state_transition`: Description of graph edges severed by the action.
6. `projected_reachability_summary`: Summary of severed vs surviving paths.
7. `projected_security_impact_score`: Projected security risk score [0–100].
8. `projected_business_impact_score`: Projected operational disruption score [0–100].

#### Consequences
- **Positive**: Provides end-to-end explainability for every simulation.
- **Positive**: Ensures full compliance with P8-13 acceptance criteria.
- **Negative**: Marginal increase in serialized payload size.

---

### ADR-P8-008: Deterministic Identifiers & Canonical JSON Fingerprinting

#### Status
**Accepted & Authoritative**

#### Context
Initial prototypes used random UUIDs (`uuid.uuid4().hex`) for reachability paths and comparative matrices, which caused replay verification tests to fail because identical evidence produced different hashes across executions.

#### Decision
All Phase 8 entities generate deterministic identifiers and cryptographic digests:
- `path_id`: Derived from foothold and target entity IDs: `path-{foothold.entity_id}-{target.entity_id}`.
- `matrix_id`: Derived from case ID and sorted entity IDs.
- `matrix_hash` / `analysis_hash`: Computed using `sha256_digest(canonical_json(payload))`, where `canonical_json` enforces alphabetical key sorting and deterministic float rounding.

#### Consequences
- **Positive**: 100% bit-for-bit replay equivalence. Identical inputs produce identical SHA-256 hashes every time.
- **Positive**: Eliminates test flakiness and supports cryptographic ledger validation.
- **Negative**: Identifiers must be carefully formatted to prevent collision across different cases or tenants.

---

### ADR-P8-009: Pareto Multi-Objective Optimization for World E Recommendation

#### Status
**Accepted & Authoritative**

#### Context
Single-metric optimization (e.g. maximizing attack interruption alone) invariably recommends blunt host isolation (World B), ignoring business disruption. Conversely, minimizing business disruption alone recommends doing nothing (World A), allowing the attacker to succeed.

#### Decision
The `InterventionOptimizer` applies a **Pareto Multi-Objective Optimization** algorithm:
$$\text{Objective} = \max \left( w_1 \cdot \text{InterruptionPct} + w_2 \cdot \text{ProtectedTier0} - w_3 \cdot \text{DisruptionScore} - w_4 \cdot \text{ResidualRisk} \right)$$
Subject to:
1. $\text{CriticalServiceDisruption} \le 50$.
2. $\text{Tier0Protection} = \text{MANDATORY}$ if Tier-0 assets are reachable in World A.
3. $\text{Reversibility} \ge \text{MEDIUM}$.

World E (`world-e-composite-containment`) combines surgical identity revocation with targeted microsegmentation to achieve the Pareto-optimal frontier: 100% Tier-0 protection with low disruption (28/100).

#### Consequences
- **Positive**: Recommends balanced, surgical interventions that protect both security and business continuity.
- **Positive**: Mathematically defensible recommendations presented to SOC analysts.
- **Negative**: Weights ($w_1, w_2, w_3, w_4$) must be calibrated and documented transparently.

---

### ADR-P8-010: Prohibition of Uncalibrated Probabilities & Speculative Dollar Losses

#### Status
**Accepted & Authoritative**

#### Context
Predictive security platforms frequently present uncalibrated mathematical parameters as "real-world probabilities" (e.g., claiming a 95% chance of an attack succeeding) or fabricate speculative financial losses (e.g., claiming an incident will cost $3.7M). Both practices create grave legal, audit, and operational liabilities:
1. Conflating a deterministic simulation parameter with an empirical statistical probability deceives analysts and forensic auditors.
2. Fabricating arbitrary dollar losses damages defender credibility with executive leadership and board committees.

#### Decision
1. **Continuation Probability Calibration Rule**:
   - All simulation probability scores (e.g. `0.95` for World A, `0.03` for World E) are strictly classified as **MODELLED SCENARIO PARAMETERS**, not empirical Bayesian probabilities.
   - Every `WorldProjection` carries an explicit boolean invariant: `is_statistically_calibrated = False`.
   - Analysts are presented with **Qualitative Continuation Risk Levels** (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `MINIMAL`) grounded in observable basis vectors: surviving paths, active capabilities, unrevoked credentials, and reachable Tier-0 assets.
2. **Business Impact & Financial Loss Rule**:
   - The engine **NEVER invents speculative dollar losses**.
   - Business and financial impact must be derived exclusively from **customer-configured metadata**: Asset Criticality Tier (`TIER_0` to `NORMAL`), Data Sensitivity (`RESTRICTED` to `PUBLIC`), Financial Impact Category (`CRITICAL` to `LOW`), Revenue Classification, RTO/RPO, and Regulatory Scope (`PCI-DSS`, `HIPAA`, `SOX`, `GDPR`).
   - All financial impact evaluations are output as defensible qualitative classifications with traceable metadata provenance.

#### Consequences
- **Positive**: Complete forensic credibility. Defensible in audits, legal proceedings, and regulatory reviews.
- **Positive**: Grounded strictly in verifiable customer configuration and observable evidence.
- **Negative**: Requires customer onboarding of asset classification catalogs for enriched business scoring.

