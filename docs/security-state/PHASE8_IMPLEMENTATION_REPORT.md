# NivXRay Security State — Phase 8 Implementation Report
## Dynamic Enterprise Reachability, Crown-Jewel Valuation & Counterfactual Parallel Simulation (Worlds A–E)

**Phase**: Phase 8  
**Subsystem**: NivXRay Security State + Causal Intelligence Core  
**Mode**: `NIVX_FLAG_SECURITY_STATE = SHADOW`  
**Execution Safety**: `AUTO_RESPONSE = FALSE`, `EXECUTE = LOCKED`  
**Graph of Record**: Authoritative Investigation Knowledge Graph (IKG) — Zero Duplication  
**Status**: 🟢 **IMPLEMENTED & VERIFIED**

---

### Executive Overview

Phase 8 directly addresses the single largest blocker to response automation in enterprise SOCs: **blast-radius uncertainty and response paralysis**.

Prior to Phase 8, enterprise defenders faced a binary dilemma:
1. **Take blunt containment actions** (e.g., isolate an entire host), risking catastrophic business service outage, breaking database replication, and generating severe operational downtime.
2. **Do nothing or delay for hours** while manually verifying blast radius, giving attackers unhindered dwell time to traverse subnets, extract NTDS.dit, exfiltrate confidential data, or purge backups.

Phase 8 solves this challenge deterministically by implementing the **Security State Counterfactual Simulation Architecture**:
```text
Evidence (OBSERVED)
   ↓
Security State (DERIVED)
   ↓
Attacker Capabilities (EVALUATED)
   ↓
Authoritative IKG Graph (QUERIED — Read-Only)
   ↓
Dynamic Enterprise Reachability (CAPABILITY-CONDITIONED)
   ↓
Crown-Jewel Valuation (TIER 0 / 1 / 2 & REGULATORY SCOPE)
   ↓
Parallel Counterfactual Projections (WORLDS A–E — PROJECTED)
   ├── World A: Do Nothing (Unconstrained Progression Baseline)
   ├── World B: Full Host Isolation (Blunt Network Containment)
   ├── World C: Surgical Identity Action (Kerberos/OAuth Session Revocation)
   ├── World D: Targeted Network Microsegmentation (Port/Route SMB-RPC Sever)
   └── World E: Composite Surgical Containment (Pareto-Optimal Graph Cut)
   ↓
Comparative Intervention Matrix (MATHEMATICALLY DERIVED RATINGS)
   ↓
Minimal Effective Intervention Plan (RECOMMENDED & STAGED)
   ↓
Response Safety Gate (BOUNDARY & PRIVILEGE ENFORCEMENT)
   ↓
Human Approval (COCKPIT PRESENTATION)
   ↓
[EXECUTE = LOCKED in Shadow Mode]
```

---

### 1. The 13 Acceptance Gates Delivered

| Gate | Name | Architectural Delivery |
| :--- | :--- | :--- |
| **P8-01** | **Reachability Correctness** | Calculates multi-hop reachable paths across authoritative IKG nodes (`device`, `server`, `cloud_resource`, `backup_system`, `data_store`) from compromised footholds without graph duplication. |
| **P8-02** | **Capability-Aware Reachability** | Different attacker capabilities produce mathematically distinct reachable sets (`CAP_NTDS_EXTRACTION` unlocks Tier-0 DC directory replication; `CAP_CLOUD_METADATA_ACCESS` unlocks Cloud Vaults; `CAP_MULTI_HOST_TRAVERSAL` unlocks adjacent endpoints). |
| **P8-03** | **Crown-Jewel Valuation Decoupling** | Explicitly decouples business criticality (`TIER_0`, `TIER_1`, `TIER_2`, `NORMAL`), data sensitivity (`RESTRICTED`), financial impact (`CRITICAL`), and regulatory scopes (`PCI-DSS`, `HIPAA`, `SOX`) from network distance and technical reachability. |
| **P8-04** | **Counterfactual Isolation (World B)** | Models blunt host isolation: severs all network hops originating/terminating at foothold, slashes continuation probability, quantifies high business disruption (45/100), and records surviving credentials as residual risk. |
| **P8-05** | **Identity Intervention (World C)** | Models surgical identity revocation: invalidates Kerberos TGTs, OAuth refresh tokens, and password handles; severs credential-reuse hops with lower disruption (25/100); notes on-host persistence survives. |
| **P8-06** | **Network Intervention (World D)** | Models targeted microsegmentation: blocks SMB 445 / RPC 135 to Tier-0 DC and Backup storage while keeping workstation online; achieves minimal business disruption (10/100) with Tier-0 protection. |
| **P8-07** | **Do-Nothing Projection (World A)** | Projects baseline unconstrained attack trajectory: continuation probability $\ge 0.90$, projected impact $\ge 85$, zero business disruption, projecting escalation to ransomware staging. |
| **P8-08** | **Comparative Intervention Matrix** | Deterministic matrix evaluating Worlds A through E across Attack Interruption %, Assets Protected, Business Disruption Score, and Residual Risk Score. Derived mathematically from model inputs. |
| **P8-09** | **Deterministic Replay** | Replay of identical evidence + graph + model versions produces bit-for-bit identical hashes across `matrix_hash`, `analysis_hash`, `card_hash`, and `plan_hash`. |
| **P8-10** | **Provenance & Epistemic Separation** | Strict epistemic boundary: all simulated worlds and counterfactual futures carry `epistemic_status = EpistemicStatus.PROJECTED`. Asserts `PROJECTED != OBSERVED`. |
| **P8-11** | **Authoritative Pipeline Invariance** | Authoritative Case Verdict, Attack Story, and IKG are 100% read-only and invariant. Zero duplicate graph tables. |
| **P8-12** | **Response Execution Safety Lock** | Response actions remain strictly simulated and ranked for human decision; `AUTO_RESPONSE = FALSE`, `is_locked = True`, `EXECUTE = LOCKED`. |
| **P8-13** | **Counterfactual Integrity** | Full lineage traceability across every simulated world: `OBSERVED INPUTS -> CURRENT SECURITY STATE -> ASSUMPTIONS -> INTERVENTION -> SIMULATED TRANSITION -> PROJECTED REACHABILITY -> PROJECTED IMPACT`. |

---

### 2. Core Engines & Architectural Changes

#### 2.1 Contracts (`contracts.py`)
- Added `AssetCriticalityTier` (`TIER_0`, `TIER_1`, `TIER_2`, `NORMAL`, `UNCLASSIFIED`).
- Added `DataSensitivityTier` (`RESTRICTED`, `CONFIDENTIAL`, `INTERNAL`, `PUBLIC`).
- Added `FinancialImpactCategory` (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
- Added `InterventionType` (`DO_NOTHING`, `HOST_ISOLATION`, `IDENTITY_REVOCATION`, `NETWORK_MICROSEGMENTATION`, `COMPOSITE_SURGICAL`).
- Added `AssetValuation` dataclass with business criticality score (0–100) and regulatory scope list (`PCI-DSS`, `HIPAA`, `SOX`, `GDPR`).
- Added `CounterfactualSimulationProvenance` for P8-13 lineage validation.
- Added `InterventionImpactRating` and `ComparativeInterventionMatrix` dataclasses with SHA-256 fingerprinting.

#### 2.2 Enterprise Reachability Engine (`reachability/engine.py` — v1.1.0)
- Upgraded `ReachabilityHop` with `required_capability`, `required_privilege`, `protocol_port`, `is_cut_by_intervention`, and `intervention_id`.
- Upgraded `ReachabilityPath` with `valuation`, `is_severed`, `severed_by_action`, and `exposure_explanation`.
- Implemented capability discrimination:
  - `CAP_NTDS_EXTRACTION` / `CAP_DCSYNC`: unlocks Active Directory directory replication (`DIRECTORY_REPLICATION_RPC`).
  - `CAP_CLOUD_METADATA_ACCESS` / `CAP_CLOUD_TOKEN_THEFT`: unlocks Cloud S3 vault via IMDS token scraping (`IMDS_ROLE_SESSION`).
  - `CAP_MULTI_HOST_TRAVERSAL`: unlocks lateral traversal to adjacent workstations via WMI/SMB.
  - `CAP_SHADOW_COPY_DELETION` / `CAP_BACKUP_TAMPERING`: unlocks Veeam immutable backup repository.
- Made `path_id` and `matrix_id` fully deterministic based on entity identities, tenant, case, and timestamp.

#### 2.3 Counterfactual Engine (`counterfactual/engine.py` — v1.1.0)
- Implemented parallel worlds:
  - **World A (`world-a-do-nothing`)**: Baseline unhindered trajectory.
  - **World B (`world-b-isolate-host`)**: Network containment of host.
  - **World C (`world-c-revoke-identity`)**: Surgical credential invalidation.
  - **World D (`world-d-targeted-microsegmentation`)**: Targeted port blocks to Tier-0 assets.
  - **World E (`world-e-composite-containment`)**: Composite optimal graph-cut.
- Embedded `CounterfactualSimulationProvenance` into every world for P8-13 integrity.
- Built `ComparativeInterventionMatrix` deterministically scoring attack interruption %, assets protected, business disruption, and residual risk.

#### 2.4 Impact Engine (`impact/engine.py` — v1.1.0)
- Integrated `AssetValuation` and aggregated regulatory scope (`regulatory_impact_scope`) across reachable paths.
- Preserved complete decoupling from Verdict confidence.

#### 2.5 Intervention Optimizer (`intervention/optimizer.py` — v1.1.0)
- Populates `recommended_world_id` and `comparative_matrix_id` onto `InterventionPlan`.
- Maintains response safety locks (`requires_dual_approval` for Tier-0 assets).

---

### 3. Epistemic & Provenance Discipline

Phase 8 adheres strictly to the 10-term NivXRay epistemic vocabulary:
- **OBSERVED**: Telemetry sensor events, process execution records, authentic network frames.
- **SUPPORTED**: Corroborated causal mechanisms.
- **DERIVED**: Deterministically inferred states and active capabilities.
- **PROJECTED**: All counterfactual world outcomes, attack trajectories, and reachability simulations.
- **ASSUMED**: Explicit operational priors recorded in provenance (e.g. *"Kerberos ticket cache lifetime is 10 hours"*).

**Strict Invariant Enforced**: `PROJECTED != OBSERVED`. No simulated prediction or counterfactual world outcome can ever be classified as `OBSERVED`.
