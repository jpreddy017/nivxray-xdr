# NivXRay Security State — Phase 8 Data Flow Specification

> **Document Type:** Data Flow & Schema Specification  
> **Status:** Authoritative  
> **Target Subsystem:** `backend/security_state/`  
> **Target Release:** Phase 8  

---

## 1. Pipeline Overview

The Phase 8 data processing pipeline transforms raw authoritative forensic evidence into staged, simulated intervention options across eight deterministic stages:

```
[Stage 1: Ingestion & Canonicalization]
                   │
                   ▼ (CanonicalEvidence, EntityRef)
[Stage 2: Security State & Active Capability Derivation]
                   │
                   ▼ (SecurityState, StandardCapabilities)
[Stage 3: Authoritative IKG Read-Only Topology Extraction]
                   │
                   ▼ (IKG Nodes & Edges)
[Stage 4: Dynamic Enterprise Reachability Traversal]
                   │
                   ▼ (ReachabilityMatrix, ReachabilityPath, ReachabilityHop)
[Stage 5: Crown-Jewel & Regulatory Scope Valuation Mapping]
                   │
                   ▼ (AssetValuation, ImpactScoreCard)
[Stage 6: Parallel Counterfactual Simulation (Worlds A–E)]
                   │
                   ▼ (WorldProjection, CounterfactualSimulationProvenance)
[Stage 7: Comparative Intervention Matrix & Impact Aggregation]
                   │
                   ▼ (ComparativeInterventionMatrix, InterventionImpactRating)
[Stage 8: Recommended Intervention Staging & Response Safety Gating]
                   │
                   ▼ (InterventionPlan, SafetyGateDecision)
```

---

## 2. Stage-by-Stage Data Specifications

---

### Stage 1: Evidence Ingestion & Entity Canonicalization

#### Responsibility
Ingests normalized events from the Canonical Evidence Model (CEM) and Single Source of Truth (SSOT), canonicalizing enterprise entities into typed `EntityRef` structures.

#### Inputs
- Canonical event streams from telemetry decoders (EDR, Sysmon, Windows Event Log, CloudTrail, Okta).
- Format: JSON dictionary conforming to `CanonicalEvidenceModel`.

#### Data Transformation
1. Parse event metadata (`tenant_id`, `event_id`, `timestamp_utc`, `event_type`).
2. Resolve principal entity identifiers:
   - Host: FQDN, NetBIOS name, or UUID &rarr; `EntityCategory.DEVICE`
   - User: UPN, SAMAccountName, or ObjectGUID &rarr; `EntityCategory.USER`
   - Process: SHA-256 hash, PID, CommandLine &rarr; `EntityCategory.PROCESS`
   - Cloud: IAM ARN, Resource ID &rarr; `EntityCategory.CLOUD_RESOURCE`

#### Output Schema: `EntityRef`
```json
{
  "category": "DEVICE",
  "entity_id": "DESKTOP-E801",
  "tenant_id": "tenant-enterprise-01",
  "display_name": "DESKTOP-E801.corp.internal"
}
```

#### Epistemic Status
- `OBSERVED` (100% grounded in recorded sensor telemetry).

---

### Stage 2: Security State & Active Capability Derivation

#### Responsibility
Maintains current state vectors for enterprise entities and evaluates active attacker capabilities using causal chain analysis.

#### Inputs
- `EntityRef` stream from Stage 1.
- Authoritative SSOT evidence history.
- Domain causal rules (`CausalKnowledgeBase`).

#### Data Transformation
1. Evaluate state properties: `compromise_status`, `privilege_level`, `execution_context`.
2. Evaluate dual-use tools and causal sequences to activate `StandardCapabilities`:
   - E.g., `cmd.exe` spawning `powershell.exe -enc` with RPC calls to DC &rarr; derives `CAP_DCSYNC`.
   - E.g., curl querying `169.254.169.254/latest/meta-data/` &rarr; derives `CAP_CLOUD_METADATA_ACCESS`.
3. Compute SHA-256 fingerprint for entity security state.

#### Output Schema: `SecurityState`
```json
{
  "state_id": "state-desktop-e801-v4",
  "tenant_id": "tenant-enterprise-01",
  "entity_ref": {
    "category": "DEVICE",
    "entity_id": "DESKTOP-E801",
    "tenant_id": "tenant-enterprise-01"
  },
  "epistemic_status": "DERIVED",
  "observed_facts": [
    "Process powershell.exe executed with DCSync RPC arguments",
    "Outbound connection established to 10.0.0.10:445"
  ],
  "derived_facts": [
    "Attacker possesses CAP_DCSYNC capability",
    "Attacker possesses CAP_ADMIN_EXECUTION on DESKTOP-E801"
  ],
  "active_capabilities": [
    "CAP_ADMIN_EXECUTION",
    "CAP_DCSYNC",
    "CAP_LATERAL_MOVEMENT"
  ],
  "state_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

---

### Stage 3: Authoritative IKG Read-Only Topology Extraction

#### Responsibility
Extracts topological relationships connecting the foothold entity to enterprise targets directly from the Authoritative IKG without creating duplicate graph tables.

#### Inputs
- Foothold entity: `DESKTOP-E801`.
- Tenant ID: `tenant-enterprise-01`.

#### Data Transformation
1. Query Authoritative IKG graph storage (read-only SQLite / Graph table):
   ```sql
   SELECT source_id, target_id, relation_type, properties 
   FROM ikg_edges 
   WHERE tenant_id = :tenant_id 
     AND (source_id = :foothold_id OR path_distance <= 3);
   ```
2. Retrieve adjacent nodes: Domain Controllers, Cloud Buckets, File Servers, Backup Repositories.
3. Build in-memory traversal adjacency list.

#### Epistemic Guarantee
- Zero graph mutation: Read-only access guarantees that the Case Attack Story and Authoritative Verdict remain byte-identical.

---

### Stage 4: Dynamic Enterprise Reachability Traversal

#### Responsibility
Traverses the topology graph from compromised footholds, checking protocol, privilege, and capability prerequisites at every hop.

#### Inputs
- Adjacency list from Stage 3.
- Active capabilities from Stage 2 (`active_capabilities_applied`).

#### Traversal Algorithm
1. Initialize Breadth-First Search (BFS) from foothold entities.
2. For each candidate hop $(u \to v)$:
   - Determine `hop_type`: `NETWORK_ROUTE`, `CREDENTIAL_REUSE`, `LOCAL_ADMIN_RIGHT`, `CLOUD_ROLE_ASSUME`.
   - Check `required_capability`: E.g., if target is a Domain Controller requesting Directory Replication RPC, verify that `CAP_DCSYNC` is in `active_capabilities`.
   - Check network protocol: Verify port accessibility (`TCP/445`, `TCP/135`, `TCP/5985`, `HTTPS/443`).
   - Check security controls: If an MFA air-gap or host firewall rule exists, mark `is_blocked_by_control = True` and status = `BLOCKED`.
3. Synthesize full paths into `ReachabilityPath` objects.
4. Calculate aggregate summary counts.

#### Output Schema: `ReachabilityMatrix`
```json
{
  "matrix_id": "reach-DESKTOP-E801-1000",
  "tenant_id": "tenant-enterprise-01",
  "case_id": "case-2026-0904-01",
  "evaluated_at": "2026-09-04T07:14:00Z",
  "foothold_entities": [
    {
      "category": "DEVICE",
      "entity_id": "DESKTOP-E801",
      "tenant_id": "tenant-enterprise-01"
    }
  ],
  "active_capabilities_applied": [
    "CAP_ADMIN_EXECUTION",
    "CAP_DCSYNC"
  ],
  "paths": [
    {
      "path_id": "path-DESKTOP-E801-dc-01.corp.internal",
      "target_entity": {
        "category": "SERVER",
        "entity_id": "dc-01.corp.internal",
        "tenant_id": "tenant-enterprise-01"
      },
      "status": "CURRENTLY_REACHABLE",
      "criticality_tier": "TIER_0",
      "required_prerequisites": ["CAP_DCSYNC", "TCP/135"],
      "hops": [
        {
          "source_entity": { "category": "DEVICE", "entity_id": "DESKTOP-E801", "tenant_id": "tenant-enterprise-01" },
          "target_entity": { "category": "SERVER", "entity_id": "dc-01.corp.internal", "tenant_id": "tenant-enterprise-01" },
          "hop_type": "NETWORK_ROUTE",
          "protocol_port": "TCP/135",
          "required_capability": "CAP_DCSYNC",
          "is_blocked_by_control": false
        }
      ],
      "is_severed": false,
      "exposure_explanation": "Direct DCSync directory replication reachable via RPC 135"
    }
  ],
  "currently_reachable_count": 1,
  "potentially_reachable_count": 2,
  "blocked_count": 1,
  "tier_0_exposed": true,
  "reachable_tier_0_count": 1
}
```

---

### Stage 5: Crown-Jewel & Regulatory Scope Valuation Mapping

#### Responsibility
Enriches reachability paths with sovereign business valuation and compliance data, strictly decoupled from topological distance.

#### Inputs
- `ReachabilityMatrix` from Stage 4.
- `AssetValuationCatalog`.

#### Data Transformation
1. Lookup asset valuation metadata for each path target entity:
   - `tier`: `TIER_0`, `TIER_1`, `TIER_2`, `NORMAL`.
   - `business_criticality_score`: Integer 0 to 100.
   - `sensitivity`: `RESTRICTED`, `CONFIDENTIAL`, `INTERNAL`, `PUBLIC`.
   - `financial_category`: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`.
   - `regulatory_scope`: E.g., `["PCI-DSS", "HIPAA", "SOX", "GDPR"]`.
2. Attach `AssetValuation` to `ReachabilityPath.valuation`.
3. Aggregate unique regulatory frameworks impacted into `regulatory_impact_scope`.

#### Output Schema: `AssetValuation`
```json
{
  "entity_id": "dc-01.corp.internal",
  "tenant_id": "tenant-enterprise-01",
  "tier": "TIER_0",
  "business_criticality_score": 100,
  "sensitivity": "RESTRICTED",
  "financial_category": "CRITICAL",
  "regulatory_scope": ["SOX", "PCI-DSS"],
  "business_function": "Primary Active Directory Domain Controller",
  "valuation_source": "ASSET_INVENTORY"
}
```

---

### Stage 6: Parallel Counterfactual Simulation (Worlds A–E)

#### Responsibility
Simulates candidate containment interventions as parallel state forks branching from the identical observed state, computing P8-13 simulation provenance for every world.

#### Inputs
- `ReachabilityMatrix` (enriched with valuations).
- `SecurityState` of the foothold.
- Candidate interventions:
  - World A: `DO_NOTHING`
  - World B: `HOST_ISOLATION` (isolate `DESKTOP-E801`)
  - World C: `IDENTITY_REVOCATION` (revoke `corporate\\jsmith`)
  - World D: `NETWORK_MICROSEGMENTATION` (block `TCP/445` and `TCP/135` to Tier 0)
  - World E: `COMPOSITE_SURGICAL` (revoke identity + microsegmentation)

#### Simulation Logic
For each world:
1. Apply the intervention action filter against hops in `ReachabilityMatrix`:
   - If `HOST_ISOLATION`: Sever all hops where `source_entity == DESKTOP-E801`.
   - If `IDENTITY_REVOCATION`: Sever hops where `hop_type == CREDENTIAL_REUSE` or `CLOUD_ROLE_ASSUME`.
   - If `NETWORK_MICROSEGMENTATION`: Sever hops where `protocol_port in ['TCP/445', 'TCP/135']` and target is `TIER_0`.
2. Recompute surviving active paths.
3. Calculate:
   - `attack_interruption_pct` $= \frac{\text{severed\_paths}}{\text{total\_active\_paths}} \times 100$
   - `continuation_probability`: Decreases inversely with severed path percentage.
   - `business_disruption_score`: Derived from the operational criticality of severed entities.
   - `residual_attack_paths`: List of target entities that remain reachable.
4. Construct `CounterfactualSimulationProvenance` documenting the 8-step lineage.

#### Output Schema: `WorldProjection`
```json
{
  "world_id": "world-b-isolate-host",
  "description": "Blunt network isolation of DESKTOP-E801",
  "action_applied": "endpoint.isolate",
  "continuation_probability": 0.15,
  "continuation_risk_level": "LOW",
  "continuation_basis": [
    "Host network hops severed: 2/3",
    "Cached cloud tokens or stolen credentials remain usable outside host"
  ],
  "is_statistically_calibrated": false,
  "reachable_assets_count": 1,
  "projected_impact_score": 35,
  "residual_attack_paths": ["arn:aws:s3:::prod-customer-pii"],
  "business_disruption_score": 45,
  "reversibility": "HIGH",
  "evidence_preservation_score": 90,
  "likely_next_transitions": ["Attacker attempts external cloud token use"],
  "epistemic_status": "PROJECTED",
  "attack_interruption_pct": 66.7,
  "tier0_protected_count": 2,
  "tier1_protected_count": 1,
  "simulation_provenance": {
    "observed_inputs": ["ev-proc-spawn-001", "ev-net-connect-002"],
    "current_security_state": "state-desktop-e801-v4",
    "assumptions": ["Host isolation terminates local outbound TCP/IP stack"],
    "intervention": "endpoint.isolate:DESKTOP-E801",
    "simulated_state_transition": "Severed network interface of DESKTOP-E801",
    "projected_reachability_summary": "Severed 2/3 active paths; cloud token persists",
    "projected_security_impact_score": 35,
    "projected_business_impact_score": 45,
    "model_version": "CounterfactualEngine-v1.1.0"
  }
}
```

---

### Stage 7: Comparative Intervention Matrix & Impact Aggregation

#### Responsibility
Aggregates performance metrics across Worlds A through E into a cryptographically hashed Comparative Intervention Matrix.

#### Inputs
- World projections from Stage 6.

#### Data Transformation
1. Build `InterventionImpactRating` records for each world:
   - World A: 0% interruption, 0 disruption, 95 residual risk.
   - World B: 66.7% interruption, 45 disruption, 30 residual risk.
   - World C: 66.7% interruption, 25 disruption, 35 residual risk.
   - World D: 66.7% interruption, 10 disruption, 30 residual risk.
   - World E: 100.0% interruption, 28 disruption, 5 residual risk.
2. Select `recommended_world_id` using Pareto multi-objective scoring (World E).
3. Compute `matrix_hash = sha256_digest(canonical_json(payload))`.

#### Output Schema: `ComparativeInterventionMatrix`
```json
{
  "matrix_id": "matrix-case-2026-0904-01-1000",
  "tenant_id": "tenant-enterprise-01",
  "case_id": "case-2026-0904-01",
  "evaluated_at": "2026-09-04T07:14:05Z",
  "recommended_world_id": "world-e-composite-containment",
  "decision_rationale": "World E achieves 100.0% attack interruption, protects 3 Tier-0 assets with minimal business disruption (28/100).",
  "ratings": [
    {
      "world_id": "world-a-do-nothing",
      "intervention_type": "DO_NOTHING",
      "attack_interruption_pct": 0.0,
      "tier0_protected_count": 0,
      "tier1_protected_count": 0,
      "total_protected_count": 0,
      "business_disruption_score": 0,
      "residual_risk_score": 95,
      "rationale": "Unconstrained baseline: full progression to domain compromise"
    },
    {
      "world_id": "world-e-composite-containment",
      "intervention_type": "COMPOSITE_SURGICAL",
      "attack_interruption_pct": 100.0,
      "tier0_protected_count": 3,
      "tier1_protected_count": 1,
      "total_protected_count": 4,
      "business_disruption_score": 28,
      "residual_risk_score": 5,
      "rationale": "Surgical composite: revokes compromised identity and severs Tier-0 RPC/SMB routes"
    }
  ],
  "matrix_hash": "3f8b91a7e2c5d648109bf43a12e87c5690b21a3487f90e513247c61b9a2345d1"
}
```

---

### Stage 8: Recommended Intervention Staging & Response Safety Gating

#### Responsibility
Translates the recommended world into a concrete, ranked `InterventionPlan` and enforces response safety policy gates.

#### Inputs
- `ComparativeInterventionMatrix` from Stage 7.
- Safety policy rules: tenant scope, critical asset locks, dual approval requirements.

#### Data Transformation
1. Generate ordered response actions:
   - Action 1: `identity.revoke_sessions` for `corporate\\jsmith`.
   - Action 2: `network.block_ports` on firewall: Block TCP 445/135 to `dc-01.corp.internal`.
2. Evaluate Safety Gate:
   - Check tenant boundary: Confirmed matching `tenant_id`.
   - Check critical asset protection: Target involves Tier-0 DC &rarr; set `requires_dual_approval = True`.
   - Check mode: `NIVX_FLAG_SECURITY_STATE == SHADOW` &rarr; set `is_locked = True`, `auto_execute = False`.
3. Stage plan in database for Cockpit UI presentation.

#### Output Schema: `InterventionPlan`
```json
{
  "plan_id": "plan-case-2026-0904-01-1000",
  "tenant_id": "tenant-enterprise-01",
  "case_id": "case-2026-0904-01",
  "recommended_world_id": "world-e-composite-containment",
  "comparative_matrix_id": "matrix-case-2026-0904-01-1000",
  "actions": [
    {
      "action_id": "act-01-revoke-identity",
      "action_type": "identity.revoke_sessions",
      "target_entity": { "category": "USER", "entity_id": "corporate\\jsmith", "tenant_id": "tenant-enterprise-01" },
      "priority": 1,
      "reversibility": "HIGH"
    },
    {
      "action_id": "act-02-block-tier0-rpc",
      "action_type": "network.block_ports",
      "target_entity": { "category": "SERVER", "entity_id": "dc-01.corp.internal", "tenant_id": "tenant-enterprise-01" },
      "parameters": { "ports": ["135", "445"], "protocol": "TCP" },
      "priority": 2,
      "reversibility": "HIGH"
    }
  ],
  "requires_dual_approval": true,
  "is_locked": true,
  "execution_status": "STAGED_FOR_HUMAN_APPROVAL",
  "plan_hash": "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0"
}
```

---

## 3. Cryptographic Invariants & Validation Summary

| Field | Check | Invariant |
| :--- | :--- | :--- |
| `matrix_hash` | SHA-256 Digest | Byte-for-byte identical across repeated replays of identical inputs |
| `epistemic_status` | Enum Assertion | Strictly `PROJECTED` for all simulation outputs; never `OBSERVED` |
| `tenant_id` | Boundary Check | All entities in a plan must match the tenant of the requesting case |
| `is_locked` | Safety Lock | Always `True` in Phase 8 (`AUTO_RESPONSE = FALSE`) |
