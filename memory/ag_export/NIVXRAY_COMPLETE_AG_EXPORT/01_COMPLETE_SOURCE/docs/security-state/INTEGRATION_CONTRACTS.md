# NivXRay Security State: Integration Contracts & API Surface

> **Document Type:** Phase 0 Integration Contracts  
> **Status:** Authoritative  
> **Prefix:** `/api/v2/security-state/`  
> **Feature Flag:** `NIVX_FLAG_SECURITY_STATE`  

---

## 1. Internal System Integration Points

### 1.1 Canonical SSOT Adapter (`SSOTAdapter`)
- **Source**: `backend/canonical/ssot/` (`AuthoritativeSSOT`, `EvidenceGraph`, `Provenance`)
- **Integration Mode**: `CONSUME` (Read-only)
- **Contract**:
  - The security state engine ingests `AuthoritativeSSOT` instances or `ssot_ref` pointers.
  - Every node generated in the security state graph maintains a back-reference to `upstream_evidence_ids` in the SSOT.
  - No writes are ever made to SSOT authoritative buckets except via the existing authorized sink.

### 1.2 Verdict Engine Adapter (`VerdictAdapter`)
- **Source**: `backend/v2/verdict/` (`canonical.py::score`, `engine.py`)
- **Integration Mode**: `CONSUME` (Read-only)
- **Contract**:
  - Security State consumes `CanonicalVerdict` outputs to inform transition confidence and state classification.
  - The 5-label verdict vocabulary (`Undetermined`, `Informational`, `Runtime Dependent`, `Suspicious`, `Malicious`) is preserved verbatim.
  - Security State never overrides or mutates the Verdict Engine's score.

### 1.3 Response Engine Adapter (`ResponseAdapter`)
- **Source**: `apps/nivxray-xdr-response/` (`POST /api/respond/execute`, `GET /api/respond/executions/{id}`)
- **Integration Mode**: `EXTEND & VERIFY`
- **Contract**:
  - When the Intervention Optimizer generates an approved `InterventionPlan`, actions are dispatched to the response engine's canonical endpoint:
    `POST /api/respond/execute` with `authorization` headers and `action_id`.
  - The Response Safety Engine monitors `GET /api/respond/executions/{id}` until execution reaches `SUCCEEDED`.
  - Once `SUCCEEDED`, the Response Verification Engine initiates the environmental re-observation loop.

### 1.4 Feature Flag Registration
- **Source**: `backend/v2/flags.py`
- **Flag Name**: `SECURITY_STATE`
- **Environment Key**: `NIVX_FLAG_SECURITY_STATE`
- **Values**: `disabled` (default) | `shadow` | `enabled`
- **Contract**:
  - When `disabled`: Routes return 404 or inactive payload; background workers do not start.
  - When `shadow`: Engines run asynchronously in observation mode, recording state computations to shadow logs for validation without affecting primary incident APIs.
  - When `enabled`: Fully active in the investigation pipeline.

---

## 2. Canonical API Endpoints Specification

All endpoints are registered under the FastAPI app with the `/api/v2/security-state` prefix.

### 2.1 Evaluate Security State
- **Route**: `POST /api/v2/security-state/evaluate`
- **Summary**: Ingests evidence and computes current security state for specified entities.
- **Request Body**:
  ```json
  {
    "tenant_id": "tenant-corp-01",
    "case_id": "case-2026-089",
    "entity_refs": [
      { "kind": "DEVICE", "id": "host-finance-04" },
      { "kind": "IDENTITY", "id": "admin.john" }
    ],
    "evidence_bundle_ref": "ssot-uuid-7788"
  }
  ```
- **Response** (200 OK):
  ```json
  {
    "state_id": "state-uuid-101",
    "timestamp": "2026-09-04T01:00:00Z",
    "entities": [
      {
        "entity_ref": { "kind": "DEVICE", "id": "host-finance-04" },
        "classification": "ABUSED_CAPABILITY",
        "epistemic_status": "SUPPORTED",
        "observed_facts": ["powershell.exe spawned whoami.exe", "scheduled task created"],
        "derived_facts": ["persistence established", "privilege elevated"],
        "active_capabilities": ["CAP_REMOTE_EXECUTION", "CAP_PERSISTENCE"],
        "confidence": 92,
        "state_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      }
    ]
  }
  ```

### 2.2 Get Security State by Case
- **Route**: `GET /api/v2/security-state/{case_id}`
- **Summary**: Returns current consolidated security state for a case.

### 2.3 Get State Transitions
- **Route**: `GET /api/v2/security-state/{case_id}/transitions`
- **Summary**: Returns chronological chain of state transitions with causal mechanisms.
- **Response** (200 OK):
  ```json
  {
    "case_id": "case-2026-089",
    "transitions": [
      {
        "transition_id": "tr-001",
        "timestamp": "2026-09-04T00:45:10Z",
        "from_state_hash": "a1b2...",
        "to_state_hash": "c3d4...",
        "triggering_evidence_ids": ["ev-9901"],
        "property_mutated": "privilege_tier",
        "causal_mechanism": "SUPPORTED_CAUSALITY: Token manipulation from elevated process",
        "new_capability_unlocked": "CAP_ACCESS_LSASS",
        "attack_state_transition": "EXECUTION -> PRIVILEGE_ESCALATION"
      }
    ]
  }
  ```

### 2.4 Get Causal Analysis
- **Route**: `GET /api/v2/security-state/{case_id}/causality`
- **Summary**: Returns causal graph differentiating supported causality from temporal correlation.

### 2.5 Get Trusted Capability Abuse
- **Route**: `GET /api/v2/security-state/{case_id}/capabilities`
- **Summary**: Returns evaluation of dual-use capabilities (RMM, admin tools, cloud APIs).

### 2.6 Get Reachability Matrix
- **Route**: `GET /api/v2/security-state/{case_id}/reachability`
- **Summary**: Returns multidimensional reachability graph (currently, potentially, and conditionally reachable assets).

### 2.7 Evaluate Counterfactual Futures
- **Route**: `POST /api/v2/security-state/{case_id}/counterfactual`
- **Summary**: Evaluates "Do Nothing" baseline vs proposed response interventions.
- **Request Body**:
  ```json
  {
    "candidate_actions": [
      { "action_id": "endpoint.isolate", "target": "host-finance-04" },
      { "action_id": "identity.disable_account", "target": "admin.john" }
    ]
  }
  ```
- **Response** (200 OK):
  ```json
  {
    "projections": {
      "world_a_do_nothing": {
        "continuation_probability": 0.88,
        "reachable_assets_count": 14,
        "projected_impact_score": 85,
        "likely_next_steps": ["lateral_movement_to_dc", "credential_dump"]
      },
      "world_b_isolate_host": {
        "continuation_probability": 0.22,
        "reachable_assets_count": 1,
        "residual_attack_paths": ["active_cloud_token_remains_valid"],
        "business_disruption_score": 25,
        "reversibility": "HIGH"
      }
    }
  }
  ```

### 2.8 Plan Optimal Intervention
- **Route**: `POST /api/v2/security-state/{case_id}/interventions/plan`
- **Summary**: Computes minimal effective response plan severing attack graph.

### 2.9 Verify Response Action
- **Route**: `POST /api/v2/security-state/{case_id}/response/verify`
- **Summary**: Re-observes telemetry to verify post-action state and containment efficacy.

### 2.10 Audit Ledger
- **Route**: `GET /api/v2/security-state/{case_id}/ledger`
- **Summary**: Returns cryptographically chained state ledger entries.
