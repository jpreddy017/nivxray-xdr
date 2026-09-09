# NivXRay Intervention Model Specification

> **Document Type:** Intervention Optimization Specification  
> **Status:** Authoritative  
> **Package:** `backend/security_state/intervention/`  

---

## 1. Multi-Objective Graph-Cut Optimization

The Intervention Optimizer identifies the minimum disruption action set that cuts the reachability graph between the attacker's foothold and sensitive enterprise assets.

$$
\min_{\mathcal{A} \subseteq \text{Actions}} \left[ \lambda_1 \cdot \text{ResidualRisk}(\mathcal{A}) + \lambda_2 \cdot \text{DisruptionCost}(\mathcal{A}) \right]
$$

Subject to:
- $\text{Reversibility}(\mathcal{A}) \ge \text{ReversibilityThreshold}$
- $\text{EvidencePreservation}(\mathcal{A}) = \text{Verified}$

---

## 2. Planned Action Structure

Every action in the generated `InterventionPlan` includes:
- `step_number`: Execution order.
- `action_id`: Canonical action reference (e.g. `endpoint.isolate`, `identity.revoke_sessions`).
- `target_entity`: Exact entity identifier.
- `rationale`: Verifiable reason anchored in causal state.
- `expected_path_cut`: Graph reachability edge eliminated by this action.
- `is_reversible`: Boolean reversibility status.
