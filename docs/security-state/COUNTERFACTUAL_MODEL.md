# NivXRay Counterfactual Security Model Specification

> **Document Type:** Counterfactual Reasoning Specification  
> **Status:** Authoritative  
> **Package:** `backend/security_state/counterfactual/`  

---

## 1. Parallel World Projection

Given an active security state, the Counterfactual Engine evaluates multiple alternate timelines:

```
                  ┌──────────────────────────────────────────────┐
                  │              Current State                   │
                  └──────────────────────┬───────────────────────┘
                                         │
                 ┌───────────────────────┼───────────────────────┐
                 ▼                       ▼                       ▼
      ┌─────────────────────┐ ┌─────────────────────┐ ┌─────────────────────┐
      │  World A:           │ │  World B:           │ │  World C:           │
      │  DO NOTHING         │ │  ISOLATE ENDPOINT   │ │  REVOKE SESSIONS    │
      ├─────────────────────┤ ├─────────────────────┤ ├─────────────────────┤
      │ • Continuation: 95% │ │ • Continuation: 15% │ │ • Continuation: 30% │
      │ • Blast Radius: 15  │ │ • Blast Radius: 1   │ │ • Blast Radius: 4   │
      │ • Disruption: 0     │ │ • Disruption: 20    │ │ • Disruption: 35    │
      │ • Reversible: NO    │ │ • Reversible: YES   │ │ • Reversible: YES   │
      └─────────────────────┘ └─────────────────────┘ └─────────────────────┘
```

---

## 2. Decision Metrics

For each candidate world, the engine computes:
- **`continuation_probability`**: Likelihood the attacker achieves their objective under this intervention.
- **`residual_attack_paths`**: What avenues remain open if this specific action is taken.
- **`business_disruption_score`**: Estimated productivity impact on legitimate users.
- **`evidence_preservation_score`**: Whether volatile RAM/disk evidence is preserved for forensics.
- **`reversibility`**: Speed and ease of undoing the response action if benign intent is determined.
