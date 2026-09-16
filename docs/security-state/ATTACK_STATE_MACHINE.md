# NivXRay Attack State Machine Specification

> **Document Type:** Attack Lifecycle Specification  
> **Status:** Authoritative  
> **Package:** `backend/security_state/attack_state/`  

---

## 1. 18 Explicit Attack States

NivXRay tracks an explicit, evidence-backed finite state machine:

```
NO_ATTACK_EVIDENCE
       ↓
RECONNAISSANCE
       ↓
INITIAL_ACCESS
       ↓
EXECUTION
       ↓
PERSISTENCE
       ↓
PRIVILEGE_ESCALATION
       ↓
DEFENSE_EVASION
       ↓
CREDENTIAL_ACCESS
       ↓
DISCOVERY
       ↓
LATERAL_MOVEMENT
       ↓
COMMAND_AND_CONTROL
       ↓
COLLECTION
       ↓
EXFILTRATION
       ↓
IMPACT
       ↓
CONTAINED  ──→  ERADICATED  ──→  RECOVERING  ──→  VERIFIED_SAFE
```

---

## 2. Invariants & Transition Rules

1. **Evidence-Gated Advancement**:
   A state transition requires a verified `SecurityStateTransition` with proof. MITRE technique presence serves only as supporting context.
2. **Monotonicity**:
   Forward movement reflects attacker compromise progression. Backward movement occurs **only** when an authorized containment or eradication action is verified by re-observation.
3. **Multi-Host Lateral Movement**:
   `LATERAL_MOVEMENT` requires evidence of compromised capabilities across multiple discrete endpoints.
