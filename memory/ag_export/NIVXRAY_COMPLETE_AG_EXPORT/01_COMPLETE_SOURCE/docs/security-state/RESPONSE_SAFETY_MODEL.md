# NivXRay Response Safety & Verification Model Specification

> **Document Type:** Response Safety & Closed-Loop Verification  
> **Status:** Authoritative  
> **Package:** `backend/security_state/response_safety/`  

---

## 1. Multi-Gate Pre-Execution Safety Policy

No intervention action may execute without passing 4 mandatory gates:

1. **`Tenancy Gate`**: Caller tenant, target asset tenant, and session token must match identically. Cross-tenant execution is impossible.
2. **`Critical Asset Gate`**: Systems designated as Tier-0 (Domain Controllers, core payment gateways, hypervisor management consoles) require explicit dual-analyst human confirmation.
3. **`Confidence Floor`**: Automated containment requires evidence confidence $\ge 0.70$. Lower confidence actions enter `WAITING_APPROVAL`.
4. **`Authorization Scope Gate`**: Caller must hold verified RBAC scopes (e.g. `soc:analyst` or `soc:admin`).

---

## 2. Closed-Loop Environmental Re-Observation

Containment is treated as a hypothesis, not a fact:
```
RESPONSE EXECUTED ──→ RE-OBSERVE TELEMETRY ──→ EVALUATE EVIDENCE ──→ VERIFY CONTAINMENT
```
The Verification Engine checks whether:
- Target process handle died and stayed dead.
- Outbound network sockets on isolated endpoints dropped to 0 (except for the agent control channel).
- Revoked tokens fail subsequent API invocations with HTTP 401.
- Attacker did not pivot to secondary persistence handles.
