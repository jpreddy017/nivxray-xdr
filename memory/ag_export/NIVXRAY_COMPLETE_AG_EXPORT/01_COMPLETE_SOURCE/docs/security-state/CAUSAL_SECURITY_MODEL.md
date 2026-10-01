# NivXRay Causal Security Model Specification

> **Document Type:** Core Causal Reasoning Specification  
> **Status:** Authoritative  
> **Package:** `backend/security_state/causal/`  

---

## 1. Causality vs Correlation Principle

Conventional XDR tools confuse temporal coincidence with causality:
* *Alert A happened at 12:00:01, Alert B happened at 12:00:03 &rarr; XDR draws an arrow.*

NivXRay enforces a strict causal ontology:
- **`TEMPORAL_CORRELATION`**: Events occurred in temporal sequence, but no operating-system or network mechanism proves one induced the other.
- **`STATISTICAL_CORRELATION`**: Events frequently co-occur in historical cases, but causal link is not established in this instance.
- **`SUPPORTED_CAUSALITY`**: Verifiable operating system mechanism links the events with evidence.
- **`STRONG_CAUSAL_EVIDENCE`**: Unambiguous direct link (e.g. kernel syscall `NtCreateUserProcess` where parent PID matches child PPID).
- **`INFERRED_CAUSALITY`**: Highly consistent with known attack sequences where intermediate telemetry is missing.
- **`POSSIBLE_CAUSALITY`**: Plausible hypothesis under active investigation.
- **`CONTRADICTED_CAUSALITY`**: Disproven by conflicting telemetry (e.g. timestamp inversion or PID reuse).

---

## 2. Graph Primitives & Competing Hypotheses

Every edge in the `CausalGraph` stores:
1. `cause_ref`: Pointer to cause event/fact.
2. `effect_ref`: Pointer to effect event/fact.
3. `causal_level`: One of the 7 levels above.
4. `mechanism`: `CausalMechanism` (`mechanism_type`, `description`, `verifiable_kernel_evidence`).
5. `temporal_delta_ms`: Exact delta in milliseconds.
6. `competing_hypotheses`: Competing non-malicious explanations (e.g. routine admin task, OS maintenance) with refutation status.
7. `confidence`: Monotonic confidence factor.

---

## 3. Root Cause Analysis

Roots in the `CausalGraph` represent true initial compromises (e.g., initial macro execution, initial SSH login from untrusted IP) rather than downstream symptom alerts.
