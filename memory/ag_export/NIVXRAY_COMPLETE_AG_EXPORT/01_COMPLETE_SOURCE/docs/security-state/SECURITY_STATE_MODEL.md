# NivXRay Security State Model Specification

> **Document Type:** Core Model Specification  
> **Status:** Authoritative  
> **Package:** `backend/security_state/model/`  

---

## 1. Overview & Conceptual Model

The Security State Model represents the ground-truth operational security status of enterprise entities. It rejects simplistic risk numbers in favor of explicit epistemic assertions and observed/derived facts linked to canonical evidence.

```
┌────────────────────────────────────────────────────────────┐
│                       SecurityState                        │
├────────────────────────────────────────────────────────────┤
│ • state_id: str (deterministic sha256 identifier)         │
│ • tenant_id: str (strict tenant boundary)                  │
│ • entity_ref: EntityRef (category + entity_id)             │
│ • timestamp: RFC3339                                       │
│ • epistemic_status: EpistemicStatus                        │
│ • classification: CapabilityStatus                         │
│ • previous_state_hash: Optional[sha256]                    │
│ • evidence_refs: list[str]                                 │
│ • observed_facts: list[ObservedFact]                       │
│ • derived_facts: list[DerivedFact]                         │
│ • active_capabilities: list[str]                           │
│ • assumptions: list[str]                                   │
│ • contradictions: list[str]                                │
│ • missing_evidence: list[str]                              │
│ • provenance: ProvenanceEnvelope                           │
│ • state_hash: sha256 (canonical JSON digest)               │
└────────────────────────────────────────────────────────────┘
```

---

## 2. Epistemic Status Primitives

Confidence is never collapsed into an opaque float. The model requires one of eight explicit epistemic classifications:

1. **`OBSERVED`**: Directly recorded by a verified sensor or telemetry log.
2. **`SUPPORTED`**: Formally corroborated by multiple independent evidence items.
3. **`DERIVED`**: Deterministically deduced via verified causal or logical inference rules.
4. **`LIKELY`**: High Bayesian probability with strong supporting behavioral context.
5. **`POSSIBLE`**: Plausible hypothesis under active investigation.
6. **`UNSUPPORTED`**: Claim stated without sufficient backing evidence.
7. **`CONTRADICTED`**: Telemetry from another verified sensor conflicts with this claim.
8. **`DISPROVEN`**: Chronologically or mathematically impossible.

---

## 3. The 20 Modeled Enterprise Entity Categories

1. `USER`
2. `IDENTITY`
3. `DEVICE`
4. `PROCESS`
5. `FILE`
6. `SERVICE`
7. `NETWORK_CONNECTION`
8. `ACCOUNT`
9. `CREDENTIAL`
10. `CLOUD_RESOURCE`
11. `SAAS_RESOURCE`
12. `APPLICATION`
13. `WORKLOAD`
14. `SERVER`
15. `ENDPOINT`
16. `SECURITY_CONTROL`
17. `DATA_STORE`
18. `BACKUP_SYSTEM`
19. `VIRTUALIZATION_HOST`
20. `TRUST_RELATIONSHIP`

---

## 4. Hash Determinism & Chaining

The `state_hash` is calculated via:
```python
state_hash = sha256(canonical_json({
    "state_id": self.state_id,
    "tenant_id": self.tenant_id,
    "entity_ref": self.entity_ref.to_dict(),
    "timestamp": self.timestamp,
    "epistemic_status": self.epistemic_status.value,
    "classification": self.classification.value,
    "previous_state_hash": self.previous_state_hash,
    "evidence_refs": sorted(self.evidence_refs),
    "observed_facts": [f.to_dict() for f in self.observed_facts],
    "derived_facts": [f.to_dict() for f in self.derived_facts],
    "active_capabilities": sorted(self.active_capabilities),
    "assumptions": sorted(self.assumptions),
    "contradictions": sorted(self.contradictions),
    "missing_evidence": sorted(self.missing_evidence),
    "provenance": self.provenance.to_dict(),
}))
```
Chaining: Each subsequent state transition sets `previous_state_hash = state_before.state_hash`, ensuring an unbroken, tamper-evident cryptographic chain.
