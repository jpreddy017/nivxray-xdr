# NivXRay Deterministic Replay Specification

> **Document Type:** Replay & Determinism Specification  
> **Status:** Authoritative  
> **Standard:** Strict Bit-Identical Replay  

---

## 1. Deterministic Replay Invariants

Given identical:
1. **Input Telemetry & Evidence**: Exact byte streams or canonical evidence records.
2. **Engine Code Version**: Immutable engine version tag (e.g. `SecurityStateEngine v1.0.0`).
3. **Knowledge Base Version**: Rules, thresholds, and capability definitions.
4. **Tenant Configuration**: Tenant scope, authorized admin roles, and custom policies.

The system MUST produce:
- **Byte-identical `state_hash`** for all evaluated entities.
- **Identical `transition_hash`** for every state delta.
- **Identical `CausalGraph` edges**, weights, and mechanisms.
- **Identical `ReachabilityMatrix`** and path evaluations.
- **Identical `InterventionPlan`** action ordering.
- **Identical `LedgerBlock` hashes** in the security state ledger.

---

## 2. Non-Determinism Elimination Measures

To eliminate non-deterministic drift, the implementation enforces:
1. **Content-Addressable IDs**: All IDs (`state-id`, `fact-id`, `der-id`, `edge-id`, `path-id`) are derived from SHA-256 hashes of their seed content, not non-deterministic RNGs (`uuid.uuid4`).
2. **Canonical JSON**: `json.dumps(..., sort_keys=True, ensure_ascii=False, separators=(",", ":"))` standardizes key ordering and whitespace across all platforms and architectures.
3. **Sorted Collection Invariants**: Sets, lists of references, and dictionaries are sorted alphabetically prior to hashing.
4. **Decoupled Wall-Clock Time**: Evaluation timestamps are passed explicitly in execution envelopes rather than reading ambient system time (`datetime.now()`).
